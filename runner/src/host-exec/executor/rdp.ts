/**
 * RDP transport implementations: rdpValidate, rdpShadowPrep (v0.19.0 refactor — extracted from executor.ts).
 */
import { HOST_EXEC_TIMEOUT_MS, type HostCredentials, capOutput, checkDestructive, collectSecrets, redactSecrets, resolveWinrmCredentials, validateHostTarget } from "../common.js";
import { RDP_SHADOW_PREP_PS, buildShadowHandoff, rdpValidateCredentials } from "../rdp.js";
import { ExecutorCore } from "./core.js";
import { type HostExecResult } from "./types.js";

export async function rdpValidateImpl(core: ExecutorCore, args: {
  host: string;
  port?: number;
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  // No shell command runs here, but the credential-bearing flow still goes
  // through kill-switch + scope + credential resolution, fail closed.
  if (core.killSwitch.aborted) {
    return core.refusedResult("winrm", args.host, "kill switch active — coordinator aborted; no new host executions");
  }
  const v = validateHostTarget(args.host, args.scopeHosts);
  if (!v.ok) return core.refusedResult("winrm", args.host, v.reason);
  let creds: HostCredentials;
  let secrets: string[];
  try {
    creds = resolveWinrmCredentials(core.deps.env);
    secrets = collectSecrets(creds);
  } catch (err) {
    return core.refusedResult("winrm", args.host, (err as Error).message);
  }
  const t = core.deps.rdp();
  try {
    const r = await core.bounded(
      rdpValidateCredentials(t, {
        host: args.host,
        port: args.port,
        creds,
        timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
        signal: args.signal,
      }),
      (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 5_000,
      "rdp_auth",
      t,
    );
    const verdict =
      r.credentialValid === true ? "CREDENTIAL VALID" : r.credentialValid === false ? "credential NOT valid" : "no verdict";
    return {
      ok: r.credentialValid === true,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(
        `rdp NLA validation ${args.host}: reachable=${r.reachable} nla=${r.nlaRequired} ${verdict} (${r.selectedProtocol ?? "no protocol"})`,
        secrets,
      ),
      output: redactSecrets(capOutput(r.note), secrets),
      ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(`rdp NLA validation ${args.host} failed: ${(err as Error).message}`, secrets),
      output: "",
      ms: Date.now() - started,
    };
  } finally {
    await t.close().catch(() => undefined);
  }
}

/**
 * RDP shadow preparation (battery WS-065) — HUMAN-GATED. Runs the
 * read-only session/policy enumeration over WinRM and builds the complete
 * human handoff package. The runner NEVER shadows a session.
 */

export async function rdpShadowPrepImpl(core: ExecutorCore, args: {
  host: string;
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  const denied = checkDestructive(RDP_SHADOW_PREP_PS);
  if (denied) {
    return core.refusedResult("winrm", args.host, `shadow-prep script tripped the denylist (${denied}) — refusing`);
  }
  const pre = core.preflight("winrm", args.host, args.scopeHosts, RDP_SHADOW_PREP_PS);
  if ("refused" in pre) return core.refusedResult("winrm", args.host, pre.refused);
  const t = core.deps.winrm();
  try {
    const r = await core.bounded(
      t.exec({
        host: args.host,
        creds: pre.creds,
        command: RDP_SHADOW_PREP_PS,
        powershell: true,
        timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
        signal: args.signal,
      }),
      (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 5_000,
      "rdp_shadow_prep",
      t,
    );
    const handoff = buildShadowHandoff(r.stdout, args.host);
    return {
      ok: true,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(
        `rdp shadow prep ${args.host}: session/policy enumeration complete — HUMAN OPERATOR REQUIRED for the shadowing act`,
        pre.secrets,
      ),
      output: redactSecrets(capOutput(handoff), pre.secrets),
      ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "winrm",
      host: args.host,
      summary: redactSecrets(`rdp shadow prep ${args.host} failed: ${(err as Error).message}`, pre.secrets),
      output: "",
      ms: Date.now() - started,
    };
  } finally {
    await t.close().catch(() => undefined);
  }
}

/**
 * Pass-the-hash over SMB with NTLMv2 (battery WS-023). The NT hash is the
 * test account's OWN, client-provided via REDTEAM_SMB_NTHASH — handled
 * with password-grade secrecy.
 */
