/**
 * SMB transport implementations: smbExec, smbPth (v0.19.0 refactor — extracted from executor.ts).
 */
import { HOST_EXEC_TIMEOUT_MS, type HostCredentials, capOutput, collectSecrets, redactSecrets, resolveSmbHashCredentials, validateHostTarget } from "../common.js";
import { ExecutorCore } from "./core.js";
import { type HostExecResult } from "./types.js";

export async function smbExecImpl(core: ExecutorCore, args: {
  host: string;
  operation: "list_shares" | "list_dir" | "stat";
  share?: string;
  path?: string;
  extraShares?: string[];
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  const pre = core.preflight("smb", args.host, args.scopeHosts);
  if ("refused" in pre) return core.refusedResult("smb", args.host, pre.refused);
  if ((args.operation === "list_dir" || args.operation === "stat") && !args.share) {
    return core.refusedResult("smb", args.host, `${args.operation} requires a share name`, pre.secrets);
  }
  const t = core.deps.smb();
  try {
    const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
    const tArgs = { host: args.host, creds: pre.creds, timeoutMs, signal: args.signal };
    let output: string;
    if (args.operation === "list_shares") {
      const res = await core.bounded(t.probeShares(tArgs, args.extraShares ?? []), timeoutMs + 5_000, "smb_exec", t);
      output = res.map((r) => `${r.share}: ${r.accessible ? "ACCESSIBLE" : "denied"} (${r.note})`).join("\n");
    } else if (args.operation === "list_dir") {
      const entries = await core.bounded(t.listDir(tArgs, args.share!, args.path ?? ""), timeoutMs + 5_000, "smb_exec", t);
      output = entries.map((e) => `${e.isDirectory ? "[dir] " : ""}${e.name}`).join("\n") || "(empty)";
    } else {
      const st = await core.bounded(t.stat(tArgs, args.share!, args.path ?? ""), timeoutMs + 5_000, "smb_exec", t);
      output = st.exists ? `exists, ${st.isDirectory ? "directory" : `file${st.size !== undefined ? `, ${st.size} bytes` : ""}`}` : "not found";
    }
    const where = args.operation === "list_shares" ? "shares" : `${args.share}${args.path ? `\\${args.path}` : ""}`;
    return {
      ok: true,
      transport: "smb",
      host: args.host,
      summary: redactSecrets(`smb ${args.host}: ${args.operation} ${where}`, pre.secrets),
      output: redactSecrets(capOutput(output), pre.secrets),
      ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "smb",
      host: args.host,
      summary: redactSecrets(`smb ${args.host} ${args.operation} failed: ${(err as Error).message}`, pre.secrets),
      output: "",
      ms: Date.now() - started,
    };
  } finally {
    await t.close().catch(() => undefined);
  }
}


export async function smbPthImpl(core: ExecutorCore, args: {
  host: string;
  port?: number;
  scopeHosts: string[];
  timeoutMs?: number;
  signal?: AbortSignal;
}): Promise<HostExecResult> {
  const started = Date.now();
  if (core.killSwitch.aborted) {
    return core.refusedResult("smb", args.host, "kill switch active — coordinator aborted; no new host executions");
  }
  const v = validateHostTarget(args.host, args.scopeHosts);
  if (!v.ok) return core.refusedResult("smb", args.host, v.reason);
  let hashCreds: HostCredentials;
  let secrets: string[];
  try {
    hashCreds = resolveSmbHashCredentials(core.deps.env);
    secrets = collectSecrets(hashCreds);
  } catch (err) {
    return core.refusedResult("smb", args.host, (err as Error).message);
  }
  const t = core.deps.smbPth();
  try {
    const r = await core.bounded(
      t.auth({
        host: args.host,
        port: args.port,
        username: hashCreds.username,
        ntHashHex: hashCreds.ntHash!,
        domain: hashCreds.domain,
        timeoutMs: args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS,
        signal: args.signal,
      }),
      (args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS) + 5_000,
      "smb_pth",
      t,
    );
    const verdict = r.hashAccepted === true ? "HASH ACCEPTED (PtH works)" : r.hashAccepted === false ? "hash rejected" : "no verdict";
    return {
      ok: r.hashAccepted === true,
      transport: "smb",
      host: args.host,
      summary: redactSecrets(
        `smb pass-the-hash ${args.host}: ${verdict} (${r.dialect ?? "no dialect"}, status ${r.ntStatus ?? "?"})`,
        secrets,
      ),
      output: redactSecrets(capOutput(r.note), secrets),
      ms: Date.now() - started,
    };
  } catch (err) {
    return {
      ok: false,
      transport: "smb",
      host: args.host,
      summary: redactSecrets(`smb pass-the-hash ${args.host} failed: ${(err as Error).message}`, secrets),
      output: "",
      ms: Date.now() - started,
    };
  } finally {
    await t.close().catch(() => undefined);
  }
}

/**
 * Read-only AD enumeration (batteries WS-038 attack paths, WS-043 AD CS).
 * LDAP simple bind as the test account; nothing is ever written.
 */
