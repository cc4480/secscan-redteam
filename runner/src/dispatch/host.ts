/**
 * Host-execution tool handlers: ssh/smb/winrm wave 1 + wave 2 (v0.19.0 refactor — extracted from dispatch.ts).
 */
import { BATTERY_CATEGORIES, type BatteryCategory } from "../battery.js";
import { isTargetId } from "../targets.js";
import { techniqueAllowed } from "../gate.js";
import { sleep } from "../util.js";
import { type Ctx } from "../context.js";
import { type ActorRole, type EngagementPhase } from "../types.js";
import type { ToolCallRequest } from "@secscan/redteam-llm-router";
import { type DispatchResult } from "./types.js";
import { noteCategoryCoverage, numArg, optStr } from "./prelude.js";

const WAVE2_TOOLS = new Set([
  "winrm_probe",
  "rdp_auth",
  "rdp_shadow_prep",
  "smb_pth",
  "ad_enum",
  "krb_ptt",
  "ssh_agent_audit",
  "nfs_enum",
]);

/**
 * Shared preflight for EVERY host-exec tool, wave 1 and wave 2 alike.
 *
 * The ROE technique check, the pinned targetProfile check, probe counting and
 * the coverage bookkeeping were byte-for-byte identical in both families, one
 * copy per wave. Keeping them in one place is the point: the nmap scope gap
 * came from a safety check that existed in some handlers and not others, and
 * duplicated checks drift the same way. One source, one fix.
 *
 * Returns a ready-to-return refusal, or the scope-checked host plus the
 * kill-switch controller the caller must release in its `finally`.
 */
function hostExecPrelude(
  ctx: Ctx,
  call: ToolCallRequest,
  args: Record<string, unknown>,
  attackId: string | undefined,
  category: BatteryCategory | undefined,
  wantTp: "linux" | "windows",
): { refused: DispatchResult } | { host: string; ctrl: AbortController } {
  if (!techniqueAllowed(attackId, ctx.input.mode, ctx.input.roe)) {
    return { refused: { result: `DENIED by ROE: technique ${attackId} is excluded for this engagement.`, attackId, target: String(args["host"] ?? "") } };
  }
  const rawTp = typeof args["targetProfile"] === "string" ? (args["targetProfile"] as string).toLowerCase() : "";
  if (!isTargetId(rawTp) || rawTp !== wantTp) {
    return {
      refused: {
        result: `DENIED: ${call.name} requires targetProfile "${wantTp}" (host targets are never inferred) — got ${JSON.stringify(args["targetProfile"] ?? null)}.`,
        attackId,
        target: String(args["host"] ?? ""),
      },
    };
  }
  const host = String(args["host"] ?? "");
  // The exec is really going out: count it toward the battery.
  ctx.probesUsed++;
  noteCategoryCoverage(ctx, category, wantTp);
  // Kill-switch wiring: register this execution's controller so a coordinator
  // abort terminates it mid-flight (shared ctx → all parallel tasks). The
  // executor checks the aborted flag before starting.
  const ctrl = new AbortController();
  ctx.hostKill.controllers.add(ctrl);
  return { host, ctrl };
}

export async function handleHostTools(ctx: Ctx, _role: ActorRole, _phase: EngagementPhase, call: ToolCallRequest, args: Record<string, unknown>): Promise<DispatchResult | null> {
  if (call.name !== "ssh_exec" && call.name !== "smb_exec" && call.name !== "winrm_exec" && !WAVE2_TOOLS.has(call.name)) return null;
if (call.name === "ssh_exec" || call.name === "smb_exec" || call.name === "winrm_exec") {
  const attackId = typeof args["attackId"] === "string" ? (args["attackId"] as string).toUpperCase() : undefined;
  const rawCat = typeof args["category"] === "string" ? (args["category"] as string).toLowerCase() : "";
  const category = (BATTERY_CATEGORIES as string[]).includes(rawCat) ? (rawCat as BatteryCategory) : undefined;
  const pre = hostExecPrelude(ctx, call, args, attackId, category, call.name === "ssh_exec" ? "linux" : "windows");
  if ("refused" in pre) return pre.refused;
  const { host, ctrl } = pre;
  try {
    if (ctx.input.mode === "black") await sleep(Math.random() * 2500); // jitter
    const exec = ctx.hostExecutor;
    exec.killSwitch = ctx.hostKill;
    const res =
      call.name === "ssh_exec"
        ? await exec.sshExec({ host, port: numArg(args["port"]), command: String(args["command"] ?? ""), scopeHosts: ctx.hosts, signal: ctrl.signal })
        : call.name === "smb_exec"
          ? await exec.smbExec({
              host,
              operation: (["list_shares", "list_dir", "stat"] as const).includes(args["operation"] as "list_shares") ? (args["operation"] as "list_shares" | "list_dir" | "stat") : "list_shares",
              share: optStr(args["share"]),
              path: optStr(args["path"]),
              extraShares: Array.isArray(args["extraShares"]) ? (args["extraShares"] as unknown[]).map(String).slice(0, 20) : [],
              scopeHosts: ctx.hosts,
              signal: ctrl.signal,
            })
          : await exec.winrmExec({
              host,
              port: numArg(args["port"]),
              command: String(args["command"] ?? ""),
              powershell: args["powershell"] !== false,
              useTls: args["useTls"] === true,
              scopeHosts: ctx.hosts,
              signal: ctrl.signal,
            });
    if (/kill switch/i.test(res.summary)) {
      return { result: `ABORTED by coordinator kill switch — engagement halting. ${res.summary}`, attackId, target: host };
    }
    if (res.refused) {
      return { result: `DENIED by host-exec safety core: ${res.refused}`, attackId, target: host };
    }
    const out = res.output ? ` Output: ${res.output.slice(0, 600)}` : "";
    return { result: `${res.summary}.${out}`, attackId, target: host, ok: res.ok };
  } finally {
    ctx.hostKill.controllers.delete(ctrl);
  }
}

// -- Host execution tools, wave 2 (v0.10.0): winrm_probe, rdp_auth,
// rdp_shadow_prep, smb_pth, ad_enum, krb_ptt, ssh_agent_audit, nfs_enum.
// Same safety-core contract as wave 1: ROE technique check, pinned
// targetProfile (never inferred), coverage counting, kill-switch
// controller registration, DENIED/ABORTED mapping.

if (WAVE2_TOOLS.has(call.name)) {
  const attackId = typeof args["attackId"] === "string" ? (args["attackId"] as string).toUpperCase() : undefined;
  const rawCat = typeof args["category"] === "string" ? (args["category"] as string).toLowerCase() : "";
  const category = (BATTERY_CATEGORIES as string[]).includes(rawCat) ? (rawCat as BatteryCategory) : undefined;
  const wantTp = call.name === "ssh_agent_audit" || call.name === "nfs_enum" ? "linux" : "windows";
  const pre = hostExecPrelude(ctx, call, args, attackId, category, wantTp);
  if ("refused" in pre) return pre.refused;
  const { host, ctrl } = pre;
  try {
    if (ctx.input.mode === "black") await sleep(Math.random() * 2500); // jitter
    const exec = ctx.hostExecutor;
    exec.killSwitch = ctx.hostKill;
    const t = { host, scopeHosts: ctx.hosts, signal: ctrl.signal };
    const res =
      call.name === "winrm_probe"
        ? await exec.winrmProbe({ ...t, ports: Array.isArray(args["ports"]) ? (args["ports"] as unknown[]).map(Number).filter((n) => n > 0 && n < 65536).slice(0, 16) : undefined })
        : call.name === "rdp_auth"
          ? await exec.rdpValidate({ ...t, port: numArg(args["port"]) })
          : call.name === "rdp_shadow_prep"
            ? await exec.rdpShadowPrep(t)
            : call.name === "smb_pth"
              ? await exec.smbPth({ ...t, port: numArg(args["port"]) })
              : call.name === "ad_enum"
                ? await exec.adEnum({
                    ...t,
                    port: numArg(args["port"]),
                    useTls: args["useTls"] === true,
                    baseDn: optStr(args["baseDn"]),
                    operations: (Array.isArray(args["operations"]) ? args["operations"] : []).map(String),
                  })
                : call.name === "krb_ptt"
                  ? await exec.krbPtt({ ...t, spn: optStr(args["spn"]) })
                  : call.name === "ssh_agent_audit"
                    ? await exec.sshAgentAudit({ ...t, port: numArg(args["port"]), mode: args["mode"] === "abuse-path" ? "abuse-path" : "socket-check" })
                    : await exec.nfsEnum(t);
    if (/kill switch/i.test(res.summary)) {
      return { result: `ABORTED by coordinator kill switch — engagement halting. ${res.summary}`, attackId, target: host };
    }
    if (res.refused) {
      return { result: `DENIED by host-exec safety core: ${res.refused}`, attackId, target: host };
    }
    const out = res.output ? ` Output: ${res.output.slice(0, 600)}` : "";
    return { result: `${res.summary}.${out}`, attackId, target: host, ok: res.ok };
  } finally {
    ctx.hostKill.controllers.delete(ctrl);
  }
}

// -- Metasploit bridge (v0.11.0): msf_exec --------------------------------
// search/suggest are recon-safe (never fire); run is EXPLOIT PHASE ONLY —
// the recon→exploit coordinator sign-off is the approval gate, enforced
// mechanically here (not by prompt). Same contract as host tools: ROE
// technique check, pinned targetProfile, coverage counting, kill-switch
// controller, DENIED/ABORTED mapping. Per-CVE instances (attackId like
// "MSF-CVE-2021-44228" is NOT a valid attackId — the coordinator rejects
// anything that isn't a real ATT&CK ID (lookupTechnique). Per-CVE instances
// travel in the `cve` field and are named in the result; they reconcile
// against coverage via the category, and the module + CVE are named in the
// result so the report lists them like any other battery item.
  return null;
}
