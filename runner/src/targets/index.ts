/**
 * Target profiles + target-specific attack batteries (v0.8.0).
 *
 * Generic batteries test "a webapp". These batteries test THESE targets
 * against their REAL surfaces:
 *  - SecScan (scanner webapp, 120 items) + SecLayer (MCP/API layer, 80 items)
 *  - Windows host + AD (100+ items) + Linux host (100+ items)
 *
 * Target-specific beats generic because the same flaw class lands
 * differently on each surface: IDOR on a scan report is not IDOR on a
 * shopping cart; privesc on Windows is not privesc on Linux. Every item
 * names the actual endpoint, flow, mechanism, or parameter.
 *
 * FULL_BATTERY unified engagement: one operation, all selected targets, one
 * report — recon all → per-target exploit batteries → cross-cutting chains
 * → unified report. Coverage counts complete only when every selected
 * target × category cell is probed OR honestly blocked (3 × 4 = 12 cells).
 *
 * HONEST EXECUTION SCOPING (v0.9.0): the runner's host-exec tools
 * (`ssh_exec`, `smb_exec`, `winrm_exec` in runner/src/host-exec/) execute
 * the Windows/Linux batteries through the safety core (scope, denylist,
 * timeouts, audit). Host items that need MORE than non-interactive command
 * execution / SMB listing still carry needs:"host-exec tooling" and are
 * PLAN-ONLY: the agents write the hypothesis and expected evidence, and the
 * cell reports BLOCKED under Honest limits (never covered, never failed).
 * Items executable via http_probe (HTTP banner/TLS/headers on host web
 * ports) carry no marker and count toward their cells normally.
 * See docs/ROADMAP.md for the delivered host-exec track.
 *
 * Non-destructive always: never trigger emails to real users, never delete
 * scans/reports, benign canary content only, races are single paired
 * requests, credential testing against authorized test accounts only.
 * Items that need prerequisites say so in `needs` — honestly, never
 * pretending a test ran when its setup was missing.
 */

import type { BatteryCategory } from "../battery.js";
import { BATTERY_CATEGORIES, CATEGORY_LABELS } from "../battery.js";
import type { TargetBatteryItem, TargetId, TargetKind, TargetProfile } from "./types.js";
import { BATTERY_ITEM_COUNTS, FULL_BATTERY_TARGETS, HOST_EXEC_TOOLING, NEEDS_HUMAN_OPERATOR, NEEDS_KERBEROS_TICKET, NEEDS_MSFRPCD, NEEDS_NUCLEI, NEEDS_PRIVILEGED_CLIENT, TARGET_PREFIXES, TOTAL_BATTERY_ITEMS, isTargetId } from "./types.js";
import { SECSCAN_PROFILE } from "./secscan.js";
import { SECLAYER_PROFILE } from "./seclayer.js";
import { WINDOWS_PROFILE } from "./windows.js";
import { LINUX_PROFILE } from "./linux.js";

export type { TargetBatteryItem, TargetId, TargetKind, TargetProfile };
export { BATTERY_ITEM_COUNTS, FULL_BATTERY_TARGETS, HOST_EXEC_TOOLING, NEEDS_HUMAN_OPERATOR, NEEDS_KERBEROS_TICKET, NEEDS_MSFRPCD, NEEDS_NUCLEI, NEEDS_PRIVILEGED_CLIENT, TARGET_PREFIXES, TOTAL_BATTERY_ITEMS, isTargetId };

export const TARGET_PROFILES: Record<TargetId, TargetProfile> = {
  secscan: SECSCAN_PROFILE,
  seclayer: SECLAYER_PROFILE,
  windows: WINDOWS_PROFILE,
  linux: LINUX_PROFILE,
};

export function lookupTargetProfile(id: string): TargetProfile | undefined {
  const key = id.toLowerCase();
  return isTargetId(key) ? TARGET_PROFILES[key] : undefined;
}

/**
 * Selected targets for a full-battery engagement. Defaults to all four;
 * --targets narrows the subset (e.g. secscan,seclayer for the web-only run).
 */
export function activeTargets(input: { targets?: TargetId[] }): TargetId[] {
  if (input.targets && input.targets.length > 0) {
    const valid = input.targets.map((t) => String(t).toLowerCase()).filter(isTargetId);
    if (valid.length > 0) return valid;
  }
  return [...FULL_BATTERY_TARGETS];
}

export function targetItemsFor(profile: TargetProfile, category: BatteryCategory): TargetBatteryItem[] {
  return profile.battery.filter((b) => b.category === category);
}

/**
 * Every distinct ATT&CK technique ID used across all batteries (v0.12.0) —
 * the compliance module maps each of these to controls, and the test
 * suite asserts zero unmapped IDs. Items without an attackId are skipped
 * (the mapping is technique-keyed; findings without ATT&CK IDs carry no
 * control mapping, honestly).
 */
export function allBatteryAttackIds(): string[] {
  const ids = new Set<string>();
  for (const t of FULL_BATTERY_TARGETS) {
    for (const item of TARGET_PROFILES[t].battery) {
      if (item.attackId) ids.add(item.attackId);
    }
  }
  return [...ids].sort();
}

/** Infer which target a probe URL belongs to: the MCP path is SecLayer, everything else is the webapp. Host targets are never inferred — they need an explicit tag. */
export function inferTargetProfile(url: string): TargetId {
  try {
    const path = new URL(url).pathname.toLowerCase();
    if (path.startsWith("/api/mcp")) return "seclayer";
  } catch {
    /* unparseable — default to the webapp */
  }
  return "secscan";
}

/**
 * A coverage cell is BLOCKED when the runner cannot execute any of its
 * items: every item in that target+category carries a `needs` prerequisite
 * the operator has not met, and no probe was tagged for the cell. Blocked
 * cells are reported under Honest limits — never counted as covered, never
 * counted as failed. (v0.10.0: no cell is fully blocked; the mechanic stays
 * for future batteries.)
 */
export function targetCellBlocked(profile: TargetProfile, category: BatteryCategory): boolean {
  const items = targetItemsFor(profile, category);
  return items.length > 0 && items.every((b) => !!b.needs);
}

export type CellStatus = "done" | "blocked" | "missing";

/** Cell status for one target × category. */
export function targetCellStatus(
  profile: TargetProfile,
  category: BatteryCategory,
  probed: Set<BatteryCategory> | undefined,
): CellStatus {
  if (probed?.has(category)) return "done";
  if (targetCellBlocked(profile, category)) return "blocked";
  return "missing";
}

/**
 * Compact checklist for one target's battery, for prompt injection.
 * 400+ items can't ship with full detail — every item appears as
 * ID + name + one-line brief, grouped by category. The full `what`
 * stays in-module; agents expand per item as they work it.
 */
export function targetBatteryChecklistText(profile: TargetProfile, mode: "red" | "black"): string {
  const lines: string[] = [`## ${profile.name} (${profile.baseUrl}) — ${profile.battery.length} items`, `Auth model: ${profile.authModel}`];
  for (const cat of BATTERY_CATEGORIES) {
    lines.push(`### ${CATEGORY_LABELS[cat]}`);
    for (const item of targetItemsFor(profile, cat)) {
      const stealth = mode === "black" && item.blackNote ? ` [black: ${item.blackNote}]` : "";
      const needs = item.needs ? ` [needs: ${item.needs}]` : "";
      const deferred = item.deferredReason ? ` [DEFERRED: ${item.deferredReason}]` : "";
      lines.push(`- ${item.id} ${item.name}: ${item.brief}${stealth}${needs}${deferred}`);
    }
  }
  return lines.join("\n");
}

/** Selected targets' batteries, for the full-battery plan skeleton. */
export function fullBatteryChecklistText(mode: "red" | "black", targets?: TargetId[]): string {
  return activeTargets({ targets }).map((t) => targetBatteryChecklistText(TARGET_PROFILES[t], mode)).join("\n\n");
}

const PLAN_PHASE_NAMES: Record<TargetId, string> = {
  secscan: "EXPLOIT SecScan battery (SS-*) — the scanner webapp: intake, SSRF guard, DNS gate, lifecycle, reports, shares, opt-out, rate limits, auth, API, efficacy canaries.",
  seclayer: "EXPLOIT SecLayer battery (SL-*) — the MCP/API layer: handshake, tools/list, per-tool per-param attacks, JSON-RPC layer, HTTP layer, auth layer, notifications, quotas, oracles.",
  windows: `EXPLOIT Windows battery (WS-*, ${BATTERY_ITEM_COUNTS.windows} items) — host + AD: recon, auth attacks (test accounts only), AD attack paths, privesc, lateral movement, credential-exposure audit, persistence findings. All items are executable via the host tools (smb_exec/smb_pth, winrm_exec/winrm_probe, rdp_auth, ad_enum, krb_ptt) plus the Metasploit/Nuclei methodology items (WS-105–108). Items needing operator-supplied prerequisites are tagged [needs: …] in the checklist; two need more than operator tooling — WS-064 (kerberos ticket material) and WS-065 (a human operator for the shadowing act itself; use rdp_shadow_prep to prepare the handoff — never pretend the runner shadowed a session). HTTP(S) banner/TLS/headers recon via http_probe IS executable and counts toward the validation cell.`,
  linux: `EXPLOIT Linux battery (LX-*, ${BATTERY_ITEM_COUNTS.linux} items) — host: recon, SSH, privesc, exposed services, file-permission audit, persistence findings. All items are executable via the host tools (ssh_exec, ssh_agent_audit, nfs_enum) plus the Metasploit/Nuclei methodology items (LX-107–110). Items needing operator-supplied prerequisites are tagged [needs: …] in the checklist; LX-041's mount+file proof needs a privileged test client (REDTEAM_NFS_TEST_CLIENT, in scope) — the export enumeration itself runs unprivileged. HTTP(S) banner/TLS/headers recon via http_probe IS executable and counts toward the validation cell.`,
};

/**
 * The unified engagement plan skeleton — one operation, all selected
 * targets, one report. The coordinator expands this into the operation
 * plan; the runner enforces the coverage rule mechanically.
 */
export function fullBatteryPlanSkeleton(targets?: TargetId[]): string {
  const selected = activeTargets({ targets });
  const names = selected.map((t) => TARGET_PROFILES[t].name).join(" + ");
  const phases = selected.map((t, i) => `${i + 2}. ${PLAN_PHASE_NAMES[t]}`).join("\n");
  const cells = selected.length * BATTERY_CATEGORIES.length;
  return `## FULL-BATTERY unified engagement — ${names}, ONE operation
Phase order (do not reorder):
1. RECON all surfaces — every selected target: entry points, auth models, fingerprints, WAF/EDR signals.
${phases}
${selected.length + 2}. CROSS-CUTTING CHAINS — paths spanning targets: does a primitive on one surface become impact on another? State each chain as one line.
${selected.length + 3}. UNIFIED REPORT — one Megazord narrative, all batteries, honest limits per target.
Coverage rule (runner-enforced): the battery counts complete only when ALL THREE categories are probed on EVERY selected target, or the cell is honestly BLOCKED (3 × ${selected.length} = ${cells} cells). Tag every http_probe with targetProfile (${selected.map((t) => `"${t}"`).join(" | ")}) — the runner also infers secscan/seclayer from the URL path (/api/mcp → seclayer). Host targets (windows/linux) are NEVER inferred: tag explicitly.`;
}
