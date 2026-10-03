/**
 * Linux target profile — host.
 *
 * EXHAUSTIVE battery (v0.8.0): surface × technique. Every distinct attacker
 * intent against a Linux host's real surface is one item. Surfaces: recon
 * (host enumeration plus prober-reachable web ports), SSH hardening & access,
 * privilege escalation (SUID/SGID, sudo, capabilities, cron/at, PATH and
 * linker hijacking, systemd, kernel, NFS, containers/LXD), exposed services
 * (audited as FINDINGS via read-only checks), file-permission & secret
 * auditing, persistence FINDINGS (reported, never planted), accounts &
 * authentication, logging & detection, network posture, kernel & system
 * hardening, cross-cutting chains.
 *
 * Execution model (v0.10.0): the runner's `ssh_exec` host tool executes this
 * battery — non-interactive SSH command execution with the safety core
 * (scope, denylist, timeouts) — plus `ssh_agent_audit` (LX-018/LX-019: agent
 * socket exposure + abuse-path analysis via agent-forwarded sessions) and
 * `nfs_enum` (LX-041: userland RPC/MOUNT export enumeration, no kernel
 * mount). One item keeps an honest prerequisite in `needs` (NOT plan-only —
 * it executes when the prerequisite is met): LX-041's mount+file proof
 * needs a privileged test client (operator-designated, in scope).
 *
 * Non-destructive always: read-only enumeration preferred; no service
 * crashing; no destructive payloads; persistence mechanisms REPORTED as
 * findings, never planted; privesc proofs are safe non-destructive checks
 * (version output, permission bits, --help, dry reads) — never a real root
 * shell. Credential testing against client-PROVIDED authorized test accounts
 * ONLY (T1078) — never guessed, never stuffed.
 */

import type { TargetBatteryItem, TargetProfile } from "./types.js";
import { LINUX_PART_1 } from "./linux-part-1.js";
import { LINUX_PART_2 } from "./linux-part-2.js";
import { LINUX_PART_3 } from "./linux-part-3.js";
import { LINUX_PART_4 } from "./linux-part-4.js";
import { LINUX_PART_5 } from "./linux-part-5.js";

const LINUX_BATTERY: TargetBatteryItem[] = [
  ...LINUX_PART_1,
  ...LINUX_PART_2,
  ...LINUX_PART_3,
  ...LINUX_PART_4,
  ...LINUX_PART_5,
];

export const LINUX_PROFILE: TargetProfile = {
  id: "linux",
  name: "Linux host",
  baseUrl: "in-scope hosts (ROE scope)",
  kind: "host-linux",
  authModel: "SSH keys/passwords; sudo for elevation. Credential testing against client-PROVIDED authorized test accounts ONLY (T1078) — never guessed, never stuffed.",
  scopeNotes: "Non-destructive always: read-only enumeration preferred; no service crashing; no destructive payloads; persistence mechanisms REPORTED as findings, never planted; privesc proofs are safe non-destructive checks.",
  battery: LINUX_BATTERY,
};
