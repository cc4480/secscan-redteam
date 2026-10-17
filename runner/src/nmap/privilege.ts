/**
 * Nmap raw-socket privilege handling (v0.33.0).
 *
 * Every profile in `policy.ts` is a SYN scan (`-sS`), because that is the
 * correct default when the runner has the privilege to use it. On Windows that
 * privilege is not free: `-sS` needs an elevated token *and* a packet-capture
 * driver (Npcap), and on Linux it needs `CAP_NET_RAW`. An unprivileged runner
 * therefore failed every scan with a raw-socket error — and the whole host
 * battery lost its port map, which is the input every later step needs.
 *
 * The honest fallback is a TCP connect scan (`-sT`): identical port states, no
 * raw sockets, no driver, no elevation. The only things that genuinely need raw
 * access are OS detection (`-O`, `--osscan-guess`) and UDP (`-sU`), so those are
 * dropped on the fallback and reported as such.
 *
 * This module is pure so the decision can be tested without running nmap.
 */

/** Stderr signatures that mean "this scan failed for lack of raw-socket privilege". */
const PRIVILEGE_FAILURE =
  /raw socket|requires (root|administrator|privileg)|npcap|winpcap|access is denied|permission denied|operation not permitted/i;

/** True when nmap's failure looks like a privilege/Npcap problem rather than a target problem. */
export function isNmapPrivilegeFailure(stderr: string | undefined | null): boolean {
  return PRIVILEGE_FAILURE.test(String(stderr ?? ""));
}

/** Flags that cannot work without raw sockets and must be dropped on a connect scan. */
const RAW_ONLY_FLAGS = new Set(["-O", "--osscan-guess", "-sU"]);

/**
 * Rewrite an nmap argv for an unprivileged connect scan.
 *
 * Returns `undefined` when there is nothing to rewrite (no `-sS` present) so the
 * caller can tell "already connect" from "rewritten". The binary stays argv[0].
 */
export function connectScanArgv(argv: readonly string[]): string[] | undefined {
  if (!argv.includes("-sS")) return undefined;
  return argv
    .map((token) => (token === "-sS" ? "-sT" : token))
    .filter((token) => !RAW_ONLY_FLAGS.has(token));
}
