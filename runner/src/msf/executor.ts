/**
 * MsfExecutor — the runner's Metasploit bridge, behind the safety core.
 *
 * Preflight order (mirrors host-exec/executor.ts):
 *   1. kill-switch check (refuse new work when the coordinator aborted)
 *   2. ROE scope check (exact hostname match, fail closed, before any packet)
 *   3. module/payload policy (dos + destructive modules refused; only
 *      generic single-command payloads; the command is always the runner-built
 *      canary marker and additionally passes the destructive denylist)
 *   4. credential resolution (REDTEAM_MSFRPC_* env/Secure Vault only, fail
 *      fast with setup instructions)
 *   5. execution with timeout + abort signal; the console is destroyed on
 *      abort (that IS the kill switch for a running module)
 *   6. session hygiene: a validation run must not leave sessions behind —
 *      any session that wasn't there before is stopped immediately
 *   7. redaction of every secret from every string that leaves
 *
 * The request function is injectable so tests run against a fake msfrpcd.
 */

export { MsfExecutor, MSF_TIMEOUT_MS } from "./executor/executor.js";
export type { MsfDeps, MsfResult } from "./executor/executor.js";
