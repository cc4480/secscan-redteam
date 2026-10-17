/**
 * Operator policy rules (v0.34.0) — allow/deny over tool calls, deny-wins.
 *
 * An engagement is often bound by a client's rules ("never touch the payment
 * path", "only these hosts", "no file writes"). Today that would mean patching
 * the dispatcher. This makes it data: a JSON file the operator supplies, loaded
 * once at engagement start and enforced mechanically before any packet, exactly
 * like the tier and variant caps.
 *
 * Format (REDTEAM_POLICY_FILE points at it):
 *   { "allow": ["*"], "deny": ["smb_exec *", "* 10.0.0.5"] }
 *
 * Subjects are matched as `<tool>` and `<tool> <target>`, so a rule can scope by
 * tool alone or by tool + host. Deny always wins; when `allow` is non-empty and
 * nothing matches it, the call is denied (default-deny, opt-in allow-list).
 *
 * Patterns are globs (`*`, `?`), case-insensitive — the same vocabulary the
 * external-tool registry uses for its command rules, so operators learn one
 * syntax.
 */

export interface PolicyRules {
  allow: string[];
  deny: string[];
  /** Where the rules came from (file path or "inline"), for the audit trail. */
  source: string;
}

export const POLICY_ENV_FILE = "REDTEAM_POLICY_FILE";

/** Translate a glob into an anchored, case-insensitive RegExp. */
export function globToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .trim()
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

/** True when `value` matches the glob pattern. */
export function globMatch(pattern: string, value: string): boolean {
  const p = pattern.trim();
  if (p === "" || p === "*") return true;
  return globToRegExp(p).test(value.trim());
}

/** Parse a policy document. Returns undefined for anything unrecognisable (fail closed at the caller). */
export function parsePolicy(raw: unknown, source = "inline"): PolicyRules | undefined {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const obj = raw as Record<string, unknown>;
  const list = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").map((s) => s.trim()).filter(Boolean) : [];
  return { allow: list(obj["allow"]), deny: list(obj["deny"]), source };
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
}

/**
 * Check one tool call against the rules. `subject` candidates are the bare tool
 * name and `"<tool> <target>"` when a target is known; a pattern matching either
 * counts. Deny wins over allow.
 */
export function checkToolPolicy(
  rules: PolicyRules | undefined,
  tool: string,
  target?: string,
  args?: Record<string, unknown>,
): PolicyDecision {
  if (!rules) return { allowed: true, reason: "no policy configured" };
  const subjects = [tool, target ? `${tool} ${target}` : undefined].filter((s): s is string => Boolean(s));
  // Include a compact args rendering so operator rules can scope by parameter
  // (e.g. `* --mode=delete`), without exposing the raw object to the matcher.
  if (args) {
    const rendered = Object.entries(args)
      .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
      .map(([k, v]) => `${k}=${String(v)}`)
      .join(" ");
    if (rendered) subjects.push(`${tool} ${rendered}`);
  }
  for (const pattern of rules.deny) {
    if (subjects.some((s) => globMatch(pattern, s))) {
      return { allowed: false, reason: `deny rule ${JSON.stringify(pattern)} matched (${rules.source})` };
    }
  }
  if (rules.allow.length > 0 && !rules.allow.some((p) => subjects.some((s) => globMatch(p, s)))) {
    return { allowed: false, reason: `no allow rule matched — allow-list is non-empty (default deny, ${rules.source})` };
  }
  return { allowed: true, reason: "allowed by policy" };
}
