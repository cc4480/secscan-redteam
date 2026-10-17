/**
 * Secret redaction for the event log (v0.33.0).
 *
 * The event stream is the primary audit record, and its raw args/results must
 * never carry a live credential to disk. Two mechanisms, both applied at write
 * time and both pure/testable:
 *
 *   1. KEY-based: any object key that looks like a secret name (token, secret,
 *      password, passwd, pwd, key, credential, authorization, api_key, apikey)
 *      is replaced with "<redacted>" — regardless of depth.
 *   2. VALUE-based: every string is scanned for the literal secrets this
 *      process knows about (from the environment) and any occurrence is
 *      replaced with "<redacted>". This catches secrets embedded inside a
 *      free-form `result` string, which key-based redaction alone cannot.
 *
 * The lesson is from AlterEgo's event log, where redaction was top-level-only
 * and nested secrets (`args.token`, `args.nested.password`) reached disk in
 * cleartext. This port is deliberately recursive on both axes.
 */

/** Key names treated as secret carriers. Matched case-insensitively. */
const SECRET_KEY = /token|secret|password|passwd|pwd|credential|authorization|api[_-]?key|apikey|nthash|nthash16|private[_-]?key/i;

/** Environment names this runner treats as secrets. Non-empty values only. */
const SECRET_ENV_NAMES = [
  "DEEPSEEK_API_KEY",
  "QWEN_API_KEY",
  "SECSCAN_MCP_TOKEN",
  "SECLAYER_API_KEY",
  "REDTEAM_SMB_PASSWORD",
  "REDTEAM_SMB_NTHASH",
  "REDTEAM_SSH_PASSWORD",
  "REDTEAM_MSFRPC_PASS",
  "REDTEAM_UI_TOKEN",
  "REDTEAM_JIRA_API_TOKEN",
  "REDTEAM_SNOW_PASSWORD",
  "GITHUB_TOKEN",
  "GH_TOKEN",
];

/**
 * Collect the literal secret values present in the environment, for value-based
 * redaction. Returns [] when none are set. Values shorter than 6 characters are
 * dropped: masking a 2-char string would corrupt ordinary text.
 */
export function collectSecrets(env: NodeJS.ProcessEnv = process.env): string[] {
  const secrets: string[] = [];
  for (const name of SECRET_ENV_NAMES) {
    const value = (env[name] ?? "").trim();
    if (value.length >= 6) secrets.push(value);
  }
  return secrets;
}

/**
 * Recursively redact a value: secret-named keys are replaced, and any known
 * secret literal is masked wherever it appears in a string. Returns a new value;
 * primitives pass through unchanged.
 */
export function redact<T>(value: T, secrets: string[] = collectSecrets()): T {
  if (typeof value === "string") {
    let s: string = value;
    for (const secret of secrets) {
      if (s.includes(secret)) s = s.split(secret).join("<redacted>");
    }
    return s as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redact(item, secrets)) as unknown as T;
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      out[key] = SECRET_KEY.test(key) ? "<redacted>" : redact(val, secrets);
    }
    return out as T;
  }
  return value;
}
