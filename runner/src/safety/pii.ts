/**
 * PII redaction (v0.13.0) — the production safety case.
 *
 * Secrets (passwords, keys, hashes) were already redacted. Buyers also demand
 * PII handling: tool outputs routinely contain other people's data (error
 * pages echo emails, configs leak phone numbers, dumps contain ID-like
 * strings). This module redacts PII patterns from tool outputs BEFORE they
 * reach the audit log, the agent context, findings evidence, and reports.
 *
 * Deliberately conservative: we redact the well-known shapes (email, phone,
 * US-SSN-like, payment-card-like with a Luhn check) and document exactly what
 * we do NOT touch (IP addresses and hostnames stay — the agents need them to
 * reason about targets; usernames stay — they are usually the test account).
 * Over-redaction would blind the agents; under-redaction leaks PII. The
 * pattern list is exported so the manifest and docs state it plainly.
 */

interface PiiPattern {
  label: string;
  re: RegExp;
  /** Optional second-stage validator (e.g. Luhn for cards). */
  validate?: (match: string) => boolean;
}

function luhnOk(digits: string): boolean {
  const d = digits.replace(/\D/g, "");
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = Number(d[i]);
    if (dbl) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

const PATTERNS: PiiPattern[] = [
  {
    label: "email address",
    // Standard email shape; avoids matching version strings like "1.2@3".
    re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  },
  {
    label: "phone number",
    // International / US / common formats with separators. The validate()
    // guard is load-bearing: bare 7–9 digit dash groups (CVE numbers like
    // 2017-0144, ticket IDs) are NOT phones — a real phone has a country
    // code (+), parenthesized area code, or at least 10 digits.
    re: /(?<![\d.])(?<!CVE[-\s:])(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{3,4}(?![\d.])/g,
    validate: (m) => {
      const digits = m.replace(/\D/g, "");
      if (digits.length < 7 || digits.length > 15) return false;
      if (!/\+/.test(m) && !/\(/.test(m) && digits.length < 10) return false;
      return true;
    },
  },
  {
    label: "US-SSN-like number",
    re: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    label: "payment-card-like number",
    re: /\b(?:\d[ -]?){13,19}\b/g,
    validate: luhnOk,
  },
];

/** The PII shapes we redact — exported for the manifest and docs. */
export function piiPatternLabels(): string[] {
  return PATTERNS.map((p) => p.label);
}

/**
 * Redact PII from text. Pure function — safe to apply to any tool output,
 * evidence string, or report fragment. Idempotent.
 */
export function redactPii(text: string): string {
  if (!text) return text;
  let out = text;
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    out = out.replace(p.re, (m) => (p.validate && !p.validate(m) ? m : "[PII-REDACTED]"));
  }
  return out;
}

/**
 * Heuristic: does this text still contain likely PII after redaction?
 * Used by tests and by the manifest's self-check line — not a guarantee,
 * stated honestly as a heuristic.
 */
export function likelyContainsPii(text: string): boolean {
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    const m = p.re.exec(text);
    if (m && (!p.validate || p.validate(m[0]))) return true;
  }
  return false;
}
