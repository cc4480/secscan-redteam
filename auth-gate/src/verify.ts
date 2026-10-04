/**
 * Domain-ownership verification — the legal backbone of the red-team.
 *
 * The SecScan SERVER is authoritative. It issues its own challenge tokens
 * (`secscan-verify-…`, via the `start_domain_verification` MCP tool), expects
 * the TXT record at `_secscan-challenge.<domain>`, and enforces passive-only
 * scanning on unverified domains itself. This package never issues tokens and
 * performs no DNS lookups of its own: the gate asks the server
 * (`list_verified_domains`, see server.ts) and treats a server-verified
 * domain as authorized for aggressive testing.
 *
 * Everything here is pure and dependency-free. Any check error, timeout, or
 * unparseable response means "unverified" — false IS the answer, never an
 * exception that could be mistaken for approval.
 */

/** The TXT record name the SecScan server checks, e.g. `_secscan-challenge.example.com`. */
export const SERVER_CHALLENGE_PREFIX = "_secscan-challenge";

/** Prefix of challenge tokens issued by the SecScan server (informational — the gate never issues tokens). */
export const SERVER_TOKEN_PREFIX = "secscan-verify-";

/** Normalize a raw URL or bare domain to a lowercase hostname. */
export function extractDomain(rawUrl: string): string {
  let u = (rawUrl || "").trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return new URL(u).hostname.toLowerCase();
}

/** Normalize a candidate domain string: lowercase, trimmed, no trailing dot, hostname only. */
function normalizeDomain(raw: string): string | null {
  const t = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!t) return null;
  try {
    return extractDomain(t);
  } catch {
    return null;
  }
}

/**
 * The live server's actual list_verified_domains response is sometimes prose
 * ("Verified (full active testing): secscan.us") rather than a bare domain,
 * JSON, or a recognized object key. We deliberately do NOT substring-match
 * domain-shaped tokens out of arbitrary prose here: a sentence can just as
 * easily name an *unverified* domain ("NOT VERIFIED: evil.example.com — TXT
 * record missing", or the real wording this gate has actually seen: "No
 * verified domains yet"). A naive extractor can't tell "verified" from "NOT
 * verified" apart, which would flip this fail-closed gate into fail-open for
 * exactly the inputs it exists to be strict about. Only a single prefixed
 * line is trusted: "<label>: <domain>" where label contains "verified" and
 * not "not"/"unverified"/"pending" — anything else contributes no domains.
 */
const VERIFIED_LABEL_LINE_RE = /^([a-z0-9 ()/_-]*verified[a-z0-9 ()/_-]*):\s*(.+)$/i;

function extractDomainsFromText(raw: string): string[] {
  const out: string[] = [];
  for (const rawLine of raw.split(/[\n,]/)) {
    const line = rawLine.trim();
    const m = line.match(VERIFIED_LABEL_LINE_RE);
    if (!m) continue;
    const label = m[1].toLowerCase();
    if (/\bnot\b|unverified|pending/.test(label)) continue;
    const d = normalizeDomain(m[2]);
    if (d) out.push(d);
  }
  return out;
}

/**
 * Defensively extract a verified-domain list from an MCP `tools/call` result
 * payload. Accepts the JSON-RPC envelope or the bare result, `content` text
 * blocks carrying JSON, bare arrays, and objects with `domain` / `domains` /
 * `verified` / `verifiedDomains` keys. Returns [] for anything unrecognized —
 * fail closed.
 */
export function parseVerifiedDomains(payload: unknown): string[] {
  const found: string[] = [];
  const visit = (node: unknown): void => {
    if (typeof node === "string") {
      const t = node.trim();
      if (!t) return;
      // A text block may itself be JSON (MCP tools commonly return JSON strings).
      if (t.startsWith("{") || t.startsWith("[")) {
        try {
          visit(JSON.parse(t));
          return;
        } catch {
          return; // not parseable JSON — not a domain either
        }
      }
      const d = normalizeDomain(t);
      if (d) {
        found.push(d);
        return;
      }
      // Whole string isn't a bare domain (e.g. it's a sentence) — look for
      // domain-shaped substrings instead of giving up.
      found.push(...extractDomainsFromText(t));
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) visit(item);
      return;
    }
    if (node && typeof node === "object") {
      const obj = node as Record<string, unknown>;
      // JSON-RPC envelope or MCP result wrapper.
      if ("result" in obj) visit(obj["result"]);
      const content = obj["content"];
      if (Array.isArray(content)) {
        for (const block of content) {
          if (block && typeof block === "object" && "text" in (block as Record<string, unknown>)) {
            visit((block as Record<string, unknown>)["text"]);
          } else {
            visit(block);
          }
        }
      }
      for (const key of ["domains", "verified", "verifiedDomains", "domain"]) {
        if (key in obj) visit(obj[key]);
      }
    }
  };
  visit(payload);
  return [...new Set(found)];
}

/** Exact (case-insensitive — lists are normalized) membership check. */
export function isDomainVerified(domain: string, verifiedList: readonly string[]): boolean {
  const d = normalizeDomain(domain);
  if (!d) return false;
  return verifiedList.includes(d);
}

/** Human-readable remediation: the server-owned verification flow. */
export function verificationInstructions(domain: string): string {
  const d = domain.toLowerCase();
  return (
    `To authorize active testing of ${d}:\n` +
    `1. Call the start_domain_verification tool for ${d} — the SecScan server ` +
    `issues a challenge token (${SERVER_TOKEN_PREFIX}…).\n` +
    `2. Publish it as a DNS TXT record at ${SERVER_CHALLENGE_PREFIX}.${d}.\n` +
    `3. Confirm with check_domain_verification (or see list_verified_domains).\n` +
    `Until the server lists the domain as verified, only passive reconnaissance ` +
    `is permitted.`
  );
}
