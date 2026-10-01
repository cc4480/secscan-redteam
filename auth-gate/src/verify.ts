/**
 * Domain-ownership verification — the legal backbone of the red-team.
 *
 * Mirrors the proven mechanism in cc4480/OPEN_SECLAYER (server/domainVerify.ts):
 * the engagement issues a token; the client proves control of the domain by
 * publishing it as a DNS TXT record at `_seclayer-challenge.<domain>` (or by
 * serving it from `/.well-known/seclayer-verification.txt`).
 *
 * This module is deliberately dependency-free (node:dns/promises only) and
 * fails closed: any DNS error, timeout, or mismatch returns false. It never
 * throws for "not verified" — false IS the answer.
 */

import crypto from "node:crypto";
import dns from "node:dns/promises";

export const TXT_RECORD_PREFIX = "_seclayer-challenge";
export const WELL_KNOWN_PATH = "/.well-known/seclayer-verification.txt";
const DNS_TIMEOUT_MS = 8000;

/** Normalize a raw URL or bare domain to a lowercase hostname. */
export function extractDomain(rawUrl: string): string {
  let u = (rawUrl || "").trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return new URL(u).hostname.toLowerCase();
}

/** The TXT record name checked for a domain, e.g. `_seclayer-challenge.example.com`. */
export function txtRecordName(domain: string): string {
  return `${TXT_RECORD_PREFIX}.${extractDomain(domain)}`;
}

/** Issue a fresh engagement token for the client to publish. */
export function generateEngagementToken(): string {
  return "sl-verify-" + crypto.randomBytes(16).toString("hex");
}

/**
 * Check the DNS TXT record for the token. Returns true only on an exact match.
 * Fails closed on NXDOMAIN, timeout, or any resolver error.
 */
export async function checkTxtRecord(domain: string, token: string): Promise<boolean> {
  if (!token) return false;
  const name = txtRecordName(domain);
  try {
    const records = await withTimeout(dns.resolveTxt(name), DNS_TIMEOUT_MS);
    return records.some((chunks) => chunks.join("").trim() === token);
  } catch {
    return false;
  }
}

export interface OwnershipProof {
  ok: boolean;
  domain: string;
  method: "dns-txt" | "none";
  checkedAt: string;
  /** Human-readable instructions shown when proof is missing. */
  instructions?: string;
}

/** Full verification pass for an engagement target. */
export async function verifyOwnership(
  rawTarget: string,
  token: string | undefined,
): Promise<OwnershipProof> {
  const domain = extractDomain(rawTarget);
  const checkedAt = new Date().toISOString();
  const ok = token ? await checkTxtRecord(domain, token) : false;
  return {
    ok,
    domain,
    method: ok ? "dns-txt" : "none",
    checkedAt,
    instructions: ok
      ? undefined
      : `To authorize active testing of ${domain}: add a DNS TXT record at ` +
        `${txtRecordName(domain)} containing your engagement token, or serve the token ` +
        `at https://${domain}${WELL_KNOWN_PATH}. Then re-run verification. ` +
        `Until then, only passive reconnaissance is permitted.`,
  };
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("dns timeout")), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
