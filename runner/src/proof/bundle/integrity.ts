/**
 * Bundle provenance — an integrity digest the runner records when it
 * builds a PoC bundle, verified before reverify replays anything.
 *
 * Reverify executes the bundle's stored ssh/winrm/msf commands with
 * FRESH environment credentials. Without provenance, anyone who can
 * place a crafted `poc/*.json` (or get one committed/shared) and have an
 * operator run `reverify --execute` gets arbitrary commands run on the
 * in-scope hosts. So every runner-built bundle carries a sha256 digest
 * over its canonical form, and `reverifyBundle` refuses — before firing
 * a single step — when the digest is missing or does not match.
 *
 * Honest scope: there is no signing/secret facility in this codebase to
 * key the digest with, so this proves INTEGRITY (the bundle is bit-for-bit
 * what the runner recorded; any one-byte edit is detected), not
 * authenticity against an author who recomputes the digest after
 * rewriting the bundle. That residual is accepted deliberately (audit
 * T10): the bar is tamper detection, not HMAC ceremony.
 */

import { createHash } from "node:crypto";
import type { PocBundle } from "./bundle.js";

export interface BundleIntegrity {
  algorithm: "sha256";
  /** sha256 (hex) over the canonical bundle JSON, this field excluded. */
  digest: string;
}

/**
 * Canonical JSON: object keys sorted recursively, `undefined` properties
 * dropped (matching JSON.stringify semantics), array order preserved.
 * Stable across a JSON.stringify → JSON.parse round trip, so a bundle
 * verified from disk digests identically to the in-memory original.
 */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  }
  const rec = value as Record<string, unknown>;
  const keys = Object.keys(rec)
    .filter((k) => rec[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(rec[k])}`).join(",")}}`;
}

/** sha256 (hex) of the bundle's canonical form, integrity field excluded. */
export function computeBundleDigest(bundle: PocBundle): string {
  const { integrity: _excluded, ...unsigned } = bundle;
  return createHash("sha256").update(canonicalJson(unsigned), "utf8").digest("hex");
}

/** Record the digest on a bundle the runner just built. Mutates; returns the bundle. */
export function stampBundleIntegrity(bundle: PocBundle): PocBundle {
  bundle.integrity = { algorithm: "sha256", digest: computeBundleDigest(bundle) };
  return bundle;
}

/**
 * null when the bundle is bit-for-bit what the runner recorded; otherwise
 * the refusal reason. FAIL CLOSED: no digest = no provenance = no replay.
 */
export function verifyBundleIntegrity(bundle: PocBundle): string | null {
  const recorded = bundle.integrity;
  if (
    !recorded ||
    recorded.algorithm !== "sha256" ||
    typeof recorded.digest !== "string" ||
    !/^[0-9a-f]{64}$/.test(recorded.digest)
  ) {
    return "bundle provenance check failed: no runner-recorded integrity digest — the bundle's origin cannot be established";
  }
  const computed = computeBundleDigest(bundle);
  if (computed !== recorded.digest) {
    return (
      `bundle provenance check failed: integrity digest mismatch (recorded sha256:${recorded.digest.slice(0, 12)}…, ` +
      `computed sha256:${computed.slice(0, 12)}…) — the bundle was modified after the runner recorded it`
    );
  }
  return null;
}
