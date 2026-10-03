/**
 * THE REGISTRY — the product's compounding proprietary attack intelligence.
 *
 * Store: types, record/load/save, and the v0.3.x seed. Querying lives in
 * query.ts. (Module doc comment preserved on the registry.ts barrel.)
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export interface TargetFingerprint {
  host: string;
  /** e.g. ["react-spa", "cloudflare-edge", "bearer-rest-api"] */
  stack: string[];
  /** e.g. "security-scanner-saas", "ecommerce", "banking-portal" */
  appType: string;
  notes?: string;
}

interface RegistryEntryBase {
  id: string;
  date: string; // ISO
  engagementId: string;
  target: TargetFingerprint;
}

export interface ConfirmedFinding extends RegistryEntryBase {
  kind: "confirmed";
  vulnClass: string;
  technique: string;
  attackId?: string;
  owasp?: string;
  /** The payload/shape that proved it, generalized (no live secrets). */
  payloadPattern: string;
  /** Path to the evidence within the engagement dir. */
  evidenceRef: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

export interface KilledHypothesis extends RegistryEntryBase {
  kind: "killed";
  hypothesis: string;
  killingObservation: string;
  attackId?: string;
  vulnClass?: string;
}

export type RegistryEntry = ConfirmedFinding | KilledHypothesis;

export interface VulnerabilityRegistry {
  version: 1;
  confirmed: ConfirmedFinding[];
  killed: KilledHypothesis[];
}

export function emptyRegistry(): VulnerabilityRegistry {
  return { version: 1, confirmed: [], killed: [] };
}

export interface RegistryQuery {
  vulnClass?: string;
  /** Comma-separated stack hints, e.g. "react-spa,cloudflare-edge". */
  stack?: string;
  appType?: string;
  attackId?: string;
  kind?: "confirmed" | "killed";
  limit?: number;
}

function nextId(prefix: string, existing: number): string {
  return `${prefix}-${String(existing + 1).padStart(4, "0")}`;
}

export function recordConfirmed(
  reg: VulnerabilityRegistry,
  entry: Omit<ConfirmedFinding, "id" | "kind" | "date"> & { date?: string },
): ConfirmedFinding {
  const full: ConfirmedFinding = {
    kind: "confirmed",
    id: nextId("vuln", reg.confirmed.length),
    date: entry.date ?? new Date().toISOString(),
    ...entry,
  };
  reg.confirmed.push(full);
  return full;
}

export function recordKilled(
  reg: VulnerabilityRegistry,
  entry: Omit<KilledHypothesis, "id" | "kind" | "date"> & { date?: string },
): KilledHypothesis {
  const full: KilledHypothesis = {
    kind: "killed",
    id: nextId("killed", reg.killed.length),
    date: entry.date ?? new Date().toISOString(),
    ...entry,
  };
  reg.killed.push(full);
  return full;
}


export function loadRegistryFile(path: string): VulnerabilityRegistry | null {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as VulnerabilityRegistry;
    if (raw && raw.version === 1 && Array.isArray(raw.confirmed) && Array.isArray(raw.killed)) return raw;
    return null;
  } catch {
    return null;
  }
}

/** Persist the registry (creates parent dirs). Called after every verdict write-through and at engagement end. */
export function saveRegistryFile(path: string, reg: VulnerabilityRegistry): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(reg, null, 2));
}

/**
 * Atomic read-modify-write transaction on the registry file (v0.23.0).
 *
 * The whole transaction is synchronous start-to-finish, and synchronous code
 * in Node is never preempted — so within one process, two concurrent
 * engagements (e.g. two UI-launched runs) can never silently lose each
 * other's verdicts, the way a load-at-start / blind-save-at-verdict pattern
 * did. The mutator runs against the freshly-loaded file, so IDs and dedupe
 * checks always see current state.
 *
 * Known limitation: this guards one process. Two separate OS processes
 * writing the same registry file can still race — that remains the SQLite
 * migration trigger documented on the registry barrel.
 */
export function transactRegistryFile<T>(path: string, fn: (reg: VulnerabilityRegistry) => T): T {
  mkdirSync(dirname(path), { recursive: true });
  const reg = loadRegistryFile(path) ?? emptyRegistry();
  const out = fn(reg);
  writeFileSync(path, JSON.stringify(reg, null, 2));
  return out;
}

// ---------------------------------------------------------------------------
// Seed: the v0.3.x secscan.us engagement (2026-10-01). The registry is born
// with real, evidence-backed intelligence — 10 killed hypotheses and 4
// findings — so the very first live engagement already reasons from history.
// ---------------------------------------------------------------------------

const SEED_FP: TargetFingerprint = {
  host: "secscan.us",
  stack: ["react-spa", "cloudflare-edge", "bearer-rest-api"],
  appType: "security-scanner-saas",
  notes: "1.27MB JS bundle; /api/v1 bearer API + /api/* web namespace; SPA shell; Cloudflare edge",
};

const SEED_DATE = "2026-10-01T12:45:00.000Z";
const SEED_ENG = "secscan-us-2026-10-01";

export function seedRegistry(): VulnerabilityRegistry {
  const reg = emptyRegistry();
  const killed: Array<Omit<KilledHypothesis, "id" | "kind" | "date">> = [
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "Unauthenticated REST endpoints expose scan data (IDOR/status oracle)",
      killingObservation:
        "Unauth GET /api/v1/scans, /scans/{id}, /scans/{id}/report, /me → ALL uniform 401, byte-identical bodies. Only /api/v1/openapi.json is public (by design). No oracle.",
      attackId: "T1190",
      vulnClass: "IDOR / broken object-level authorization",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "Web-app /api/* namespace (from JS bundle) has ungated routes",
      killingObservation:
        "/api/auth/user → 200 {\"user\":null} (correct anonymous); /api/account/tokens, /domain-verifications, /scans, /monitor/subscriptions, /billing/status → uniform 401. Properly gated.",
      attackId: "T1190",
      vulnClass: "missing authorization",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "Direct /report/1 and /share/test URLs leak scan data",
      killingObservation:
        "Both return the generic ~9KB SPA shell (marketing copy only); zero scan IDs, grades, or tokens. Data loads via authenticated API. Cross-account object test deferred (needs 2nd account).",
      attackId: "T1190",
      vulnClass: "IDOR via direct URL",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "Host-header injection influences password-reset links (X-Forwarded-Host)",
      killingObservation:
        "GET /forgot-password with X-Forwarded-Host: evil-attacker.example → 200, zero reflections. Bare 'Host: evil.example' rejected at the edge (connection refused).",
      attackId: "T1190",
      vulnClass: "host-header injection",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "A live WebSocket/EventSource channel exists to attack",
      killingObservation:
        "Zero WebSocket/EventSource/socket.io references in the full 1.27MB bundle. No channel exists; permissive CSP ws:/wss: is config-only.",
      vulnClass: "websocket hijacking",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "robots.txt / sitemap hide undocumented routes",
      killingObservation:
        "5,984B robots.txt fully explained: 16 AI-bot user-agent groups repeating the Disallow list. sitemap.xml lists public pages only. No hidden route strings.",
      attackId: "T1595.003",
      vulnClass: "hidden endpoint discovery",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "Reflected input + style-src 'unsafe-inline' = live CSS/HTML injection",
      killingObservation:
        "4 canary probes (/?q=<style>oast7x</style>, /?search=\"><style>oast7x, /?name=';background:url(oast7x), /scan?url=oast7x) → all 200, ZERO reflections. Killed as a live vector; directive stays a latent LOW.",
      attackId: "T1190",
      vulnClass: "CSS injection",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "www.secscan.us hostname confusion / reflection",
      killingObservation: "GET https://www.secscan.us/ → clean 301 to https://secscan.us/, no hostname reflection.",
      vulnClass: "host confusion",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "Weak TLS posture (obsolete versions, bad chain)",
      killingObservation:
        "Live-edge handshake: TLS 1.3 / AES-256-GCM / ECDSA P-256, chain verifies. Modern and valid. (An early direct-connect 'TLS 1.3 fails' reading was discarded as a VM resolver artifact.)",
      attackId: "T1590.002",
      vulnClass: "TLS misconfiguration",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      hypothesis: "MCP scope gate bypass via percent-encoded path traversal (/api/mcp/%2e%2e/v1/scans)",
      killingObservation:
        "Traversal → 404 {\"error\":\"Not found\"} vs control /api/v1/scans → 401. Traversal normalized before the scope check; gate holds. Positive control for scope enforcement.",
      attackId: "T1190",
      vulnClass: "scope-confusion / path traversal",
    },
  ];
  for (const k of killed) recordKilled(reg, { ...k, date: SEED_DATE });

  const confirmed: Array<Omit<ConfirmedFinding, "id" | "kind" | "date">> = [
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      vulnClass: "CSP weak directive (latent XSS enabler)",
      technique: "CSS/HTML injection probing with canary markers",
      attackId: "T1190",
      owasp: "WSTG-CONF",
      payloadPattern: "?q=<style>oast7x</style> (+3 reflection-context variants); 0 reflections observed",
      evidenceRef: "engagements/evidence/aggressive-battery-2026-10-01.md (P7)",
      severity: "low",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      vulnClass: "DNSSEC not enabled",
      technique: "DNS posture review via DNS-over-HTTPS",
      attackId: "T1590.002",
      payloadPattern: "DoH DS + DNSKEY queries → NOERROR, no records, AD=false",
      evidenceRef: "engagements/evidence/aggressive-battery-2026-10-01.md (P9)",
      severity: "info",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      vulnClass: "Obsolete TLS protocol support (1.0/1.1)",
      technique: "SSL Labs assessment + handshake review",
      payloadPattern: "SSL Labs grade B, capped on TLS 1.0/1.1 (BEAST on TLS 1.0 CBC); live handshakes negotiate TLS 1.3 cleanly",
      evidenceRef: "engagements/evidence/scan-e78f4581-report.txt",
      severity: "info",
    },
    {
      engagementId: SEED_ENG,
      target: SEED_FP,
      vulnClass: "robots.txt disclosure (comment admits past misconfiguration)",
      technique: "Robots/sitemap review",
      payloadPattern: "5,984B robots.txt; comment references past AI-crawler access to dashboards/other users' reports (since fixed)",
      evidenceRef: "engagements/evidence/aggressive-battery-2026-10-01.md (P6)",
      severity: "info",
    },
  ];
  for (const c of confirmed) recordConfirmed(reg, { ...c, date: SEED_DATE });
  return reg;
}
