/**
 * Recon → module mapping: detected service/version → candidate Metasploit
 * modules.
 *
 * The mapping is deliberately thin: msfrpcd's own `module.search` does the
 * real matching (it knows all ~2,000 exploits). This module builds honest
 * search queries from recon evidence and ranks/filters the results —
 * dropping policy-denied modules BEFORE the agent ever sees them, so a
 * denied module can never be proposed, let alone run.
 *
 * Pure functions (query building, ranking) are unit-tested; the search
 * itself goes through MsfClient.
 */

import { checkMsfModule, msfRankWeight } from "./policy.js";
import type { MsfClient, MsfModule } from "./client.js";

export const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/i;

/** Extract CVE identifiers from arbitrary recon text (banner, version string). */
export function extractCves(text: string): string[] {
  const out = new Set<string>();
  const re = new RegExp(CVE_RE.source, "gi");
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) out.add(m[0].toUpperCase());
  return [...out];
}

export interface SuggestInput {
  /** Service name from the banner, e.g. "smb", "http", "ssh", "rdp", "ftp". */
  service?: string;
  /** Version string from the banner, e.g. "Samba 4.3.11", "OpenSSH 7.2p2". */
  version?: string;
  /** Explicit CVE when recon already identified one. */
  cve?: string;
  /** "windows" | "linux" — narrows platform. */
  platform?: string;
}

/** Small alias table so banner spellings map to msf search terms. */
const SERVICE_ALIASES: Record<string, string> = {
  smb: "smb",
  samba: "smb",
  "microsoft-ds": "smb",
  http: "http",
  https: "http",
  www: "http",
  ssh: "ssh",
  openssh: "ssh",
  rdp: "rdp",
  "ms-wbt-server": "rdp",
  ftp: "ftp",
  vsftpd: "ftp",
  proftpd: "ftp",
  telnet: "telnet",
  smtp: "smtp",
  dns: "dns",
  ldap: "ldap",
  nfs: "nfs",
  mssql: "mssql",
  mysql: "mysql",
  postgres: "postgres",
  postgresql: "postgres",
  redis: "redis",
  mongodb: "mongodb",
  elasticsearch: "elasticsearch",
};

function normalizeService(service: string): string {
  const s = service.trim().toLowerCase().replace(/[^a-z0-9-]/g, "");
  return SERVICE_ALIASES[s] ?? s;
}

/**
 * Build msf search queries, most-specific first. A CVE query is exact;
 * a service query is a candidate list the coordinator triages.
 */
export function buildModuleQueries(input: SuggestInput): string[] {
  const queries: string[] = [];
  const cves = [...extractCves(`${input.cve ?? ""} ${input.version ?? ""}`)];
  const platform = input.platform ? ` platform:${input.platform}` : "";
  for (const cve of cves) {
    queries.push(`type:exploit cve:${cve}${platform}`);
  }
  if (input.service) {
    const svc = normalizeService(input.service);
    if (svc) queries.push(`type:exploit${platform} ${svc}`);
    if (svc) queries.push(`type:auxiliary${platform} ${svc}`);
  }
  if (queries.length === 0 && input.version) {
    queries.push(`type:exploit${platform} ${input.version.trim().slice(0, 60)}`);
  }
  return queries;
}

export interface RankedModule extends MsfModule {
  weight: number;
  /** Why this module was dropped (policy) — present only on dropped entries. */
  dropped?: string;
}

/**
 * Filter (policy first) and rank modules. Denied modules are returned with
 * `dropped` set so the agent sees they were considered and refused — never
 * silently hidden, never runnable.
 */
export function filterAndRank(modules: MsfModule[]): RankedModule[] {
  return modules
    .map((m) => {
      const denied = checkMsfModule(m.fullname, m.type);
      return { ...m, weight: msfRankWeight(m.rank), dropped: denied ?? undefined };
    })
    .sort((a, b) => b.weight - a.weight || a.fullname.localeCompare(b.fullname));
}

/** Run the query chain and return ranked candidates (cap 25 — triage, not dump). */
export async function suggestModules(client: MsfClient, input: SuggestInput): Promise<RankedModule[]> {
  const seen = new Set<string>();
  const out: RankedModule[] = [];
  for (const q of buildModuleQueries(input)) {
    const mods = await client.searchModules(q);
    for (const m of filterAndRank(mods)) {
      if (seen.has(m.fullname)) continue;
      seen.add(m.fullname);
      out.push(m);
      if (out.length >= 25) return out;
    }
    if (out.length > 0 && q.includes("cve:")) break; // exact CVE hit — no need for fuzzy queries
  }
  return out;
}
