/**
 * LDAP-based Active Directory enumeration — batteries WS-038 (BloodHound-style
 * attack-path analysis) and WS-043 (AD CS misconfiguration) — v0.10.0.
 *
 * LIBRARY CHOICE: `ldapts` (v9, actively maintained, TypeScript-native) —
 * the professional successor to the unmaintained ldapjs. Simple bind as the
 * authorized test account; every query is a READ. Nothing is written to the
 * directory, ever.
 *
 * SharpHound-equivalent dataset collected read-only:
 *   users (SPNs, account flags), groups (+ ranged member retrieval for large
 *   groups), computers (delegation flags), trusts, OUs (+ gPLink), GPOs,
 *   and nTSecurityDescriptors parsed from BINARY form (see parseSecurityDescriptor
 *   — no Windows API needed) to find dangerous grants (GenericAll, WriteDacl,
 *   WriteOwner) held by non-Tier-0 principals.
 *
 * Attack paths (WS-038) are COMPUTED OFFLINE on the collected graph —
 * shortest paths to Tier-0 via group nesting, dangerous ACL grants, and
 * delegation edges. No path is executed, no session hijacked, no edge
 * traversed against live systems.
 *
 * AD CS (WS-043) is DETECTION ONLY via LDAP: certificate template objects
 * carry every flag needed to identify ESC1/ESC2/ESC4-style misconfigurations.
 * No certificate is ever requested or enrolled.
 */

import { Client as LdapClient, escapeFilter } from "ldapts";
import {
  HOST_EXEC_TIMEOUT_MS,
  collectSecrets,
  redactSecrets,
  type HostCredentials,
} from "./common.js";

// ---------------------------------------------------------------------------
// Transport (injectable for tests)
// ---------------------------------------------------------------------------

export interface AdEntry {
  dn: string;
  attrs: Record<string, string[]>;
}

export interface AdTransport {
  connect(url: string): Promise<void>;
  bind(dn: string, password: string): Promise<void>;
  /** Search returning normalized entries (attribute names as returned by the server). */
  search(base: string, filter: string, attributes: string[], sizeLimit?: number): Promise<AdEntry[]>;
  /** Raw attribute names as returned (for ranged-retrieval markers). */
  searchRaw(base: string, filter: string, attributes: string[], sizeLimit?: number): Promise<{ dn: string; attrs: Record<string, string[]> }[]>;
  close(): Promise<void>;
}

function normalizeEntry(dn: string, raw: Record<string, unknown>): AdEntry {
  const attrs: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (k === "dn") continue;
    const vals = Array.isArray(v) ? v : [v];
    attrs[k] = vals.map((x) => (Buffer.isBuffer(x) ? (x as Buffer).toString("base64") : String(x)));
  }
  return { dn, attrs };
}

export function createAdTransport(): AdTransport {
  let client: LdapClient | undefined;
  const api: AdTransport = {
    async connect(url) {
      client = new LdapClient({ url, timeout: HOST_EXEC_TIMEOUT_MS, connectTimeout: HOST_EXEC_TIMEOUT_MS });
    },
    async bind(dn, password) {
      if (!client) throw new Error("[ad] not connected");
      await client.bind(dn, password);
    },
    async search(base, filter, attributes, sizeLimit = 2000) {
      const raw = await api.searchRaw(base, filter, attributes, sizeLimit);
      return raw.map((e) => normalizeEntry(e.dn, e.attrs));
    },
    async searchRaw(base, filter, attributes, sizeLimit = 2000) {
      if (!client) throw new Error("[ad] not connected");
      const res = await client.search(base, {
        scope: "sub",
        filter,
        attributes,
        sizeLimit,
        timeLimit: 30,
        paged: false,
      });
      return res.searchEntries.map((e) => {
        const attrs: Record<string, string[]> = {};
        for (const [k, v] of Object.entries(e)) {
          if (k === "dn") continue;
          const vals = Array.isArray(v) ? v : [v];
          attrs[k] = vals.map((x) => (Buffer.isBuffer(x) ? (x as Buffer).toString("base64") : String(x)));
        }
        return { dn: e.dn, attrs };
      });
    },
    async close() {
      try {
        await client?.unbind();
      } catch {
        /* best effort */
      }
      client = undefined;
    },
  };
  return api;
}

// ---------------------------------------------------------------------------
// Binary security descriptor parsing (no Windows API needed)
// ---------------------------------------------------------------------------

const RIGHT_GENERIC_ALL = 0x10000000;
const RIGHT_WRITE_DAC = 0x00040000;
const RIGHT_WRITE_OWNER = 0x00080000;
const RIGHT_ENROLL = 0x00000100; // CERTDB enroll extended-right mask bit used in template ACE scans
const ACE_ACCESS_ALLOWED = 0x00;

export interface DangerousAce {
  targetDn: string;
  granteeSid: string;
  rights: string[];
  mask: number;
}

function parseSid(buf: Buffer, offset: number): { sid: string; next: number } {
  const rev = buf[offset];
  const count = buf[offset + 1];
  const auth = buf.readUIntBE(offset + 2, 6); // 48-bit identifier authority, big-endian
  const parts: number[] = [];
  for (let i = 0; i < count; i++) parts.push(buf.readUInt32LE(offset + 8 + i * 4));
  return { sid: `S-${rev}-${auth}-${parts.join("-")}`, next: offset + 8 + count * 4 };
}

/**
 * Parse a BINARY security descriptor (base64) and return ACEs granting
 * dangerous rights. Pure function — tested directly.
 */
export function findDangerousAces(dn: string, sdB64: string): DangerousAce[] {
  const out: DangerousAce[] = [];
  let sd: Buffer;
  try {
    sd = Buffer.from(sdB64, "base64");
  } catch {
    return out;
  }
  if (sd.length < 20) return out;
  const daclOff = sd.readUInt32LE(16);
  if (daclOff === 0 || daclOff + 8 > sd.length) return out;
  const aceCount = sd.readUInt16LE(daclOff + 2);
  let p = daclOff + 8;
  for (let i = 0; i < aceCount && p + 8 <= sd.length; i++) {
    const type = sd[p];
    const size = sd.readUInt16LE(p + 2);
    if (size < 8 || p + size > sd.length) break;
    if (type === ACE_ACCESS_ALLOWED) {
      const mask = sd.readUInt32LE(p + 4);
      const rights: string[] = [];
      if (mask & RIGHT_GENERIC_ALL) rights.push("GenericAll");
      if (mask & RIGHT_WRITE_DAC) rights.push("WriteDacl");
      if (mask & RIGHT_WRITE_OWNER) rights.push("WriteOwner");
      if (mask & RIGHT_ENROLL) rights.push("Enroll");
      if (rights.length > 0) {
        const { sid } = parseSid(sd, p + 8);
        out.push({ targetDn: dn, granteeSid: sid, rights, mask });
      }
    }
    p += size;
  }
  return out;
}

/** Well-known low-privilege SIDs that must never hold dangerous rights. */
export function isLowPrivSid(sid: string, domainSid: string): boolean {
  const low = [
    "S-1-1-0", // Everyone
    "S-1-5-11", // Authenticated Users
    `${domainSid}-513`, // Domain Users
    `${domainSid}-515`, // Domain Computers
  ];
  return low.includes(sid);
}

/** Tier-0 SIDs: never flagged as findings when they hold dangerous rights. */
export function isTier0Sid(sid: string, domainSid: string): boolean {
  if (sid === "S-1-5-18" || sid === "S-1-5-19" || sid === "S-1-5-20") return true; // SYSTEM / LocalService / NetworkService
  for (const rid of ["-500", "-512", "-518", "-519", "-520"]) {
    if (sid === `${domainSid}${rid}`) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// AD enumeration
// ---------------------------------------------------------------------------

export type AdOperation =
  | "users"
  | "groups"
  | "computers"
  | "trusts"
  | "ous"
  | "gpos"
  | "acls"
  | "attack_paths"
  | "adcs";

export interface AdEnumArgs {
  host: string;
  port?: number;
  useTls?: boolean;
  baseDn?: string;
  creds: HostCredentials;
  operations: AdOperation[];
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface AdEnumResult {
  ok: boolean;
  baseDn?: string;
  /** Per-operation summaries (redacted, capped by the executor). */
  sections: { operation: AdOperation; summary: string; findingCount: number }[];
  note: string;
}

const USER_ATTRS = ["sAMAccountName", "userPrincipalName", "servicePrincipalName", "userAccountControl", "pwdLastSet", "lastLogon", "memberOf", "adminCount", "objectSid"];
const GROUP_ATTRS = ["sAMAccountName", "groupType", "member", "objectSid"];
const COMPUTER_ATTRS = ["sAMAccountName", "dNSHostName", "userAccountControl", "msDS-AllowedToDelegateTo", "objectSid"];
const TRUST_ATTRS = ["cn", "trustDirection", "trustType", "trustAttributes"];
const OU_ATTRS = ["ou", "gPLink"];
const GPO_ATTRS = ["cn", "displayName"];
const TEMPLATE_ATTRS = [
  "cn",
  "msPKI-Certificate-Name-Flag",
  "msPKI-Enrollment-Flag",
  "msPKI-Private-Key-Flag",
  "pKIExtendedKeyUsage",
  "nTSecurityDescriptor",
];

/** Ranged retrieval for large multi-valued attributes (e.g. member). */
async function getRangedValues(
  t: AdTransport,
  base: string,
  dn: string,
  attrBase: string,
  otherAttrs: string[],
): Promise<string[]> {
  const out: string[] = [];
  let begin = 0;
  for (;;) {
    const attr = `${attrBase};range=${begin}-*`;
    const res = await t.searchRaw(base, escapeFilter`(distinguishedName=${dn})`, [attr, ...otherAttrs], 2);
    if (res.length === 0) break;
    const entry = res[0].attrs;
    const key = Object.keys(entry).find((k) => k.toLowerCase().startsWith(`${attrBase};range=`));
    if (!key) break;
    out.push(...entry[key]);
    const m = /range=\d+-(\d+|\*)$/.exec(key);
    if (!m || m[1] === "*") break;
    begin = parseInt(m[1], 10) + 1;
    if (begin > 100_000) break; // sanity bound
  }
  return out;
}

interface GraphNode {
  dn: string;
  name: string;
  kind: "user" | "group" | "computer";
  sid: string;
}

function sidOf(e: AdEntry): string {
  // objectSid comes back base64 (binary). Tests use the fake transport with
  // plain-text SIDs — accept both.
  const v = e.attrs["objectSid"]?.[0] ?? "";
  if (/^S-1-/.test(v)) return v;
  try {
    const b = Buffer.from(v, "base64");
    if (b.length < 8) return "";
    const { sid } = parseSid(b, 0);
    return sid;
  } catch {
    return "";
  }
}

/**
 * Compute shortest privilege paths to Tier-0 on the collected graph.
 * Edges: member->group, group->parent group, dangerous-ACL grant, delegation.
 * BFS runs BACKWARD from Tier-0 over reversed edges; dist[n] = hops to Tier-0.
 * Pure function over collected data — tested directly. COMPUTED ONLY.
 */
export function computeAttackPaths(
  nodes: GraphNode[],
  edges: { from: string; to: string; via: string }[],
  tier0Dns: Set<string>,
): { path: string[]; via: string[] }[] {
  const rev = new Map<string, { from: string; via: string }[]>();
  for (const e of edges) {
    const l = rev.get(e.to) ?? [];
    l.push({ from: e.from, via: e.via });
    rev.set(e.to, l);
  }
  const dist = new Map<string, number>();
  const prev = new Map<string, { from: string; via: string }>();
  const queue: string[] = [];
  for (const t of tier0Dns) {
    dist.set(t, 0);
    queue.push(t);
  }
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const r of rev.get(cur) ?? []) {
      if (!dist.has(r.from)) {
        dist.set(r.from, dist.get(cur)! + 1);
        prev.set(r.from, { from: cur, via: r.via });
        queue.push(r.from);
      }
    }
  }
  const nameOf = new Map(nodes.map((n) => [n.dn.toLowerCase(), n.name]));
  const paths: { path: string[]; via: string[] }[] = [];
  for (const [dn, d] of dist) {
    if (d === 0 || d > 3) continue;
    const path = [nameOf.get(dn.toLowerCase()) ?? dn];
    const via: string[] = [];
    let cur = dn;
    while (prev.has(cur)) {
      const p = prev.get(cur)!;
      via.push(p.via);
      cur = p.from;
      path.push(nameOf.get(cur.toLowerCase()) ?? cur);
    }
    paths.push({ path, via });
  }
  paths.sort((a, b) => a.path.length - b.path.length);
  return paths.slice(0, 25);
}

// AD CS constants (MS-CSRA)
const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
const EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
const EKU_ANY_PURPOSE = "2.5.29.37.0";

export interface AdcsTemplateFinding {
  template: string;
  esc: "ESC1" | "ESC2" | "ESC4";
  detail: string;
}

/** Flag ESC1/ESC2/ESC4-style misconfigurations on one template entry. Pure function. */
export function analyzeTemplate(e: AdEntry, domainSid: string): AdcsTemplateFinding[] {
  const out: AdcsTemplateFinding[] = [];
  const cn = e.attrs["cn"]?.[0] ?? e.dn;
  const nameFlag = parseInt(e.attrs["msPKI-Certificate-Name-Flag"]?.[0] ?? "0", 10) || 0;
  const ekus = e.attrs["pKIExtendedKeyUsage"] ?? [];
  const hasClientAuth = ekus.includes(EKU_CLIENT_AUTH);
  const hasAnyPurpose = ekus.includes(EKU_ANY_PURPOSE);
  const sdB64 = e.attrs["nTSecurityDescriptor"]?.[0] ?? "";
  const aces = sdB64 ? findDangerousAces(e.dn, sdB64) : [];
  const lowPrivEnroll = aces.some(
    (a) => isLowPrivSid(a.granteeSid, domainSid) && (a.rights.includes("Enroll") || a.rights.includes("GenericAll")),
  );
  const lowPrivWrite = aces.some(
    (a) => isLowPrivSid(a.granteeSid, domainSid) && (a.rights.includes("WriteDacl") || a.rights.includes("WriteOwner") || a.rights.includes("GenericAll")),
  );
  if (nameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT && hasClientAuth && lowPrivEnroll) {
    out.push({
      template: cn,
      esc: "ESC1",
      detail: "ENROLLEE_SUPPLIES_SUBJECT + Client Authentication EKU + low-privilege enrollment — arbitrary SAN impersonation path.",
    });
  }
  if (hasAnyPurpose && lowPrivEnroll) {
    out.push({
      template: cn,
      esc: "ESC2",
      detail: "Any Purpose EKU + low-privilege enrollment — certificate usable as any EKU including client auth.",
    });
  }
  if (lowPrivWrite) {
    out.push({
      template: cn,
      esc: "ESC4",
      detail: "Low-privilege principal holds WriteDacl/WriteOwner/GenericAll on the template — template reconfiguration path.",
    });
  }
  return out;
}

export async function adEnumerate(transport: AdTransport, args: AdEnumArgs): Promise<AdEnumResult> {
  const port = args.port ?? (args.useTls ? 636 : 389);
  const scheme = args.useTls ? "ldaps" : "ldap";
  const url = `${scheme}://${args.host}:${port}`;
  const secrets = collectSecrets(args.creds);
  const redact = (s: string) => redactSecrets(s, secrets);
  const sections: AdEnumResult["sections"] = [];
  const push = (operation: AdOperation, summary: string, findingCount: number) =>
    sections.push({ operation, summary: redact(summary), findingCount });

  try {
    if (args.signal?.aborted) throw new Error("[ad] aborted by kill switch");
    await transport.connect(url);
    const bindDn = args.creds.domain ? `${args.creds.domain}\\${args.creds.username}` : args.creds.username;
    if (!args.creds.password) throw new Error("[ad] LDAP simple bind needs REDTEAM_SMB_PASSWORD (test account password)");
    await transport.bind(bindDn, args.creds.password);

    // Discover naming contexts when the operator didn't supply a base DN.
    let baseDn = args.baseDn;
    let configNc = "";
    let domainSid = "";
    if (!baseDn || args.operations.includes("adcs")) {
      const root = await transport.search("", "(objectClass=*)", ["defaultNamingContext", "configurationNamingContext"], 1);
      baseDn = baseDn ?? root[0]?.attrs["defaultNamingContext"]?.[0];
      configNc = root[0]?.attrs["configurationNamingContext"]?.[0] ?? "";
      if (!baseDn) throw new Error("[ad] could not discover defaultNamingContext from RootDSE");
      // Domain SID for Tier-0/low-priv SID comparisons.
      const dom = await transport.search(baseDn, "(objectClass=domain)", ["objectSid"], 1);
      domainSid = sidOf(dom[0]);
    }

    const ops = new Set(args.operations);
    const wantEnum = ops.has("users") || ops.has("groups") || ops.has("computers") || ops.has("acls") || ops.has("attack_paths");
    let users: AdEntry[] = [];
    let groups: AdEntry[] = [];
    let computers: AdEntry[] = [];
    const nodes: GraphNode[] = [];
    const edges: { from: string; to: string; via: string }[] = [];
    const dnOf = (sid: string, pool: AdEntry[]): string => pool.find((e) => sidOf(e) === sid)?.dn ?? sid;

    if (wantEnum) {
      if (ops.has("users") || ops.has("attack_paths") || ops.has("acls")) {
        users = await transport.search(baseDn!, "(objectClass=user)", USER_ATTRS);
        push("users", `Enumerated ${users.length} user objects (SPNs, account flags, hygiene attributes).`, users.length);
      }
      if (ops.has("groups") || ops.has("attack_paths")) {
        groups = await transport.search(baseDn!, "(objectClass=group)", GROUP_ATTRS);
        // Ranged member retrieval for large groups (AD caps plain reads).
        for (const g of groups) {
          const members = g.attrs["member"] ?? [];
          if (members.length >= 1500) {
            g.attrs["member"] = await getRangedValues(transport, baseDn!, g.dn, "member", ["objectSid"]);
          }
        }
        push("groups", `Enumerated ${groups.length} groups (ranged member retrieval for large groups).`, groups.length);
      }
      if (ops.has("computers") || ops.has("attack_paths")) {
        computers = await transport.search(baseDn!, "(objectClass=computer)", COMPUTER_ATTRS);
        const deleg = computers.filter((c) => {
          const uac = parseInt(c.attrs["userAccountControl"]?.[0] ?? "0", 10) || 0;
          return uac & 0x80000 || uac & 0x1000000 || (c.attrs["msDS-AllowedToDelegateTo"]?.length ?? 0) > 0;
        });
        push(
          "computers",
          `Enumerated ${computers.length} computers; ${deleg.length} carry delegation flags (unconstrained/constrained/resource-based).`,
          deleg.length,
        );
      }

      // Build the graph for attack-path computation.
      const all: AdEntry[] = [...users, ...groups, ...computers];
      const sidToDn = new Map(all.map((e) => [sidOf(e), e.dn]));
      for (const e of all) {
        const kind: GraphNode["kind"] = e.attrs["servicePrincipalName"] !== undefined || users.includes(e) ? "user" : groups.includes(e) ? "group" : "computer";
        const sid = sidOf(e);
        nodes.push({ dn: e.dn, name: e.attrs["sAMAccountName"]?.[0] ?? e.dn, kind, sid });
        for (const m of e.attrs["memberOf"] ?? []) edges.push({ from: e.dn, to: m, via: "memberOf" });
      }
      for (const g of groups) {
        for (const m of g.attrs["member"] ?? []) {
          // member values are DNs in real LDAP; the fake transport may use SIDs.
          const from = m.startsWith("S-1-") ? (sidToDn.get(m) ?? m) : m;
          edges.push({ from, to: g.dn, via: "member" });
        }
      }
      if (ops.has("acls") || ops.has("attack_paths")) {
        const aclTargets = [...users, ...groups, ...computers];
        let dangerous = 0;
        for (const e of aclTargets) {
          const sdB64 = e.attrs["nTSecurityDescriptor"]?.[0];
          if (!sdB64) continue;
          for (const ace of findDangerousAces(e.dn, sdB64)) {
            if (isTier0Sid(ace.granteeSid, domainSid)) continue;
            dangerous++;
            const from = dnOf(ace.granteeSid, all);
            edges.push({ from, to: e.dn, via: `ACL:${ace.rights.join("+")}` });
          }
        }
        push("acls", `Parsed DACLs on ${aclTargets.length} objects; ${dangerous} dangerous grants held by non-Tier-0 principals.`, dangerous);
      }
      if (ops.has("attack_paths")) {
        const tier0 = new Set(
          nodes.filter((n) => isTier0Sid(n.sid, domainSid) && n.sid).map((n) => n.dn),
        );
        const paths = computeAttackPaths(nodes, edges, tier0);
        const rendered = paths
          .map((p) => `${p.path.join(" -> ")}  [${p.via.join(" | ")}]`)
          .join("\n");
        push(
          "attack_paths",
          `Shortest privilege paths to Tier-0 (computed offline, max 3 hops, ${paths.length} shown):\n${rendered || "(no short paths found)"}\nCOMPUTED ONLY — no path was executed against live systems.`,
          paths.length,
        );
      }
    }

    if (ops.has("trusts")) {
      const trusts = await transport.search(baseDn!, "(objectClass=trustedDomain)", TRUST_ATTRS);
      push(
        "trusts",
        `Enumerated ${trusts.length} trusts: ${trusts.map((t) => `${t.attrs["cn"]?.[0]} (dir=${t.attrs["trustDirection"]?.[0]}, attrs=${t.attrs["trustAttributes"]?.[0]})`).join("; ") || "(none)"}.`,
        trusts.length,
      );
    }
    if (ops.has("ous")) {
      const ous = await transport.search(baseDn!, "(objectClass=organizationalUnit)", OU_ATTRS);
      const linked = ous.filter((o) => (o.attrs["gPLink"]?.[0] ?? "").length > 0);
      push("ous", `Enumerated ${ous.length} OUs; ${linked.length} carry GPO links.`, linked.length);
    }
    if (ops.has("gpos")) {
      const gpos = configNc
        ? await transport.search(`CN=Policies,CN=System,${baseDn}`, "(objectClass=groupPolicyContainer)", GPO_ATTRS)
        : [];
      push("gpos", `Enumerated ${gpos.length} Group Policy objects.`, gpos.length);
    }
    if (ops.has("adcs")) {
      if (!configNc) throw new Error("[ad] configurationNamingContext unknown — cannot locate certificate templates");
      const templates = await transport.search(
        `CN=Certificate Templates,CN=Public Key Services,CN=Services,${configNc}`,
        "(objectClass=pKICertificateTemplate)",
        TEMPLATE_ATTRS,
      );
      const findings = templates.flatMap((t) => analyzeTemplate(t, domainSid));
      push(
        "adcs",
        `Audited ${templates.length} certificate templates (DETECTION ONLY — no certificate requested or enrolled). ` +
          `ESC-style findings: ${findings.length}\n${findings.map((f) => `${f.esc} on "${f.template}": ${f.detail}`).join("\n") || "(none)"}`,
        findings.length,
      );
    }

    return { ok: true, baseDn, sections, note: "Read-only LDAP enumeration as the authorized test account; nothing was written to the directory." };
  } finally {
    await transport.close().catch(() => undefined);
  }
}
