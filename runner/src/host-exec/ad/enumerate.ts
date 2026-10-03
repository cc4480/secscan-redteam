// ---------------------------------------------------------------------------
// AD enumeration
// ---------------------------------------------------------------------------

import { escapeFilter } from "ldapts";
import { collectSecrets, redactSecrets, type HostCredentials } from "../common.js";
import type { AdEntry, AdTransport } from "./transport.js";
import { findDangerousAces, isLowPrivSid, isTier0Sid } from "./security.js";
import { computeAttackPaths, sidOf, type GraphNode } from "./attack-paths.js";
import { analyzeTemplate } from "./adcs.js";

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
