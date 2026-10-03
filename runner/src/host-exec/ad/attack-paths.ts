import type { AdEntry } from "./transport.js";
import { parseSid } from "./security.js";

export interface GraphNode {
  dn: string;
  name: string;
  kind: "user" | "group" | "computer";
  sid: string;
}

export function sidOf(e: AdEntry): string {
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
