/**
 * DNS + pinned transport for the web prober (audit 2026-10-09, security #5).
 * The prober used to vet only the hostname STRING before a plain fetch, so a
 * target-controlled DNS answer could point it at 169.254.169.254 or RFC1918
 * services — an SSRF pivot. Here every hostname is resolved first, EVERY
 * resolved address is classified, and the connection is pinned to exactly
 * the validated addresses (dns.lookup override): the checked address is the
 * connected address. Fail closed — any bad address refuses the whole name:
 * link-local is ALWAYS refused (metadata unreachable even in sandbox mode);
 * loopback/private needs explicit operator allowance; resolution errors and
 * empty answers refuse. TLS is not downgraded: SNI and cert validation still
 * use the original hostname, not the pinned IP.
 */
import { lookup as dnsLookup } from "node:dns";
import { Agent as HttpAgent, request as httpRequest } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";

export interface DnsAddress {
  address: string;
  family: 4 | 6;
}

/** Injectable resolver seam — tests inject fakes; production uses node:dns. */
export type DnsResolver = (hostname: string) => Promise<DnsAddress[]>;

/** System resolver (handles names, IP literals, /etc/hosts entries). */
export const defaultDnsResolver: DnsResolver = (hostname) =>
  new Promise((resolve, reject) => {
    dnsLookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err) reject(err);
      else
        resolve(
          (addresses as { address: string; family: number }[]).map((a) => ({
            address: a.address,
            family: a.family === 6 ? (6 as const) : (4 as const),
          })),
        );
    });
  });

export type IpClass = "public" | "loopback" | "private" | "link-local";

function classifyV4(octets: number[]): IpClass {
  const [a, b] = octets as [number, number, number, number];
  if (a === 127) return "loopback";
  if (a === 169 && b === 254) return "link-local";
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
  if (a === 0) return "private"; // 0.0.0.0/8 "this host" — never a public target
  if (a === 100 && b >= 64 && b <= 127) return "private"; // RFC 6598 CGNAT shared space
  return "public";
}

function parseV4(text: string): number[] | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  return octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) ? octets : null;
}

/** Expand an IPv6 address to 8 hextets, or null if unparseable. */
function expandV6(ip: string): number[] | null {
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const parseSide = (side: string): number[] | null => {
    if (side === "") return [];
    const out: number[] = [];
    for (const group of side.split(":")) {
      if (group.includes(".")) {
        const v4 = parseV4(group);
        if (!v4) return null;
        out.push((v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
        out.push(parseInt(group, 16));
      }
    }
    return out;
  };
  const left = parseSide(halves[0]!);
  const right = halves.length === 2 ? parseSide(halves[1]!) : [];
  if (left === null || right === null) return null;
  if (halves.length === 1) return left.length === 8 ? left : null;
  const missing = 8 - left.length - right.length;
  if (missing < 1) return null;
  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

export function classifyIpAddress(rawIp: string): IpClass {
  let ip = rawIp.trim().toLowerCase();
  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
  const v4 = parseV4(ip);
  if (v4) return classifyV4(v4);
  const h = expandV6(ip);
  if (!h) return "private"; // unparseable — fail closed, never treat as public
  // Embedded IPv4: ::ffff:a.b.c.d (v4-mapped) and 64:ff9b::/96 (NAT64) carry a
  // real v4 address in the last 32 bits — classify by the embedded address.
  const embedded =
    h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff
      ? [(h[6]! >> 8) & 0xff, h[6]! & 0xff, (h[7]! >> 8) & 0xff, h[7]! & 0xff]
      : h[0] === 0x64 && h[1] === 0xff9b && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0
        ? [(h[6]! >> 8) & 0xff, h[6]! & 0xff, (h[7]! >> 8) & 0xff, h[7]! & 0xff]
        : null;
  if (embedded) return classifyV4(embedded);
  if (h.every((x, i) => (i === 7 ? x === 1 : x === 0))) return "loopback"; // ::1
  if (h.every((x) => x === 0)) return "private"; // :: unspecified
  if ((h[0]! & 0xffc0) === 0xfe80) return "link-local"; // fe80::/10
  if ((h[0]! & 0xfe00) === 0xfc00) return "private"; // fc00::/7 unique-local
  return "public";
}

export interface ResolveCheckedOptions {
  /** LOCAL SANDBOX MODE ONLY — permits loopback/private resolutions. */
  allowPrivateHosts?: boolean;
  resolver?: DnsResolver;
}

/**
 * Resolve `hostname` and validate EVERY resulting address against policy.
 * IP literals skip DNS and are classified directly. Returns the validated
 * address set for pinned connections.
 */
export async function resolveCheckedAddresses(
  hostname: string,
  opts: ResolveCheckedOptions = {},
): Promise<{ ok: true; addresses: DnsAddress[] } | { ok: false; reason: string }> {
  const host = hostname.trim().toLowerCase().replace(/^\[|\]$/g, "");
  let addresses: DnsAddress[];
  const literal = isIP(host);
  if (literal !== 0) {
    addresses = [{ address: host, family: literal === 6 ? 6 : 4 }];
  } else {
    try {
      addresses = await (opts.resolver ?? defaultDnsResolver)(host);
    } catch (err) {
      return { ok: false, reason: `could not resolve ${host}: ${(err as Error).message}` };
    }
    if (!addresses || addresses.length === 0) {
      return { ok: false, reason: `could not resolve ${host}: no addresses returned` };
    }
  }
  for (const { address } of addresses) {
    const cls = classifyIpAddress(address);
    if (cls === "link-local") {
      return {
        ok: false,
        reason:
          `${host} resolves to link-local address ${address} — always refused ` +
          `(cloud metadata/link-local is never a legitimate target, even in sandbox mode)`,
      };
    }
    if (cls !== "public" && !opts.allowPrivateHosts) {
      return {
        ok: false,
        reason:
          `${host} resolves to ${cls} address ${address} — refused (SSRF pivot guard; ` +
          `private targets require local-sandbox mode)`,
      };
    }
  }
  return { ok: true, addresses };
}

/**
 * A dns.lookup replacement that can only ever yield `addresses` — the set
 * resolveCheckedAddresses already validated. The socket connects to the
 * checked addresses: no second resolution, no check/fetch TOCTOU window.
 */
export function makePinnedLookup(addresses: DnsAddress[]): LookupFunction {
  const pinned = addresses.map((a) => ({ address: a.address, family: a.family as number }));
  return ((_hostname: string, options: { all?: boolean }, callback: (...args: never[]) => void) => {
    const cb = callback as (
      err: NodeJS.ErrnoException | null,
      address?: string | { address: string; family: number }[],
      family?: number,
    ) => void;
    if (options && options.all) cb(null, pinned.map((p) => ({ ...p })));
    else cb(null, pinned[0]!.address, pinned[0]!.family);
  }) as unknown as LookupFunction;
}

export interface PinnedResponse {
  status: number;
  headers: Record<string, string>;
  text: string;
}

// One socket per request, closed after the response: the prober fires single
// requests minutes apart, and pooled keep-alive sockets go stale (and get
// poisoned when a burst read destroys one early) — fresh sockets are the
// reliable parity with fetch here.
const httpAgent = new HttpAgent({ keepAlive: false });
const httpsAgent = new HttpsAgent({ keepAlive: false });

/** Decompressed text is capped too: a 64 KiB gzip can expand ~1000x. */
const MAX_DECODED_BYTES = 64 * 1024;

function decodeBody(buf: Buffer, contentEncoding: string | undefined): string {
  const enc = (contentEncoding ?? "").toLowerCase();
  try {
    if (/\bgzip\b/.test(enc)) return gunzipSync(buf, { maxOutputLength: MAX_DECODED_BYTES }).toString("utf8");
    if (/\bdeflate\b/.test(enc)) return inflateSync(buf, { maxOutputLength: MAX_DECODED_BYTES }).toString("utf8");
    if (/\bbr\b/.test(enc)) return brotliDecompressSync(buf, { maxOutputLength: MAX_DECODED_BYTES }).toString("utf8");
  } catch {
    // Undecodable or over-cap body — fall through to the raw bytes, never throw.
  }
  return buf.toString("utf8");
}

/**
 * One HTTP(S) request to `url`, connected to the pre-validated `addresses`
 * (pinning via lookup override). Redirects are never followed here — the
 * caller inspects and validates Location targets itself. When `readBody` is
 * false the promise resolves as soon as headers arrive (burst probe).
 */
export function pinnedHttpRequest(
  url: string,
  init: {
    method: string;
    headers?: Record<string, string>;
    body?: string;
    addresses: DnsAddress[];
    signal?: AbortSignal;
    readBody?: boolean;
    /** Cap on buffered wire bytes; past it the response is cut short. */
    maxBodyBytes?: number;
  },
): Promise<PinnedResponse> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const isHttps = u.protocol === "https:";
    const bareHost = u.hostname.replace(/^\[|\]$/g, "");
    const headers: Record<string, string> = { ...(init.headers ?? {}), host: u.host };
    if (init.body !== undefined) headers["content-length"] = String(Buffer.byteLength(init.body, "utf8"));
    const req = (isHttps ? httpsRequest : httpRequest)(
      {
        protocol: u.protocol,
        hostname: bareHost,
        port: u.port ? Number(u.port) : isHttps ? 443 : 80,
        path: `${u.pathname}${u.search}`,
        method: init.method,
        headers,
        agent: isHttps ? httpsAgent : httpAgent,
        lookup: makePinnedLookup(init.addresses),
        servername: isHttps ? bareHost : undefined,
        auth: u.username ? `${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}` : undefined,
        signal: init.signal,
      },
      (res) => {
        const flat: Record<string, string> = {};
        for (const [key, val] of Object.entries(res.headers)) {
          if (val === undefined) continue;
          flat[key.toLowerCase()] = Array.isArray(val) ? val.join(", ") : val;
        }
        const status = res.statusCode ?? 0;
        if (init.readBody === false) {
          res.destroy();
          resolve({ status, headers: flat, text: "" });
          return;
        }
        // Cap buffered wire bytes (a hostile target must not make the runner
        // hold a huge body to return a 4 KB snippet): past maxBodyBytes keep
        // the in-cap prefix, destroy the stream, resolve with what was kept.
        const cap = init.maxBodyBytes ?? Number.POSITIVE_INFINITY;
        const chunks: Buffer[] = [];
        let kept = 0;
        let settled = false;
        const finish = () => {
          if (settled) return;
          settled = true;
          resolve({ status, headers: flat, text: decodeBody(Buffer.concat(chunks), flat["content-encoding"]) });
        };
        res.on("data", (chunk: Buffer) => {
          if (settled) return;
          if (kept + chunk.length > cap) {
            const room = Math.max(0, cap - kept);
            if (room > 0) chunks.push(chunk.subarray(0, room));
            kept = cap;
            finish();
            res.destroy();
            return;
          }
          chunks.push(chunk);
          kept += chunk.length;
        });
        res.on("end", finish);
        res.on("error", (err) => { if (!settled) reject(err); });
      },
    );
    req.on("error", (err) => reject(err));
    if (init.body !== undefined) req.write(init.body);
    req.end();
  });
}
