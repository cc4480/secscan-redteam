/**
 * Web prober — the exploiter's hands.
 *
 * Every probe is a single HTTP(S) request against an in-scope host. Guardrails
 * are mechanical, not advisory:
 *  - only http/https URLs, only exact in-scope hostnames
 *  - literal private IPs / localhost are rejected (the runner must never be
 *    usable as an SSRF pivot against internal infrastructure)
 *  - request bodies capped at 64KB; 20s timeout; global rate limit
 *  - detection signals (WAF block, 429, CAPTCHA markers) are surfaced as
 *    OPSEC events so black mode can back off
 *
 * Non-destructive by construction: the prober sends single requests, never
 * floods, and the payload discipline lives in the exploiter prompt (no data
 * writes/deletes, no resource exhaustion).
 */

export interface ProbeRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface ProbeResult {
  status: number;
  headers: Record<string, string>;
  /** First 4KB of the response body. */
  bodySnippet: string;
  ms: number;
  /** Set when the response looks like a defender fired (WAF/rate-limit/CAPTCHA). */
  opsecSignal?: string;
}

const MAX_BODY_BYTES = 64 * 1024;
const PRIVATE_HOST =
  /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|\[::1\]|::1$)/i;

export function validateProbeTarget(url: string, scopeHosts: string[]): { ok: true } | { ok: false; reason: string } {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return { ok: false, reason: `unparseable URL: ${url}` };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, reason: `scheme not allowed: ${u.protocol}` };
  }
  const host = u.hostname.toLowerCase();
  if (PRIVATE_HOST.test(host)) {
    return { ok: false, reason: `private/loopback host rejected: ${host}` };
  }
  if (!scopeHosts.includes(host)) {
    return { ok: false, reason: `out of scope: ${host} (scope: ${scopeHosts.join(", ")})` };
  }
  return { ok: true };
}

function detectOpsecSignal(status: number, headers: Record<string, string>, body: string): string | undefined {
  if (status === 429) return "rate-limited (429)";
  const server = (headers["server"] ?? "").toLowerCase();
  const bodyLow = body.toLowerCase();
  if (status === 403 && /cloudflare|akamai|incapsula|imperva|f5|awselb|distil|perimeterx/i.test(server + bodyLow)) {
    return "probable WAF/bot-wall block (403)";
  }
  if (/captcha|cf-chl|attention required|request blocked|access denied.*bot/i.test(bodyLow) && body.length < 20000) {
    return "challenge/block page served";
  }
  return undefined;
}

export interface ProberOptions {
  scopeHosts: string[];
  timeoutMs?: number;
  /** Minimum ms between probes. Black mode adds jitter on top. Default 800. */
  minDelayMs?: number;
}

/** Structural interface so tests can inject a fake prober (no network). */
export interface ProberLike {
  probe(req: ProbeRequest): Promise<ProbeResult>;
}

export class WebProber implements ProberLike {
  private readonly scopeHosts: string[];
  private readonly timeoutMs: number;
  private readonly minDelayMs: number;
  private lastProbeAt = 0;

  constructor(opts: ProberOptions) {
    this.scopeHosts = opts.scopeHosts.map((h) => h.toLowerCase());
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    this.minDelayMs = opts.minDelayMs ?? 800;
  }

  async probe(req: ProbeRequest): Promise<ProbeResult> {
    const v = validateProbeTarget(req.url, this.scopeHosts);
    if (!v.ok) throw new Error(`[prober] refused: ${v.reason}`);
    if (req.body && Buffer.byteLength(req.body, "utf8") > MAX_BODY_BYTES) {
      throw new Error(`[prober] refused: body exceeds ${MAX_BODY_BYTES} bytes`);
    }
    const method = (req.method || "GET").toUpperCase();
    if (!/^[A-Z]+$/.test(method) || method.length > 10) {
      throw new Error(`[prober] refused: bad method ${req.method}`);
    }

    // Global rate limit.
    const wait = this.minDelayMs - (Date.now() - this.lastProbeAt);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    const started = Date.now();
    try {
      const res = await fetch(req.url, {
        method,
        headers: { "user-agent": "secscan-redteam-runner/0.4.0", ...(req.headers ?? {}) },
        body: req.body === undefined ? undefined : req.body,
        redirect: "manual",
        signal: ctrl.signal,
      });
      const text = await res.text().catch(() => "");
      const headers: Record<string, string> = {};
      res.headers.forEach((val, key) => {
        headers[key.toLowerCase()] = val;
      });
      const ms = Date.now() - started;
      this.lastProbeAt = Date.now();
      const bodySnippet = text.slice(0, 4096);
      return {
        status: res.status,
        headers,
        bodySnippet,
        ms,
        opsecSignal: detectOpsecSignal(res.status, headers, bodySnippet),
      };
    } finally {
      clearTimeout(timer);
    }
  }
}
