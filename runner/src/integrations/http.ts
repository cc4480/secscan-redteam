/**
 * INTEGRATIONS — tiny injectable HTTP layer (v0.15.0).
 *
 * All integration traffic goes through this: global fetch by default,
 * a fake in tests. 15s timeout, abortable, and the response helper
 * surfaces non-2xx as typed errors (never throws raw bodies at callers).
 */

export type HttpFn = (url: string, init: RequestInit) => Promise<Response>;

export const INTEGRATION_TIMEOUT_MS = 15_000;

export class IntegrationHttpError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(message: string, status: number, body: string) {
    super(message);
    this.name = "IntegrationHttpError";
    this.status = status;
    this.body = body.slice(0, 500);
  }
}

function withTimeout(fetchFn: HttpFn): HttpFn {
  return async (url, init) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), INTEGRATION_TIMEOUT_MS);
    try {
      return await fetchFn(url, { ...init, signal: ctrl.signal });
    } finally {
      clearTimeout(timer);
    }
  };
}

export function defaultHttp(): HttpFn {
  return withTimeout(fetch);
}

/** POST/PUT JSON; throws IntegrationHttpError on non-2xx. Never logs bodies. */
export async function requestJson(
  http: HttpFn,
  method: "POST" | "PUT" | "PATCH" | "GET",
  url: string,
  headers: Record<string, string>,
  body?: unknown,
): Promise<unknown> {
  const res = await http(url, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text().catch(() => "");
  if (!res.ok) {
    throw new IntegrationHttpError(
      `integration request failed: ${method} ${redactUrl(url)} → HTTP ${res.status}`,
      res.status,
      text,
    );
  }
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { _raw: text.slice(0, 500) };
  }
}

/** Strip query strings from URLs before they appear in errors/logs. */
export function redactUrl(url: string): string {
  const q = url.indexOf("?");
  return q >= 0 ? url.slice(0, q) : url;
}

export function basicAuth(user: string, secret: string): string {
  return `Basic ${Buffer.from(`${user}:${secret}`, "utf8").toString("base64")}`;
}
