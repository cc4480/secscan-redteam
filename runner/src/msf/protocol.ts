/**
 * msfrpc wire protocol — MessagePack over HTTP(S), injectable transport.
 *
 * Metasploit Framework's RPC daemon (msfrpcd) speaks a simple protocol:
 * POST a MessagePack-encoded array [method, token, ...args] to /api/ and
 * read back a MessagePack-encoded map. The transport is a function so tests
 * run against a fake (no Metasploit needed) and production uses fetch.
 *
 * Reference: Metasploit Framework msfrpc (external service, not vendored).
 */

import { encode, decode } from "@msgpack/msgpack";

export const MSFRPC_DEFAULT_HOST = "127.0.0.1";
export const MSFRPC_DEFAULT_PORT = 55553;
export const MSFRPC_DEFAULT_TLS = true;

/** Raw request function: POST body → response body. Injectable for tests. */
export type MsfRequestFn = (body: Uint8Array) => Promise<Uint8Array>;

export class MsfTransportError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "MsfTransportError";
  }
}

/**
 * msfrpcd encodes every string as MessagePack BINARY, not str.
 *
 * Ruby's `String#to_msgpack` emits `bin` for ASCII-8BIT strings, and msfrpcd's
 * responses come back that way — both map keys and values. Two consequences,
 * both of which made this bridge unable to talk to a real daemon:
 *
 *   1. @msgpack/msgpack v3 refuses a non-string map key ("The type of key must
 *      be string or number but object"), so every call threw
 *      MsfTransportError('undecodable data') before the result was ever read.
 *   2. Even with the keys converted, values arrive as Uint8Array rather than
 *      string, so `res['result'] === 'success'` could never be true.
 *
 * Found by pointing the bridge at a real msfrpcd. The unit tests inject a fake
 * transport that returns encoder-produced bytes, which use str — so they pass
 * while production fails. Fix both sides: convert keys on the way in, then
 * normalise binary leaves to UTF-8 strings.
 */
function decodeMsfResponse(raw: Uint8Array): unknown {
  return decode(raw, {
    mapKeyConverter: (key: unknown): string | number =>
      typeof key === "string" || typeof key === "number" ? key : new TextDecoder().decode(key as Uint8Array),
  });
}

/** Recursively turn binary leaves into UTF-8 strings, leaving other types alone. */
function normaliseBinary(value: unknown): unknown {
  if (value instanceof Uint8Array) return new TextDecoder().decode(value);
  if (Array.isArray(value)) return value.map(normaliseBinary);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = normaliseBinary(v);
    return out;
  }
  return value;
}

/**
 * One msfrpc call. Throws MsfTransportError when the daemon is unreachable
 * or the response is not MessagePack at all — both fail closed upstream.
 *
 * The response may legitimately be a MAP (`core.version`, `auth.login`,
 * `module.exploits`) or an ARRAY: `module.search` returns a bare array of
 * module records, not `{modules:[…]}`. Demanding a map here made every
 * module search throw "non-map response" against a real daemon, so the
 * caller decides which shape it expects.
 */
export async function msfCall(
  request: MsfRequestFn,
  method: string,
  token: string | null,
  args: unknown[],
): Promise<Record<string, unknown> | unknown[]> {
  const payload = token === null ? [method, ...args] : [method, token, ...args];
  let raw: Uint8Array;
  try {
    raw = await request(encode(payload as unknown[]));
  } catch (err) {
    throw new MsfTransportError(`msfrpcd request failed (${method}): ${(err as Error).message}`, err);
  }
  let decoded: unknown;
  try {
    decoded = normaliseBinary(decodeMsfResponse(raw));
  } catch (err) {
    throw new MsfTransportError(`msfrpcd returned undecodable data (${method})`, err);
  }
  if (Array.isArray(decoded)) return decoded;
  if (typeof decoded !== "object" || decoded === null) {
    throw new MsfTransportError(`msfrpcd returned neither a map nor an array (${method})`);
  }
  return decoded as Record<string, unknown>;
}

export interface MsfHttpOptions {
  host: string;
  port: number;
  useTls: boolean;
  timeoutMs: number;
  signal?: AbortSignal;
}

/**
 * Production transport: HTTPS (or HTTP when explicitly configured) POST to
 * /api/ with a timeout. msfrpcd ships self-signed by default — the runner
 * connects to the OPERATOR's OWN daemon (usually 127.0.0.1), so we do not
 * do public-CA validation here; the credential (user/pass) is the auth.
 */
export function createHttpMsfRequest(opts: MsfHttpOptions): MsfRequestFn {
  const scheme = opts.useTls ? "https" : "http";
  const url = `${scheme}://${opts.host}:${opts.port}/api/`;
  return async (body: Uint8Array): Promise<Uint8Array> => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs);
    const onAbort = () => ctrl.abort();
    opts.signal?.addEventListener("abort", onAbort, { once: true });
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "binary/message-pack" },
        body: body as unknown as BodyInit,
        signal: ctrl.signal,
        // @ts-expect-error Node fetch extension: msfrpcd default certs are self-signed.
        rejectUnauthorized: false,
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status} ${res.statusText}`);
      }
      return new Uint8Array(await res.arrayBuffer());
    } catch (err) {
      if ((err as Error).name === "AbortError") {
        throw new MsfTransportError(`msfrpcd request timed out after ${opts.timeoutMs}ms — is msfrpcd running?`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
    }
  };
}
