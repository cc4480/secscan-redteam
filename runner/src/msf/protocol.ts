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
 * One msfrpc call. Throws MsfTransportError when the daemon is unreachable
 * or the response is not a MessagePack map — both fail closed upstream.
 */
export async function msfCall(
  request: MsfRequestFn,
  method: string,
  token: string | null,
  args: unknown[],
): Promise<Record<string, unknown>> {
  const payload = token === null ? [method, ...args] : [method, token, ...args];
  let raw: Uint8Array;
  try {
    raw = await request(encode(payload as unknown[]));
  } catch (err) {
    throw new MsfTransportError(`msfrpcd request failed (${method}): ${(err as Error).message}`, err);
  }
  let decoded: unknown;
  try {
    decoded = decode(raw);
  } catch (err) {
    throw new MsfTransportError(`msfrpcd returned undecodable data (${method})`, err);
  }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new MsfTransportError(`msfrpcd returned a non-map response (${method})`);
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
