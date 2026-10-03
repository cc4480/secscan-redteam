/**
 * NFS export enumeration (battery LX-041) — pure-Node userland RPC.
 *
 * NO KERNEL MOUNT, by design: mounting needs privileges (CAP_SYS_ADMIN /
 * root) the runner will not assume, and a mount changes target-side state.
 * The export list IS the executable evidence — it answers "which
 * filesystems does this host offer to whom" without touching them.
 *
 * Wire protocol, from scratch (no new dependencies):
 *   1. TCP to the target's portmapper (port 111), ONC RPC call
 *      GETPORT (prog 100000, vers 2, proc 3) for the mount daemon
 *      (prog 100005), TCP (proto 6). Falls back to asking for mountd
 *      vers 1 when vers 3 is not registered.
 *   2. TCP to the returned mountd port, RPC MOUNT prog 100005 proc 5
 *      (EXPORT, no arguments) — try vers 3 first, fall back to vers 1 on
 *      PROG_UNAVAIL / PROG_MISMATCH.
 *   3. Parse the export linked list (dirpath + per-export group list).
 *
 * XDR is encoded/decoded by hand with tiny total helpers (they throw on
 * truncated input rather than reading past the buffer). RPC-over-TCP
 * record marking (RFC 1831 §10) is handled on both write and read.
 *
 * Timeouts bound every dial and every round-trip; an AbortSignal destroys
 * in-flight sockets. Everything fails closed.
 */

import { connect, type Socket } from "node:net";
import { HOST_EXEC_TIMEOUT_MS } from "./common.js";

// ---------------------------------------------------------------------------
// Tiny XDR helpers — total: they throw on truncated input.
// ---------------------------------------------------------------------------

export class XdrReader {
  private off = 0;
  constructor(private readonly buf: Buffer) {}

  u32(): number {
    if (this.off + 4 > this.buf.length) throw new Error("[nfs] truncated XDR input (u32)");
    const v = this.buf.readUInt32BE(this.off);
    this.off += 4;
    return v;
  }

  /** XDR string: u32 length, bytes, zero-padded to a 4-byte boundary. */
  str(): string {
    const len = this.u32();
    if (len > 4 * 1024 * 1024) throw new Error("[nfs] absurd XDR string length");
    if (this.off + len > this.buf.length) throw new Error("[nfs] truncated XDR input (string)");
    const s = this.buf.subarray(this.off, this.off + len).toString("utf8");
    this.off += len + ((-len & 3) >>> 0);
    return s;
  }

  /** Skip n bytes plus XDR padding to the next 4-byte boundary. */
  skip(n: number): void {
    const total = n + ((-n & 3) >>> 0);
    if (this.off + total > this.buf.length) throw new Error("[nfs] truncated XDR input (skip)");
    this.off += total;
  }

  rest(): Buffer {
    return this.buf.subarray(this.off);
  }
}

export function xdrU32(v: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(v >>> 0, 0);
  return b;
}

export function xdrString(s: string): Buffer {
  const raw = Buffer.from(s, "utf8");
  const pad = (-raw.length & 3) >>> 0;
  return Buffer.concat([xdrU32(raw.length), raw, Buffer.alloc(pad)]);
}

// ---------------------------------------------------------------------------
// ONC RPC framing (RFC 1831)
// ---------------------------------------------------------------------------

let xidCounter = (Math.random() * 0xffffffff) >>> 0;

function rpcCall(prog: number, vers: number, proc: number, args: Buffer): Buffer {
  xidCounter = (xidCounter + 1) >>> 0;
  const head = Buffer.alloc(24);
  head.writeUInt32BE(xidCounter, 0); // xid
  head.writeUInt32BE(0, 4); // CALL
  head.writeUInt32BE(2, 8); // RPC version 2
  head.writeUInt32BE(prog, 12);
  head.writeUInt32BE(vers, 16);
  head.writeUInt32BE(proc, 20);
  const authNull = Buffer.alloc(16); // cred AUTH_NULL (flavor+len) + verf AUTH_NULL (flavor+len)
  return Buffer.concat([head, authNull, args]);
}

function rpcXid(call: Buffer): number {
  return call.readUInt32BE(0);
}

/** Error carrying the RPC accept status so callers can decide on fallback. */
export class RpcAcceptError extends Error {
  constructor(
    message: string,
    readonly acceptStatus: number,
  ) {
    super(message);
  }
}

/** Accept status codes (RFC 1831): 0 SUCCESS, 1 PROG_UNAVAIL, 2 PROG_MISMATCH, 3 PROC_UNAVAIL, 4 GARBAGE_ARGS, 5 SYSTEM_ERR. */
export const RPC_PROG_MISMATCH = 2;

/** Parse an RPC reply record; returns the procedure-result bytes. Throws on reject/failure. */
export function parseRpcReply(record: Buffer, xid: number): Buffer {
  const r = new XdrReader(record);
  const rx = r.u32();
  if (rx !== xid) throw new Error("[nfs] RPC xid mismatch — not our reply");
  if (r.u32() !== 1) throw new Error("[nfs] not an RPC REPLY message");
  const replyState = r.u32();
  if (replyState !== 0) throw new Error(`[nfs] RPC call rejected (reply state ${replyState})`);
  r.u32(); // verifier flavor
  r.skip(r.u32()); // verifier body (+ padding)
  const accept = r.u32();
  if (accept !== 0) {
    throw new RpcAcceptError(`[nfs] RPC call failed (accept status ${accept})`, accept);
  }
  return r.rest();
}

// ---------------------------------------------------------------------------
// TCP connection with RPC record-marking I/O
// ---------------------------------------------------------------------------

export interface NfsConnection {
  write(data: Buffer): Promise<void>;
  /** Read one complete RPC reply record (record-marking handled). */
  readRecord(): Promise<Buffer>;
  close(): void;
}

export type NfsDialFn = (
  host: string,
  port: number,
  timeoutMs: number,
  signal?: AbortSignal,
) => Promise<NfsConnection>;

class SocketConnection implements NfsConnection {
  private buf = Buffer.alloc(0);
  private waiters: Array<() => void> = [];
  private failed: Error | null = null;
  private ended = false;

  constructor(
    private readonly sock: Socket,
    signal?: AbortSignal,
  ) {
    sock.on("data", (d: Buffer) => {
      this.buf = Buffer.concat([this.buf, d]);
      this.pump();
    });
    sock.on("error", (e) => this.die(e as Error));
    sock.on("close", () => {
      this.ended = true;
      this.pump();
    });
    signal?.addEventListener(
      "abort",
      () => this.die(new Error("[nfs] aborted by kill switch")),
      { once: true },
    );
  }

  private pump(): void {
    const w = this.waiters.splice(0);
    for (const fn of w) fn();
  }

  private die(err: Error): void {
    if (!this.failed) this.failed = err;
    try {
      this.sock.destroy();
    } catch {
      /* already gone */
    }
    this.pump();
  }

  private async readBytes(n: number): Promise<Buffer> {
    for (;;) {
      if (this.failed) throw this.failed;
      if (this.buf.length >= n) {
        const out = this.buf.subarray(0, n);
        this.buf = this.buf.subarray(n);
        return Buffer.from(out);
      }
      if (this.ended) throw new Error("[nfs] connection closed mid-record");
      await new Promise<void>((res) => this.waiters.push(res));
    }
  }

  async write(data: Buffer): Promise<void> {
    if (this.failed) throw this.failed;
    // RPC-over-TCP record marking: single fragment, last-fragment bit set.
    // (0x80000000 | len) is negative as a JS int32 — coerce to unsigned.
    const header = Buffer.alloc(4);
    header.writeUInt32BE((0x80000000 + data.length) >>> 0, 0);
    await new Promise<void>((resolve, reject) => {
      this.sock.write(Buffer.concat([header, data]), (e) => (e ? reject(e) : resolve()));
    });
  }

  async readRecord(): Promise<Buffer> {
    const chunks: Buffer[] = [];
    for (;;) {
      const h = await this.readBytes(4);
      const word = h.readUInt32BE(0);
      const last = (word & 0x80000000) !== 0;
      const len = word & 0x7fffffff;
      if (len > 8 * 1024 * 1024) throw new Error("[nfs] RPC record fragment absurdly large");
      chunks.push(await this.readBytes(len));
      if (last) return Buffer.concat(chunks);
    }
  }

  close(): void {
    try {
      this.sock.destroy();
    } catch {
      /* best effort */
    }
  }
}

export function defaultNfsDial(
  host: string,
  port: number,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<NfsConnection> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error("[nfs] aborted by kill switch before dial"));
      return;
    }
    const sock = connect({ host, port });
    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      try {
        sock.destroy();
      } catch {
        /* best effort */
      }
      reject(err);
    };
    const timer = setTimeout(
      () => fail(new Error(`[nfs] connect to ${host}:${port} timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
    const onAbort = () => fail(new Error("[nfs] aborted by kill switch during dial"));
    signal?.addEventListener("abort", onAbort, { once: true });
    sock.on("connect", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve(new SocketConnection(sock, signal));
    });
    sock.on("error", (e) => fail(new Error(`[nfs] dial ${host}:${port}: ${(e as Error).message}`)));
  });
}

// ---------------------------------------------------------------------------
// Portmapper + mountd
// ---------------------------------------------------------------------------

const PORTMAPPER_PORT = 111;
const PORTMAPPER_PROG = 100000;
const MOUNT_PROG = 100005;
const PROTO_TCP = 6;

async function rpcRoundTrip(
  conn: NfsConnection,
  call: Buffer,
  timeoutMs: number,
): Promise<Buffer> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const p = (async () => {
      await conn.write(call);
      return conn.readRecord();
    })();
    const winner = await Promise.race([
      p,
      new Promise<Buffer>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`[nfs] RPC round-trip timed out after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
    return parseRpcReply(winner, rpcXid(call));
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Portmapper GETPORT for the mount daemon; tries mount vers 3, then vers 1. */
async function getMountdPort(
  dial: NfsDialFn,
  host: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<number> {
  const conn = await dial(host, PORTMAPPER_PORT, timeoutMs, signal);
  try {
    for (const vers of [3, 1]) {
      const args = Buffer.concat([xdrU32(MOUNT_PROG), xdrU32(vers), xdrU32(PROTO_TCP), xdrU32(0)]);
      const body = await rpcRoundTrip(conn, rpcCall(PORTMAPPER_PROG, 2, 3, args), timeoutMs);
      const port = new XdrReader(body).u32();
      if (port !== 0) return port;
    }
    throw new Error("[nfs] mountd not registered with the portmapper (vers 3 and 1)");
  } finally {
    conn.close();
  }
}

export interface NfsExport {
  export: string;
  groups: string[];
}

function parseExportList(body: Buffer): NfsExport[] {
  const r = new XdrReader(body);
  const out: NfsExport[] = [];
  while (r.u32() !== 0) {
    // exportnode: value_follows, dirpath, groups
    const dirpath = r.str();
    const groups: string[] = [];
    while (r.u32() !== 0) {
      // groupnode: value_follows, name
      groups.push(r.str());
    }
    out.push({ export: dirpath, groups });
  }
  return out;
}

export interface NfsEnumerateArgs {
  host: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** Structural interface so tests inject a fake (no network). */
export interface NfsTransport {
  enumerateExports(args: NfsEnumerateArgs): Promise<NfsExport[]>;
  close(): Promise<void>;
}

export function createNfsTransport(dial: NfsDialFn = defaultNfsDial): NfsTransport {
  const open = new Set<NfsConnection>();
  const track = (c: NfsConnection): NfsConnection => {
    open.add(c);
    return c;
  };

  return {
    async enumerateExports(args: NfsEnumerateArgs): Promise<NfsExport[]> {
      if (args.signal?.aborted) throw new Error("[nfs] aborted by kill switch before enumerate");
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;

      const mountdPort = await getMountdPort(dial, args.host, timeoutMs, args.signal);
      const conn = track(await dial(args.host, mountdPort, timeoutMs, args.signal));
      try {
        // EXPORT is proc 5 in both mount v3 and v1. Try v3 first; fall back
        // to v1 on PROG_UNAVAIL / PROG_MISMATCH (daemon too old for v3).
        let lastErr: unknown = null;
        for (const vers of [3, 1]) {
          try {
            const body = await rpcRoundTrip(conn, rpcCall(MOUNT_PROG, vers, 5, Buffer.alloc(0)), timeoutMs);
            return parseExportList(body);
          } catch (err) {
            lastErr = err;
            const accept = err instanceof RpcAcceptError ? err.acceptStatus : -1;
            if (vers === 3 && (accept === 1 || accept === RPC_PROG_MISMATCH)) continue; // try v1
            throw err;
          }
        }
        throw lastErr;
      } finally {
        open.delete(conn);
        conn.close();
      }
    },

    async close(): Promise<void> {
      for (const c of open) {
        try {
          c.close();
        } catch {
          /* best effort */
        }
      }
      open.clear();
    },
  };
}
