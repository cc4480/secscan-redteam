// ---------------------------------------------------------------------------
// TCP connection with RPC record-marking I/O
// ---------------------------------------------------------------------------

import { connect, type Socket } from "node:net";


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
