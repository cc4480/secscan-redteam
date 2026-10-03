// ---------------------------------------------------------------------------
// Channel abstraction (injectable for tests)
// ---------------------------------------------------------------------------

import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";

export interface RdpChannel {
  write(b: Buffer): void;
  readExactly(n: number, timeoutMs: number): Promise<Buffer>;
  /** Take whatever is currently buffered (may be empty). */
  drain(): Buffer;
  /** Upgrade the underlying socket to TLS (CredSSP runs inside TLS). */
  startTls(): Promise<void>;
  close(): void;
}

export interface RdpTransport {
  open(host: string, port: number, timeoutMs: number, signal?: AbortSignal): Promise<RdpChannel>;
  close(): Promise<void>;
}

class RealRdpChannel implements RdpChannel {
  private sock: Socket | TLSSocket;
  private buf = Buffer.alloc(0);
  private waiters: { n: number; resolve: (b: Buffer) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }[] = [];
  private closedFlag = false;

  constructor(sock: Socket) {
    this.sock = sock;
    sock.on("data", (d: Buffer) => this.onData(d));
    sock.on("close", () => this.onClose(new Error("[rdp] connection closed by peer")));
    sock.on("error", (e) => this.onClose(e instanceof Error ? e : new Error(String(e))));
  }

  private onData(d: Buffer): void {
    this.buf = Buffer.concat([this.buf, d]);
    this.pump();
  }

  private pump(): void {
    while (this.waiters.length > 0 && this.buf.length >= this.waiters[0].n) {
      const w = this.waiters.shift()!;
      clearTimeout(w.timer);
      const out = this.buf.subarray(0, w.n);
      this.buf = this.buf.subarray(w.n);
      w.resolve(out);
    }
  }

  private onClose(err: Error): void {
    if (this.closedFlag) return;
    this.closedFlag = true;
    for (const w of this.waiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(err);
    }
  }

  write(b: Buffer): void {
    if (this.closedFlag) throw new Error("[rdp] write on closed channel");
    this.sock.write(b);
  }

  readExactly(n: number, timeoutMs: number): Promise<Buffer> {    if (this.buf.length >= n) {
      const out = this.buf.subarray(0, n);
      this.buf = this.buf.subarray(n);
      return Promise.resolve(out);
    }
    return new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this.waiters.findIndex((w) => w.resolve === resolve);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new Error(`[rdp] read timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.waiters.push({ n, resolve, reject, timer });
    });
  }

  drain(): Buffer {
    const out = this.buf;
    this.buf = Buffer.alloc(0);
    return out;
  }

  async startTls(): Promise<void> {
    const sock = this.sock;
    if (this.closedFlag) throw new Error("[rdp] cannot TLS-upgrade a closed channel");
    // Carry any already-buffered bytes back so the TLS layer sees them.
    const leftover = this.buf;
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    const tlsSock = tlsConnect({
      socket: sock,
      // The server certificate is part of the observation (self-signed is
      // expected on RDP); this is an operator-scoped test host, not a trust
      // decision. Documented, deliberate.
      rejectUnauthorized: false,
    });
    await new Promise<void>((resolve, reject) => {
      tlsSock.once("secureConnect", () => resolve());
      tlsSock.once("error", reject);
    });
    if (leftover.length > 0) tlsSock.unshift(leftover);
    this.sock = tlsSock;
    tlsSock.on("data", (d: Buffer) => this.onData(d));
    tlsSock.on("close", () => this.onClose(new Error("[rdp] TLS connection closed by peer")));
    tlsSock.on("error", (e) => this.onClose(e instanceof Error ? e : new Error(String(e))));
  }

  close(): void {
    this.closedFlag = true;
    try {
      this.sock.destroy();
    } catch {
      /* best effort */
    }
  }
}

export function createRdpTransport(): RdpTransport {
  const channels: RealRdpChannel[] = [];
  return {
    async open(host, port, timeoutMs, signal): Promise<RdpChannel> {
      if (signal?.aborted) throw new Error("[rdp] aborted by kill switch before connect");
      const sock = netConnect({ host, port });
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          sock.destroy();
          reject(new Error(`[rdp] TCP connect timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        const onAbort = () => {
          clearTimeout(timer);
          sock.destroy();
          reject(new Error("[rdp] aborted by kill switch"));
        };
        signal?.addEventListener("abort", onAbort, { once: true });
        sock.once("connect", () => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          resolve();
        });
        sock.once("error", (e) => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          reject(new Error(`[rdp] TCP connect failed: ${(e as Error).message}`));
        });
      });
      const ch = new RealRdpChannel(sock);
      channels.push(ch);
      signal?.addEventListener("abort", () => ch.close(), { once: true });
      return ch;
    },
    async close(): Promise<void> {
      for (const c of channels.splice(0)) {
        try {
          c.close();
        } catch {
          /* best effort */
        }
      }
    },
  };
}
