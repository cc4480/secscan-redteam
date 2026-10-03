/**
 * SMB operations (Windows targets): session setup, share reachability, file listing.
 *
 * LIBRARY CHOICE: `@marsaud/smb2` (v0.18.0) — the most complete Node SMB2
 * implementation available: SMB2/3 dialect negotiation, NTLMv2 auth, tree
 * connect, readdir/stat/readFile. Evaluated alternatives: `smb2` (0.2.11,
 * older, same lineage), `v9u-smb2` (1.0.6 fork, same 2022 vintage),
 * `samba-client` (shells out to a system smbclient binary — fragile, not
 * portable). The SMB2 wire protocol itself is stable, so the 2022 vintage
 * is a maintenance caveat, not a protocol risk.
 *
 * HONEST LIMITATION, stated plainly: the library has NO NetShareEnum
 * (SRVSVC) support, so true share enumeration is not possible through it.
 * `list_shares` therefore probes well-known administrative shares (C$,
 * ADMIN$, IPC$) plus any share names the agents supply from recon, and
 * reports which accept the session — share REACHABILITY probing, not full
 * enumeration. Permission mapping on discovered shares (readdir/stat) is
 * fully supported. If the library ever gains SRVSVC, this module grows a
 * real enumerate-shares path.
 *
 * Read-only surface: list_dir, stat, probe-shares. No writes, no deletes —
 * the runner never needs them for the battery, so the tool doesn't offer them.
 */

import { createRequire } from "node:module";
import { connect as smbNetConnect, type Socket as SmbSocket } from "node:net";
import { randomBytes } from "node:crypto";
import { HOST_EXEC_TIMEOUT_MS, type HostCredentials } from "./common.js";
import { buildType1, parseType2, buildType3V2 } from "./ntlmv2.js";

// @marsaud/smb2 is CJS (module.exports = the client class); the tsconfig has
// no esModuleInterop, so normalize via createRequire instead of a default
// import that TypeScript can't construct.
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-require-imports
const SMB2 = require("@marsaud/smb2") as new (options: Record<string, unknown>) => Smb2Client;

export interface SmbDirEntry {
  name: string;
  isDirectory: boolean;
  size?: number;
}

export interface SmbArgs {
  host: string;
  creds: HostCredentials;
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** Structural interface so tests inject a fake (no network). */
export interface SmbTransport {
  /** Reachability probe: which of the candidate shares accept our session. */
  probeShares(args: SmbArgs, candidates: string[]): Promise<{ share: string; accessible: boolean; note: string }[]>;
  /** List a directory on a share. Path is relative, forward slashes. */
  listDir(args: SmbArgs, share: string, path?: string): Promise<SmbDirEntry[]>;
  /** Stat one path on a share. */
  stat(args: SmbArgs, share: string, path: string): Promise<{ exists: boolean; isDirectory: boolean; size?: number }>;
  close(): Promise<void>;
}

type Smb2Client = {
  readdir(share: string, cb: (err: Error | null, files: string[]) => void): void;
  stat(share: string, cb: (err: Error | null, st: { isDirectory(): boolean; size: number }) => void): void;
  close(): void;
};

function checkAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error("[smb] aborted by kill switch");
}

/** Well-known administrative shares probed by list_shares (plus recon-supplied names). */
export const WELL_KNOWN_SHARES = ["C$", "ADMIN$", "IPC$"];

function connect(args: SmbArgs, share: string): Smb2Client {
  checkAborted(args.signal);
  const domain = args.creds.domain;
  const username = domain ? `${domain}\\${args.creds.username}` : args.creds.username;
  // The library authenticates with NTLMv2 using the provided password.
  // Empty username/password = anonymous attempt; the server's accept/reject
  // IS the observation (WS-002 null-session test).
  return new SMB2({
    share: `\\\\${args.host}\\${share}`,
    domain: domain ?? "WORKGROUP",
    username,
    password: args.creds.password ?? "",
    autoCloseTimeout: 0,
  }) as unknown as Smb2Client;
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string, signal?: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`[smb] ${what} timed out after ${ms}ms`)), ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new Error("[smb] aborted by kill switch"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    p.then(
      (v) => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        reject(e);
      },
    );
  });
}

export function createSmbTransport(): SmbTransport {
  const open: Smb2Client[] = [];
  const track = (c: Smb2Client): Smb2Client => {
    open.push(c);
    return c;
  };

  return {
    async probeShares(args, candidates) {
      checkAborted(args.signal);
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
      const names = [...WELL_KNOWN_SHARES, ...candidates.filter((c) => c && !WELL_KNOWN_SHARES.includes(c))].slice(0, 20);
      const out: { share: string; accessible: boolean; note: string }[] = [];
      for (const share of names) {
        checkAborted(args.signal);
        const client = track(connect(args, share));
        try {
          await withTimeout(
            new Promise<void>((resolve, reject) => {
              // IPC$ has no browsable root; a clean stat of "" failing with
              // "not found" still proves the TREE CONNECT succeeded.
              client.stat("", (err) => {
                if (err && !/not_found|no_such|STATUS_OBJECT_NAME_NOT_FOUND/i.test((err as Error).message)) {
                  reject(err);
                  return;
                }
                resolve();
              });
            }),
            timeoutMs,
            `share probe ${share}`,
            args.signal,
          );
          out.push({ share, accessible: true, note: "tree connect accepted" });
        } catch (err) {
          const msg = (err as Error).message;
          const denied = /access_denied|logon_failure|bad_.*password|auth/i.test(msg);
          out.push({ share, accessible: false, note: denied ? "session/share denied" : `unreachable: ${msg.slice(0, 120)}` });
        }
      }
      return out;
    },

    async listDir(args, share, path = "") {
      checkAborted(args.signal);
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
      const client = track(connect(args, share));
      // Paths are relative to the connected share's root (library convention).
      const rel = path.replace(/\//g, "\\").replace(/^\\+/, "");
      const files: string[] = await withTimeout(
        new Promise<string[]>((resolve, reject) => {
          client.readdir(rel, (err, list) => (err ? reject(err) : resolve(list)));
        }),
        timeoutMs,
        `readdir ${share}\\${rel}`,
        args.signal,
      );
      return files.slice(0, 200).map((name) => ({ name, isDirectory: false }));
    },

    async stat(args, share, path) {
      checkAborted(args.signal);
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
      const client = track(connect(args, share));
      const rel = path.replace(/\//g, "\\").replace(/^\\+/, "");
      try {
        const st = await withTimeout(
          new Promise<{ isDirectory(): boolean; size: number }>((resolve, reject) => {
            client.stat(rel, (err, s) => (err ? reject(err) : resolve(s)));
          }),
          timeoutMs,
          `stat ${share}\\${rel}`,
          args.signal,
        );
        return { exists: true, isDirectory: st.isDirectory(), size: st.size };
      } catch {
        return { exists: false, isDirectory: false };
      }
    },

    async close(): Promise<void> {
      for (const c of open.splice(0)) {
        try {
          c.close();
        } catch {
          /* best effort */
        }
      }
    },
  };
}

/* ---------------------------------------------------------------------------
 * Pass-the-hash: SMB2 session setup with NTLMv2 keyed by a precomputed NT
 * hash — battery WS-023 (v0.10.0).
 *
 * WHY NOT @marsaud/smb2: the library authenticates with a PASSWORD (its
 * bundled `ntlm` helper only builds NTLMv1 responses from a password, and
 * NTLMv1 is rejected by default on modern Windows — a PtH test through it
 * would be meaningless). NTLMv2's key IS the NT hash, so a real PtH test
 * needs NTLMv2 constructed from the hash directly. This module therefore
 * speaks the minimal SMB2 handshake itself on a raw socket:
 *
 *   NEGOTIATE -> SESSION_SETUP(NTLMSSP NEGOTIATE) ->
 *   SESSION_SETUP(NTLMSSP AUTHENTICATE w/ NTLMv2 from NT hash) -> verdict
 *
 * The verdict is the SESSION_SETUP status: STATUS_SUCCESS (0x00000000) =
 * the hash authenticates; STATUS_LOGON_FAILURE (0xC000006D) = rejected.
 * On success we LOGOFF and close — the acceptance is the finding; no share
 * is touched, no further session use occurs.
 *
 * The NT hash comes from REDTEAM_SMB_NTHASH (the test account's OWN hash,
 * provided by the client) — see resolveSmbHashCredentials in common.ts.
 * It is handled with the same secrecy as a password (collectSecrets).
 * ------------------------------------------------------------------------- */

export interface SmbPthArgs {
  host: string;
  port?: number;
  username: string;
  /** 32 lowercase hex chars — the test account's own NT hash. */
  ntHashHex: string;
  domain?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface SmbPthResult {
  reachable: boolean;
  /** Set only when the handshake ran to a verdict. */
  hashAccepted?: boolean;
  dialect?: string;
  /** Raw NTSTATUS of the final SESSION_SETUP, hex. */
  ntStatus?: string;
  note: string;
}

/** Structural interface so tests inject a fake (or a loopback test server). */
export interface SmbPthTransport {
  auth(args: SmbPthArgs): Promise<SmbPthResult>;
  close(): Promise<void>;
}

const SMB2_MAGIC = Buffer.from([0xff, 0x53, 0x4d, 0x42]); // "\xFFSMB"
const STATUS_SUCCESS = 0x00000000;
const STATUS_LOGON_FAILURE = 0xc000006d;

function u16le(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
}
function u32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}
function u64le(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b;
}

function smb2Header(command: number, messageId: number, sessionId = 0): Buffer {
  return Buffer.concat([
    SMB2_MAGIC,
    u16le(64), // HeaderLength
    u16le(0), // CreditCharge
    u32le(0), // Status
    u16le(command),
    u16le(1), // Credits
    u32le(0x00000018), // Flags: RESPONSE not set; ASYNC_COMMAND not set
    u32le(0), // ChainOffset
    u64le(messageId),
    u32le(0x0000feff), // ProcessId
    u32le(0), // TreeId
    u64le(sessionId),
    Buffer.alloc(16), // Signature
  ]);
}

function netbiosWrap(payload: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h[0] = 0x00;
  h.writeUIntBE(payload.length, 1, 3);
  return Buffer.concat([h, payload]);
}

function buildNegotiate(messageId: number): Buffer {
  const dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
  const body = Buffer.concat([
    u16le(36), // StructureSize
    u16le(dialects.length),
    u16le(1), // SecurityMode: signing enabled
    u16le(0), // Reserved
    u32le(0x0000007f), // Capabilities
    randomBytes(16), // ClientGuid
    u64le(0), // ClientStartTime
    Buffer.concat(dialects.map(u16le)),
  ]);
  return netbiosWrap(Buffer.concat([smb2Header(0x0000, messageId), body]));
}

function buildSessionSetup(messageId: number, securityBlob: Buffer, sessionId = 0): Buffer {
  // MS-SMB2 2.2.5: StructureSize(2) Flags(1) SecurityMode(1) Channel(4)
  // SecurityBufferOffset(2) SecurityBufferLength(2) = 12 bytes, then the blob.
  // (There is no PreviousSessionId in SMB2 — that was SMB1.)
  const offset = 64 + 12; // header + fixed body
  const body = Buffer.concat([
    u16le(25), // StructureSize
    Buffer.from([0x00]), // Flags
    Buffer.from([0x01]), // SecurityMode
    u32le(0), // Channel
    u16le(offset), // SecurityBufferOffset (from SMB2 header start)
    u16le(securityBlob.length),
    securityBlob,
  ]);
  return netbiosWrap(Buffer.concat([smb2Header(0x0005, messageId, sessionId), body]));
}

function buildLogoff(messageId: number, sessionId: number): Buffer {
  const body = Buffer.concat([u16le(4), u16le(0)]);
  return netbiosWrap(Buffer.concat([smb2Header(0x0002, messageId, sessionId), body]));
}

const DIALECT_NAMES: Record<number, string> = {
  0x0202: "SMB 2.0.2",
  0x0210: "SMB 2.1",
  0x0300: "SMB 3.0",
  0x0302: "SMB 3.0.2",
  0x0311: "SMB 3.1.1",
};

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
