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

import { randomBytes } from "node:crypto";

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
export const STATUS_SUCCESS = 0x00000000;
export const STATUS_LOGON_FAILURE = 0xc000006d;

export function u16le(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
}
export function u32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}
export function u64le(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b;
}

export function smb2Header(command: number, messageId: number, sessionId = 0): Buffer {
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

export function netbiosWrap(payload: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h[0] = 0x00;
  h.writeUIntBE(payload.length, 1, 3);
  return Buffer.concat([h, payload]);
}

export function buildNegotiate(messageId: number): Buffer {
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

export function buildSessionSetup(messageId: number, securityBlob: Buffer, sessionId = 0): Buffer {
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

export function buildLogoff(messageId: number, sessionId: number): Buffer {
  const body = Buffer.concat([u16le(4), u16le(0)]);
  return netbiosWrap(Buffer.concat([smb2Header(0x0002, messageId, sessionId), body]));
}

export const DIALECT_NAMES: Record<number, string> = {
  0x0202: "SMB 2.0.2",
  0x0210: "SMB 2.1",
  0x0300: "SMB 3.0",
  0x0302: "SMB 3.0.2",
  0x0311: "SMB 3.1.1",
};
