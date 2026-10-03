/**
 * Shared NTLMv2 / CredSSP / DER primitives (v0.10.0).
 *
 * Pure functions, no network — used by rdp.ts (NLA credential validation)
 * and smb.ts (pass-the-hash with NTLMv2 from an NT hash). Kept in one place
 * so the two protocol implementations can't drift apart.
 *
 * MD4: Node's OpenSSL 3 build has MD4 disabled, and js-md4's fast path
 * (node crypto) throws on this runtime — so md4bytes() deliberately uses
 * js-md4's PURE-JS implementation via md4.create() (verified against the
 * known NT hash of "password": 8846f7eaee8fb117ad06bdd830b7586c).
 */

import { createHmac, randomBytes } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-require-imports
const md4lib = require("js-md4") as {
  create(): { update(d: Uint8Array): { arrayBuffer(): ArrayBuffer } };
};

/** MD4 digest (16 bytes), pure-JS — the NT hash primitive. */
export function md4bytes(data: Uint8Array): Buffer {
  return Buffer.from(md4lib.create().update(data).arrayBuffer());
}

/** NT hash = MD4(UTF-16LE(password)). */
export function ntHash(password: string): Buffer {
  return md4bytes(Buffer.from(password, "utf16le"));
}

/**
 * NTOWFv2 per MS-NLMP 3.3.2: HMAC-MD5(NT_hash, UTF16LE(UPPER(user) + domain)).
 * The NT hash IS the NTLMv2 key — which is exactly why pass-the-hash works:
 * no password is needed once the hash is known.
 */
export function ntowfv2(user: string, domain: string, hash: Buffer): Buffer {
  return createHmac("md5", hash)
    .update(Buffer.from(user.toUpperCase() + domain, "utf16le"))
    .digest();
}

const u16le = (n: number): Buffer => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
};
const u32le = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
};

/** Standard client flags: UNICODE|OEM|REQUEST_TARGET|NTLM|ALWAYS_SIGN|EXTENDED_SESSION|VERSION|128|56. */
export const NTLM_FLAGS = 0x00088207;

function secBuf(len: number, offset: number): Buffer {
  return Buffer.concat([u16le(len), u16le(len), u32le(offset)]);
}

/** NTLMSSP NEGOTIATE (Type 1). */
export function buildType1(domain = "", workstation = ""): Buffer {
  const d = Buffer.from(domain.toUpperCase(), "utf16le");
  const w = Buffer.from(workstation.toUpperCase(), "utf16le");
  const off = 32;
  const head = Buffer.concat([
    Buffer.from("NTLMSSP\0", "ascii"),
    u32le(1),
    u32le(NTLM_FLAGS),
    secBuf(d.length, off),
    secBuf(w.length, off + d.length),
  ]);
  return Buffer.concat([head, d, w]);
}

export interface Type2 {
  flags: number;
  challenge: Buffer;
  targetInfo: Buffer;
  targetName: string;
}

/** Parse an NTLMSSP CHALLENGE (Type 2). Throws on malformed input. */
export function parseType2(buf: Buffer): Type2 {
  if (buf.length < 48 || buf.subarray(0, 8).toString("ascii") !== "NTLMSSP\0" || buf.readUInt32LE(8) !== 2) {
    throw new Error("[ntlmv2] not an NTLMSSP CHALLENGE message");
  }
  const flags = buf.readUInt32LE(20);
  const challenge = buf.subarray(24, 32);
  const tiLen = buf.readUInt16LE(40);
  const tiOff = buf.readUInt32LE(44);
  const targetInfo = tiLen > 0 ? buf.subarray(tiOff, tiOff + tiLen) : Buffer.alloc(0);
  const tnLen = buf.readUInt16LE(12);
  const tnOff = buf.readUInt32LE(16);
  const targetName = tnLen > 0 ? buf.subarray(tnOff, tnOff + tnLen).toString("utf16le") : "";
  return { flags, challenge: Buffer.from(challenge), targetInfo: Buffer.from(targetInfo), targetName };
}

/**
 * NTLMSSP AUTHENTICATE (Type 3) with NTLMv2, keyed by a precomputed NT hash
 * (pass-the-hash) — or by a password-derived hash; the construction is
 * identical once the 16-byte key exists.
 */
export function buildType3V2(opts: {
  user: string;
  domain: string;
  workstation?: string;
  challenge: Buffer;
  targetInfo: Buffer;
  ntHash: Buffer;
  clientNonce?: Buffer;
}): Buffer {
  const { user, domain, challenge, targetInfo, ntHash: hash } = opts;
  const workstation = (opts.workstation ?? "").toUpperCase();
  const responseKey = ntowfv2(user, domain, hash);
  const clientNonce = opts.clientNonce ?? randomBytes(8);

  // FILETIME timestamp (100ns since 1601-01-01); servers tolerate zero, but a
  // real timestamp is more likely to be accepted.
  const filetime = BigInt(Date.now()) * 10000n + 116444736000000000n;
  const ts = Buffer.alloc(8);
  ts.writeBigUInt64LE(filetime, 0);

  // NTLMv2 blob: 01010000 00000000 timestamp clientNonce 00000000 targetInfo 00000000
  const blob = Buffer.concat([
    Buffer.from([0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    ts,
    clientNonce,
    Buffer.alloc(4),
    targetInfo,
    Buffer.alloc(4),
  ]);
  const ntProof = createHmac("md5", responseKey)
    .update(Buffer.concat([challenge, blob]))
    .digest();
  const ntResponse = Buffer.concat([ntProof, blob]);
  // NTLMv2-style LM response: HMAC-MD5(key, challenge + clientNonce) + nonce.
  const lmResponse = Buffer.concat([
    createHmac("md5", responseKey).update(Buffer.concat([challenge, clientNonce])).digest(),
    clientNonce,
  ]);

  const d = Buffer.from(domain.toUpperCase(), "utf16le");
  const u = Buffer.from(user, "utf16le");
  const w = Buffer.from(workstation, "utf16le");
  let off = 64; // 8 sig + 4 type + 6*8 secbufs + 4 flags
  const parts: Buffer[] = [];
  const push = (b: Buffer): Buffer => {
    const sb = secBuf(b.length, off);
    off += b.length;
    parts.push(b);
    return sb;
  };
  const head = Buffer.concat([
    Buffer.from("NTLMSSP\0", "ascii"),
    u32le(3),
    push(lmResponse),
    push(ntResponse),
    push(d),
    push(u),
    push(w),
    secBuf(0, off), // session key: empty
    u32le(NTLM_FLAGS),
  ]);
  return Buffer.concat([head, ...parts]);
}

// ---------------------------------------------------------------------------
// Minimal DER reader/writer — enough for CredSSP TSRequest / SPNEGO and for
// parsing kirbi (KRB-CRED) files. Not a general ASN.1 library; every helper
// is total (throws on malformed input) and bounded by the input buffer.
// ---------------------------------------------------------------------------

export function derLen(n: number): Buffer {
  if (n < 128) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function derTLV(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

const derInt = (n: number): Buffer => derTLV(0x02, Buffer.from([n]));
const derOctet = (b: Buffer): Buffer => derTLV(0x04, b);
const derSeq = (...children: Buffer[]): Buffer => derTLV(0x30, Buffer.concat(children));

/** SPNEGO OID 1.2.840.113554.1.2.2 */
const SPNEGO_OID = Buffer.from([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);

/** SPNEGO NegTokenInit wrapping a raw NTLMSSP token (Type 1). */
export function spnegoInit(ntlmToken: Buffer): Buffer {
  const mechTypes = derTLV(0xa0, derSeq(SPNEGO_OID));
  const mechToken = derTLV(0xa2, derOctet(ntlmToken));
  // [APPLICATION 0] { ... }
  return derTLV(0x60, Buffer.concat([mechTypes, mechToken]));
}

/** SPNEGO NegTokenResp wrapping a raw NTLMSSP token (Type 3). negState 1 = accept-incomplete. */
export function spnegoResp(ntlmToken: Buffer): Buffer {
  const negState = derTLV(0xa0, derTLV(0x0a, Buffer.from([0x01])));
  const responseToken = derTLV(0xa2, derOctet(ntlmToken));
  return derSeq(negState, responseToken);
}

/** CredSSP TSRequest: [0] version INTEGER, [1] negoTokens OCTET STRING. */
export function tsRequest(negoToken: Buffer, version = 6): Buffer {
  return derSeq(derTLV(0xa0, derInt(version)), derTLV(0xa1, derOctet(negoToken)));
}

interface DerNode {
  tag: number;
  content: Buffer;
  children: DerNode[];
}

function derParseOne(buf: Buffer, offset: number): { node: DerNode; next: number } {
  if (offset + 2 > buf.length) throw new Error("[der] truncated header");
  const tag = buf[offset];
  let len = buf[offset + 1];
  let pos = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || pos + n > buf.length) throw new Error("[der] bad long-form length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[pos++];
  }
  if (pos + len > buf.length) throw new Error("[der] truncated content");
  const content = buf.subarray(pos, pos + len);
  const children: DerNode[] = [];
  if (tag & 0x20) {
    let p = 0;
    while (p < content.length) {
      const r = derParseOne(content, p);
      children.push(r.node);
      p = r.next;
    }
  }
  return { node: { tag, content, children }, next: pos + len };
}

export function derParse(buf: Buffer): DerNode {
  return derParseOne(buf, 0).node;
}

/** Find first child with the given context tag (0xa0, 0xa1, ...). */
export function derChild(node: DerNode, tag: number): DerNode | undefined {
  return node.children.find((c) => c.tag === tag);
}

/** Unwrap [n] OCTET STRING (context tag holding a single OCTET STRING child, or raw bytes). */
export function derUnwrapOctet(node: DerNode): Buffer {
  const inner = node.children.find((c) => c.tag === 0x04);
  return inner ? inner.content : node.content;
}

/**
 * Extract the NTLM token from a server CredSSP TSResponse: walk
 * SEQ -> [1] negoTokens -> NegTokenResp SEQ -> [2] responseToken.
 */
export function tsResponseNtlmToken(tsResp: Buffer): Buffer {
  const root = derParse(tsResp);
  const nego = derChild(root, 0xa1);
  if (!nego) throw new Error("[der] TSResponse has no negoTokens");
  const spnego = derParse(derUnwrapOctet(nego));
  const respTok = derChild(spnego, 0xa2);
  if (!respTok) throw new Error("[der] NegTokenResp has no responseToken");
  return derUnwrapOctet(respTok);
}
