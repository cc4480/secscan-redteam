// ---------------------------------------------------------------------------
// X.224 / RDP negotiation (MS-RDPBCGR 2.2.1.1)
// ---------------------------------------------------------------------------

const PROTOCOL_RDP = 0;
const PROTOCOL_SSL = 1;
export const PROTOCOL_HYBRID = 2;
export const PROTOCOL_HYBRID_EX = 8;

export function buildX224ConnectionRequest(): Buffer {
  const rdpNegReq = Buffer.alloc(8);
  rdpNegReq[0] = 0x01; // TYPE_RDP_NEG_REQ
  rdpNegReq[1] = 0x00; // flags
  rdpNegReq.writeUInt16LE(8, 2); // length
  rdpNegReq.writeUInt32LE(PROTOCOL_SSL | PROTOCOL_HYBRID, 4); // requestedProtocols
  const x224 = Buffer.from([0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00]); // LI=6, CR, dst, src, class
  const tpktLen = 4 + x224.length + rdpNegReq.length;
  const tpkt = Buffer.from([0x03, 0x00, (tpktLen >> 8) & 0xff, tpktLen & 0xff]);
  return Buffer.concat([tpkt, x224, rdpNegReq]);
}

export type RdpNegResult =
  | { kind: "selected"; protocol: number }
  | { kind: "failure"; code: number };

/** Parse an X.224 Connection Confirm carrying an RDP negotiation response. */
export function parseX224ConnectionConfirm(buf: Buffer): RdpNegResult {
  if (buf.length < 15 || buf[0] !== 0x03 || buf[4] !== 0x06 || buf[5] !== 0xd0) {
    throw new Error("[rdp] malformed X.224 Connection Confirm");
  }
  const type = buf[11];
  if (type === 0x03) {
    return { kind: "failure", code: buf.readUInt32LE(15) };
  }
  if (type !== 0x02) throw new Error(`[rdp] unexpected negotiation type 0x${type.toString(16)}`);
  return { kind: "selected", protocol: buf.readUInt32LE(15) };
}

export function protocolName(p: number): string {
  switch (p) {
    case PROTOCOL_RDP:
      return "PROTOCOL_RDP (legacy standard security — no NLA)";
    case PROTOCOL_SSL:
      return "PROTOCOL_SSL (TLS, no NLA)";
    case PROTOCOL_HYBRID:
      return "PROTOCOL_HYBRID (NLA/CredSSP)";
    case PROTOCOL_HYBRID_EX:
      return "PROTOCOL_HYBRID_EX (NLA extended)";
    default:
      return `unknown(0x${p.toString(16)})`;
  }
}
