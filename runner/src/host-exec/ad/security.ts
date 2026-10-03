// ---------------------------------------------------------------------------
// Binary security descriptor parsing (no Windows API needed)
// ---------------------------------------------------------------------------

const RIGHT_GENERIC_ALL = 0x10000000;
const RIGHT_WRITE_DAC = 0x00040000;
const RIGHT_WRITE_OWNER = 0x00080000;
const RIGHT_ENROLL = 0x00000100; // CERTDB enroll extended-right mask bit used in template ACE scans
const ACE_ACCESS_ALLOWED = 0x00;

export interface DangerousAce {
  targetDn: string;
  granteeSid: string;
  rights: string[];
  mask: number;
}

export function parseSid(buf: Buffer, offset: number): { sid: string; next: number } {
  const rev = buf[offset];
  const count = buf[offset + 1];
  const auth = buf.readUIntBE(offset + 2, 6); // 48-bit identifier authority, big-endian
  const parts: number[] = [];
  for (let i = 0; i < count; i++) parts.push(buf.readUInt32LE(offset + 8 + i * 4));
  return { sid: `S-${rev}-${auth}-${parts.join("-")}`, next: offset + 8 + count * 4 };
}

/**
 * Parse a BINARY security descriptor (base64) and return ACEs granting
 * dangerous rights. Pure function — tested directly.
 */
export function findDangerousAces(dn: string, sdB64: string): DangerousAce[] {
  const out: DangerousAce[] = [];
  let sd: Buffer;
  try {
    sd = Buffer.from(sdB64, "base64");
  } catch {
    return out;
  }
  if (sd.length < 20) return out;
  const daclOff = sd.readUInt32LE(16);
  if (daclOff === 0 || daclOff + 8 > sd.length) return out;
  const aceCount = sd.readUInt16LE(daclOff + 2);
  let p = daclOff + 8;
  for (let i = 0; i < aceCount && p + 8 <= sd.length; i++) {
    const type = sd[p];
    const size = sd.readUInt16LE(p + 2);
    if (size < 8 || p + size > sd.length) break;
    if (type === ACE_ACCESS_ALLOWED) {
      const mask = sd.readUInt32LE(p + 4);
      const rights: string[] = [];
      if (mask & RIGHT_GENERIC_ALL) rights.push("GenericAll");
      if (mask & RIGHT_WRITE_DAC) rights.push("WriteDacl");
      if (mask & RIGHT_WRITE_OWNER) rights.push("WriteOwner");
      if (mask & RIGHT_ENROLL) rights.push("Enroll");
      if (rights.length > 0) {
        const { sid } = parseSid(sd, p + 8);
        out.push({ targetDn: dn, granteeSid: sid, rights, mask });
      }
    }
    p += size;
  }
  return out;
}

/** Well-known low-privilege SIDs that must never hold dangerous rights. */
export function isLowPrivSid(sid: string, domainSid: string): boolean {
  const low = [
    "S-1-1-0", // Everyone
    "S-1-5-11", // Authenticated Users
    `${domainSid}-513`, // Domain Users
    `${domainSid}-515`, // Domain Computers
  ];
  return low.includes(sid);
}

/** Tier-0 SIDs: never flagged as findings when they hold dangerous rights. */
export function isTier0Sid(sid: string, domainSid: string): boolean {
  if (sid === "S-1-5-18" || sid === "S-1-5-19" || sid === "S-1-5-20") return true; // SYSTEM / LocalService / NetworkService
  for (const rid of ["-500", "-512", "-518", "-519", "-520"]) {
    if (sid === `${domainSid}${rid}`) return true;
  }
  return false;
}
