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
