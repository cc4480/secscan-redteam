// ---------------------------------------------------------------------------
// ONC RPC framing (RFC 1831)
// ---------------------------------------------------------------------------

import { XdrReader } from "./xdr.js";


let xidCounter = (Math.random() * 0xffffffff) >>> 0;

export function rpcCall(prog: number, vers: number, proc: number, args: Buffer): Buffer {
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

export function rpcXid(call: Buffer): number {
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
