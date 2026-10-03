/**
 * NFS export enumeration (battery LX-041) — pure-Node userland RPC.
 *
 * NO KERNEL MOUNT, by design: mounting needs privileges (CAP_SYS_ADMIN /
 * root) the runner will not assume, and a mount changes target-side state.
 * The export list IS the executable evidence — it answers "which
 * filesystems does this host offer to whom" without touching them.
 *
 * Wire protocol, from scratch (no new dependencies):
 *   1. TCP to the target's portmapper (port 111), ONC RPC call
 *      GETPORT (prog 100000, vers 2, proc 3) for the mount daemon
 *      (prog 100005), TCP (proto 6). Falls back to asking for mountd
 *      vers 1 when vers 3 is not registered.
 *   2. TCP to the returned mountd port, RPC MOUNT prog 100005 proc 5
 *      (EXPORT, no arguments) — try vers 3 first, fall back to vers 1 on
 *      PROG_UNAVAIL / PROG_MISMATCH.
 *   3. Parse the export linked list (dirpath + per-export group list).
 *
 * XDR is encoded/decoded by hand with tiny total helpers (they throw on
 * truncated input rather than reading past the buffer). RPC-over-TCP
 * record marking (RFC 1831 §10) is handled on both write and read.
 *
 * Timeouts bound every dial and every round-trip; an AbortSignal destroys
 * in-flight sockets. Everything fails closed.
 */

/**
 * NFS export enumeration (see above) — split into submodules
 * (public export surface unchanged):
 *  - nfs/xdr.ts        — tiny total XDR helpers
 *  - nfs/rpc.ts        — ONC RPC framing + reply parsing (RFC 1831)
 *  - nfs/connection.ts — TCP connection with RPC record-marking I/O
 *  - nfs/enumerate.ts  — portmapper + mountd export enumeration (LX-041)
 */
export { XdrReader, xdrU32, xdrString } from "./nfs/xdr.js";
export { parseRpcReply, RpcAcceptError, RPC_PROG_MISMATCH } from "./nfs/rpc.js";
export { defaultNfsDial, type NfsConnection, type NfsDialFn } from "./nfs/connection.js";
export {
  createNfsTransport,
  type NfsTransport,
  type NfsExport,
  type NfsEnumerateArgs,
} from "./nfs/enumerate.js";
