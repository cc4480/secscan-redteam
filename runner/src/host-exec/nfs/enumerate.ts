// ---------------------------------------------------------------------------
// Portmapper + mountd
// ---------------------------------------------------------------------------

import { HOST_EXEC_TIMEOUT_MS } from "../common.js";
import { XdrReader, xdrU32, xdrString } from "./xdr.js";
import { rpcCall, rpcXid, parseRpcReply, RpcAcceptError, RPC_PROG_MISMATCH } from "./rpc.js";
import { defaultNfsDial, type NfsConnection, type NfsDialFn } from "./connection.js";


const PORTMAPPER_PORT = 111;
const PORTMAPPER_PROG = 100000;
const MOUNT_PROG = 100005;
const PROTO_TCP = 6;

async function rpcRoundTrip(
  conn: NfsConnection,
  call: Buffer,
  timeoutMs: number,
): Promise<Buffer> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const p = (async () => {
      await conn.write(call);
      return conn.readRecord();
    })();
    const winner = await Promise.race([
      p,
      new Promise<Buffer>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`[nfs] RPC round-trip timed out after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
    return parseRpcReply(winner, rpcXid(call));
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Portmapper GETPORT for the mount daemon; tries mount vers 3, then vers 1. */
async function getMountdPort(
  dial: NfsDialFn,
  host: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<number> {
  const conn = await dial(host, PORTMAPPER_PORT, timeoutMs, signal);
  try {
    for (const vers of [3, 1]) {
      const args = Buffer.concat([xdrU32(MOUNT_PROG), xdrU32(vers), xdrU32(PROTO_TCP), xdrU32(0)]);
      const body = await rpcRoundTrip(conn, rpcCall(PORTMAPPER_PROG, 2, 3, args), timeoutMs);
      const port = new XdrReader(body).u32();
      if (port !== 0) return port;
    }
    throw new Error("[nfs] mountd not registered with the portmapper (vers 3 and 1)");
  } finally {
    conn.close();
  }
}

export interface NfsExport {
  export: string;
  groups: string[];
}

function parseExportList(body: Buffer): NfsExport[] {
  const r = new XdrReader(body);
  const out: NfsExport[] = [];
  while (r.u32() !== 0) {
    // exportnode: value_follows, dirpath, groups
    const dirpath = r.str();
    const groups: string[] = [];
    while (r.u32() !== 0) {
      // groupnode: value_follows, name
      groups.push(r.str());
    }
    out.push({ export: dirpath, groups });
  }
  return out;
}

export interface NfsEnumerateArgs {
  host: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** Structural interface so tests inject a fake (no network). */
export interface NfsTransport {
  enumerateExports(args: NfsEnumerateArgs): Promise<NfsExport[]>;
  close(): Promise<void>;
}

export function createNfsTransport(dial: NfsDialFn = defaultNfsDial): NfsTransport {
  const open = new Set<NfsConnection>();
  const track = (c: NfsConnection): NfsConnection => {
    open.add(c);
    return c;
  };

  return {
    async enumerateExports(args: NfsEnumerateArgs): Promise<NfsExport[]> {
      if (args.signal?.aborted) throw new Error("[nfs] aborted by kill switch before enumerate");
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;

      const mountdPort = await getMountdPort(dial, args.host, timeoutMs, args.signal);
      const conn = track(await dial(args.host, mountdPort, timeoutMs, args.signal));
      try {
        // EXPORT is proc 5 in both mount v3 and v1. Try v3 first; fall back
        // to v1 on PROG_UNAVAIL / PROG_MISMATCH (daemon too old for v3).
        let lastErr: unknown = null;
        for (const vers of [3, 1]) {
          try {
            const body = await rpcRoundTrip(conn, rpcCall(MOUNT_PROG, vers, 5, Buffer.alloc(0)), timeoutMs);
            return parseExportList(body);
          } catch (err) {
            lastErr = err;
            const accept = err instanceof RpcAcceptError ? err.acceptStatus : -1;
            if (vers === 3 && (accept === 1 || accept === RPC_PROG_MISMATCH)) continue; // try v1
            throw err;
          }
        }
        throw lastErr;
      } finally {
        open.delete(conn);
        conn.close();
      }
    },

    async close(): Promise<void> {
      for (const c of open) {
        try {
          c.close();
        } catch {
          /* best effort */
        }
      }
      open.clear();
    },
  };
}
