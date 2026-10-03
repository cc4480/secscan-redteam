/**
 * host-exec v0.10.0 tests: WinRM listener probe (WS-010), NFS export
 * enumeration (LX-041), SSH agent-forwarding audit (LX-018/LX-019).
 *
 * ALL transports are mocked or loopback-only: fake HTTP(S) request
 * functions for the WinRM probe, tiny scripted RPC responders on
 * 127.0.0.1 for NFS (test infrastructure, not live targets), and a fake
 * SSH transport that records its args. No real hosts, no real credentials.
 *
 * Proven per module:
 *  - out-of-scope hosts are rejected BEFORE any connect attempt
 *  - the kill switch refuses new work
 *  - secrets never appear in summaries, output, or refusals
 *  - timeouts and abort signals terminate in-flight work
 *  - the fixed audit commands pass the destructive-command denylist
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import {
  HostExecutor,
  checkDestructive,
  probeWinrmListener,
  parseWwwAuthenticate,
  defaultWinrmProbeRequest,
  createNfsTransport,
  defaultNfsDial,
  parseRpcReply,
  XdrReader,
  xdrU32,
  xdrString,
  parseAgentSocketCheck,
  parseAgentAbusePath,
  resolveAgentSocketPath,
  SSH_AGENT_AUDIT_SOCKET_CHECK,
  SSH_AGENT_AUDIT_ABUSE_PATH,
} from "../src/host-exec/index.js";
import type {
  SshTransport,
  SshExecArgs,
  WinrmProbeRequestImpl,
  NfsTransport,
  NfsDialFn,
  NfsConnection,
} from "../src/host-exec/index.js";

const FAKE_ENV: NodeJS.ProcessEnv = {
  REDTEAM_SSH_USER: "testuser",
  REDTEAM_SSH_PASSWORD: "s3cr3t-pw-FOR-TESTS",
  REDTEAM_SSH_AGENT_SOCKET: "/tmp/fake-agent.sock",
};
const SECRET = "s3cr3t-pw-FOR-TESTS";
const SCOPE = ["10.9.0.12"];

// ---------------------------------------------------------------------------
// Fake SSH transport — records full args, never touches the network
// ---------------------------------------------------------------------------

function fakeSsh(
  behavior: { output?: string; hang?: boolean; fail?: string } = {},
): { t: SshTransport; seen: SshExecArgs[] } {
  const seen: SshExecArgs[] = [];
  const t: SshTransport = {
    async exec(args) {
      seen.push(args);
      if (args.signal?.aborted) throw new Error("[ssh] aborted by kill switch before exec");
      if (behavior.fail) throw new Error(behavior.fail);
      if (behavior.hang) {
        await new Promise<void>((_, reject) => {
          args.signal?.addEventListener("abort", () => reject(new Error("[ssh] aborted by kill switch")), {
            once: true,
          });
        });
      }
      return { stdout: behavior.output ?? "", stderr: "", code: 0, ms: 5 };
    },
    async close() {},
  };
  return { t, seen };
}

// ---------------------------------------------------------------------------
// WinRM listener probe (WS-010)
// ---------------------------------------------------------------------------

const fake401: WinrmProbeRequestImpl = async (req) => ({
  statusCode: 401,
  headers: {
    "www-authenticate": ["Negotiate", "NTLM"],
    server: "Microsoft-HTTPAPI/2.0",
  },
});

describe("winrm listener probe", () => {
  it("parses the 401 challenge into auth schemes and the server header", async () => {
    const results = await probeWinrmListener({ host: "10.9.0.12", requestImpl: fake401 });
    assert.equal(results.length, 2);
    assert.deepEqual(results[0], {
      port: 5985,
      reachable: true,
      useTls: false,
      authSchemes: ["Negotiate", "NTLM"],
      serverHeader: "Microsoft-HTTPAPI/2.0",
      note: "401 Unauthorized — WinRM listener present, advertising auth: Negotiate, NTLM",
    });
    assert.equal(results[1]!.port, 5986);
    assert.equal(results[1]!.useTls, true);
    assert.equal(results[1]!.reachable, true);
  });

  it("marks refused ports unreachable with a note, not an exception", async () => {
    const refused: WinrmProbeRequestImpl = async () => {
      throw new Error("connect ECONNREFUSED 10.9.0.12:5985");
    };
    const results = await probeWinrmListener({ host: "10.9.0.12", ports: [5985], requestImpl: refused });
    assert.equal(results.length, 1);
    assert.equal(results[0]!.reachable, false);
    assert.deepEqual(results[0]!.authSchemes, []);
    assert.match(results[0]!.note, /ECONNREFUSED/);
  });

  it("splits comma-joined WWW-Authenticate values and dedupes", () => {
    assert.deepEqual(parseWwwAuthenticate({ "www-authenticate": "Negotiate, NTLM, Negotiate" }), [
      "Negotiate",
      "NTLM",
    ]);
    assert.deepEqual(parseWwwAuthenticate({ "www-authenticate": "Basic realm=\"winrm\"" }), ["Basic"]);
    assert.deepEqual(parseWwwAuthenticate({}), []);
  });

  it("real HTTP 401 round-trip on loopback with the default request impl", async () => {
    const server = createServer((sock: Socket) => {
      sock.on("data", () => {
        sock.end(
          "HTTP/1.1 401 Unauthorized\r\n" +
            "WWW-Authenticate: Negotiate\r\n" +
            "WWW-Authenticate: NTLM\r\n" +
            "Server: Microsoft-HTTPAPI/2.0\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n\r\n",
        );
      });
    });
    await new Promise<void>((res) => server.listen(0, "127.0.0.1", res));
    const port = (server.address() as { port: number }).port;
    try {
      const res = await defaultWinrmProbeRequest({ host: "127.0.0.1", port, useTls: false, timeoutMs: 2000 });
      assert.equal(res.statusCode, 401);
      assert.deepEqual(parseWwwAuthenticate(res.headers), ["Negotiate", "NTLM"]);
      assert.equal(res.headers["server"], "Microsoft-HTTPAPI/2.0");
    } finally {
      server.close();
    }
  });

  it("default request impl times out per-port against a black hole", async () => {
    const server = createServer(() => {
      /* accept, never respond */
    });
    await new Promise<void>((res) => server.listen(0, "127.0.0.1", res));
    const port = (server.address() as { port: number }).port;
    try {
      await assert.rejects(
        defaultWinrmProbeRequest({ host: "127.0.0.1", port, useTls: false, timeoutMs: 100 }),
        /timed out/,
      );
    } finally {
      server.close();
    }
  });

  it("default request impl aborts via signal (destroys the request)", async () => {
    const server = createServer(() => {
      /* accept, never respond */
    });
    await new Promise<void>((res) => server.listen(0, "127.0.0.1", res));
    const port = (server.address() as { port: number }).port;
    try {
      const ctrl = new AbortController();
      const p = defaultWinrmProbeRequest({
        host: "127.0.0.1",
        port,
        useTls: false,
        timeoutMs: 5000,
        signal: ctrl.signal,
      });
      ctrl.abort();
      await assert.rejects(p, /abort/i);
    } finally {
      server.close();
    }
  });
});

describe("HostExecutor.winrmProbe", () => {
  it("rejects out-of-scope hosts before any request", async () => {
    let calls = 0;
    const counting: WinrmProbeRequestImpl = async (req) => {
      calls++;
      return fake401(req);
    };
    const ex = new HostExecutor({ env: FAKE_ENV });
    const r = await ex.winrmProbe({ host: "10.99.0.99", scopeHosts: SCOPE, requestImpl: counting });
    assert.equal(r.ok, false);
    assert.equal(r.transport, "winrm");
    assert.ok(r.refused?.includes("out of scope"), r.refused ?? "no refusal reason");
    assert.equal(calls, 0, "no request may be sent out of scope");
  });

  it("honors the kill switch", async () => {
    let calls = 0;
    const counting: WinrmProbeRequestImpl = async (req) => {
      calls++;
      return fake401(req);
    };
    const ex = new HostExecutor({ env: FAKE_ENV });
    ex.killSwitch.aborted = true;
    const r = await ex.winrmProbe({ host: "10.9.0.12", scopeHosts: SCOPE, requestImpl: counting });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("kill switch"));
    assert.equal(calls, 0);
  });

  it("needs no credentials — the probe is unauthenticated by design", async () => {
    const ex = new HostExecutor({ env: {} });
    const r = await ex.winrmProbe({ host: "10.9.0.12", scopeHosts: SCOPE, requestImpl: fake401 });
    assert.equal(r.ok, true);
    assert.match(r.summary, /2\/2 ports answered/);
    assert.match(r.summary, /Negotiate, NTLM/);
    assert.ok(r.output.includes("5985/plain: LISTENER"));
    assert.ok(r.output.includes("5986/tls: LISTENER"));
  });

  it("refuses an absurd port list", async () => {
    const ex = new HostExecutor({ env: FAKE_ENV });
    const r = await ex.winrmProbe({
      host: "10.9.0.12",
      scopeHosts: SCOPE,
      ports: Array.from({ length: 17 }, (_, i) => 5000 + i),
      requestImpl: fake401,
    });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("more than 16 ports"));
  });
});

// ---------------------------------------------------------------------------
// NFS export enumeration (LX-041) — scripted RPC responders on loopback
// ---------------------------------------------------------------------------

interface RpcCall {
  xid: number;
  prog: number;
  vers: number;
  proc: number;
  args: Buffer;
}

function rpcReply(xid: number, body: Buffer, acceptStatus = 0): Buffer {
  const head = Buffer.alloc(24);
  head.writeUInt32BE(xid, 0);
  head.writeUInt32BE(1, 4); // REPLY
  head.writeUInt32BE(0, 8); // MSG_ACCEPTED
  head.writeUInt32BE(0, 12); // verf flavor AUTH_NULL
  head.writeUInt32BE(0, 16); // verf length 0
  head.writeUInt32BE(acceptStatus, 20);
  return Buffer.concat([head, body]);
}

function withRecordMarking(payload: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h.writeUInt32BE((0x80000000 + payload.length) >>> 0, 0);
  return Buffer.concat([h, payload]);
}

function parseRpcCall(record: Buffer): RpcCall {
  const r = new XdrReader(record);
  const xid = r.u32();
  r.u32(); // CALL
  r.u32(); // rpcvers
  const prog = r.u32();
  const vers = r.u32();
  const proc = r.u32();
  r.u32(); // cred flavor
  r.skip(r.u32()); // cred body
  r.u32(); // verf flavor
  r.skip(r.u32()); // verf body
  return { xid, prog, vers, proc, args: r.rest() };
}

/** Scripted RPC server: reads record-marked calls, dispatches, writes replies. */
function scriptedRpcServer(dispatch: (call: RpcCall) => Buffer): Promise<{ server: Server; port: number }> {
  const server = createServer((sock: Socket) => {
    let buf = Buffer.alloc(0);
    sock.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 4) {
        const word = buf.readUInt32BE(0);
        const len = word & 0x7fffffff;
        if (buf.length < 4 + len) break;
        const record = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);
        if ((word & 0x80000000) === 0) continue; // no multi-fragment in our client
        try {
          sock.write(withRecordMarking(dispatch(parseRpcCall(record))));
        } catch {
          sock.destroy();
        }
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: (server.address() as { port: number }).port });
    });
  });
}

const SCRIPTED_EXPORTS = [
  { dirpath: "/data", groups: ["10.9.0.0/24", "10.9.0.13"] },
  { dirpath: "/home", groups: [] },
];

function encodeExportList(exports: { dirpath: string; groups: string[] }[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of exports) {
    parts.push(xdrU32(1), xdrString(e.dirpath));
    for (const g of e.groups) parts.push(xdrU32(1), xdrString(g));
    parts.push(xdrU32(0));
  }
  parts.push(xdrU32(0));
  return Buffer.concat(parts);
}

/** Portmapper GETPORT responder. Records the *requested mount version* (from args). */
function portmapperDispatch(
  mountdPort: number,
  v3Registered: boolean,
  seenVers: number[],
): (call: RpcCall) => Buffer {
  return (call) => {
    if (call.prog !== 100000 || call.proc !== 3) throw new Error("unexpected prog/proc");
    const r = new XdrReader(call.args);
    const prog = r.u32();
    const vers = r.u32();
    const prot = r.u32();
    seenVers.push(vers);
    const ok = prog === 100005 && prot === 6 && (vers === 1 || (vers === 3 && v3Registered));
    return rpcReply(call.xid, xdrU32(ok ? mountdPort : 0));
  };
}

/** Mountd EXPORT responder; v3Ok=false makes vers 3 fail with PROG_MISMATCH. */
function mountdDispatch(v3Ok: boolean, seen: RpcCall[]): (call: RpcCall) => Buffer {
  return (call) => {
    seen.push(call);
    if (call.prog !== 100005 || call.proc !== 5) throw new Error("unexpected prog/proc");
    if (call.vers === 3 && !v3Ok) return rpcReply(call.xid, Buffer.alloc(0), 2); // PROG_MISMATCH
    return rpcReply(call.xid, encodeExportList(SCRIPTED_EXPORTS));
  };
}

describe("nfs export enumeration (wire protocol on loopback)", () => {
  const servers: Server[] = [];
  afterEach(() => {
    for (const s of servers.splice(0)) s.close();
  });

  async function harness(opts: { pmV3: boolean; mountV3: boolean }): Promise<{
    dial: NfsDialFn;
    pmSeen: number[];
    mountSeen: RpcCall[];
  }> {
    const pmSeen: number[] = [];
    const mountSeen: RpcCall[] = [];
    const mount = await scriptedRpcServer(mountdDispatch(opts.mountV3, mountSeen));
    const pm = await scriptedRpcServer(portmapperDispatch(mount.port, opts.pmV3, pmSeen));
    servers.push(mount.server, pm.server);
    // Production dials the portmapper on 111; the test double remaps it to
    // the scripted portmapper. The mountd port comes from the GETPORT reply.
    const dial: NfsDialFn = (host, port, timeoutMs, signal) =>
      defaultNfsDial(host, port === 111 ? pm.port : port, timeoutMs, signal);
    return { dial, pmSeen, mountSeen };
  }

  it("enumerates exports via portmapper + mountd v3", async () => {
    const { dial, pmSeen, mountSeen } = await harness({ pmV3: true, mountV3: true });
    const t = createNfsTransport(dial);
    try {
      const exports = await t.enumerateExports({ host: "127.0.0.1", timeoutMs: 2000 });
      assert.deepEqual(exports, [
        { export: "/data", groups: ["10.9.0.0/24", "10.9.0.13"] },
        { export: "/home", groups: [] },
      ]);
      assert.ok(pmSeen.includes(3), "asked portmapper for mount v3");
      assert.ok(mountSeen.some((c) => c.vers === 3 && c.proc === 5), "called EXPORT v3");
    } finally {
      await t.close();
    }
  });

  it("falls back to mount v1 when v3 fails with PROG_MISMATCH", async () => {
    const { dial, mountSeen } = await harness({ pmV3: true, mountV3: false });
    const t = createNfsTransport(dial);
    try {
      const exports = await t.enumerateExports({ host: "127.0.0.1", timeoutMs: 2000 });
      assert.equal(exports.length, 2);
      assert.deepEqual(
        mountSeen.map((c) => c.vers),
        [3, 1],
        "tried v3 first, then fell back to v1",
      );
    } finally {
      await t.close();
    }
  });

  it("falls back to GETPORT v1 when mount v3 is not registered", async () => {
    const { dial, pmSeen } = await harness({ pmV3: false, mountV3: true });
    const t = createNfsTransport(dial);
    try {
      const exports = await t.enumerateExports({ host: "127.0.0.1", timeoutMs: 2000 });
      assert.equal(exports.length, 2);
      assert.deepEqual(pmSeen, [3, 1], "tried GETPORT v3 first, then v1");
    } finally {
      await t.close();
    }
  });

  it("throws (does not hang) on a truncated reply", async () => {
    const mount = await scriptedRpcServer(() => Buffer.from([0x00, 0x01])); // truncated record
    const pm = await scriptedRpcServer(
      portmapperDispatch(mount.port, true, []),
    );
    servers.push(mount.server, pm.server);
    const dial: NfsDialFn = (host, port, timeoutMs, signal) =>
      defaultNfsDial(host, port === 111 ? pm.port : port, timeoutMs, signal);
    const t = createNfsTransport(dial);
    try {
      await assert.rejects(t.enumerateExports({ host: "127.0.0.1", timeoutMs: 2000 }), /truncated/);
    } finally {
      await t.close();
    }
  });

  it("the RPC round-trip times out instead of hanging", async () => {
    const hangingConn: NfsConnection = {
      async write() {},
      readRecord() {
        return new Promise<Buffer>(() => undefined); // never resolves
      },
      close() {},
    };
    const dial: NfsDialFn = async () => hangingConn;
    const t = createNfsTransport(dial);
    // portmapper GETPORT itself hangs on readRecord → round-trip timeout
    await assert.rejects(
      t.enumerateExports({ host: "127.0.0.1", timeoutMs: 100 }),
      /timed out after 100ms/,
    );
    await t.close();
  });

  it("abort signal terminates an in-flight enumeration", async () => {
    // Mirrors the real SocketConnection: abort rejects pending reads.
    const dial: NfsDialFn = async (_h, _p, _t, signal) => {
      const hanging: NfsConnection = {
        async write() {},
        readRecord() {
          return new Promise<Buffer>((_, reject) => {
            signal?.addEventListener("abort", () => reject(new Error("[nfs] aborted by kill switch")), {
              once: true,
            });
          });
        },
        close() {},
      };
      return hanging;
    };
    const t = createNfsTransport(dial);
    const ctrl = new AbortController();
    const p = t.enumerateExports({ host: "127.0.0.1", timeoutMs: 5000, signal: ctrl.signal });
    setTimeout(() => ctrl.abort(), 20);
    await assert.rejects(p, /abort/i);
    await t.close();
  });

  it("default dial handles RPC record marking against real loopback TCP", async () => {
    const expected = Buffer.from("pong-payload");
    const server = createServer((sock: Socket) => {
      let buf = Buffer.alloc(0);
      sock.on("data", (d: Buffer) => {
        buf = Buffer.concat([buf, d]);
        while (buf.length >= 4) {
          const len = buf.readUInt32BE(0) & 0x7fffffff;
          if (buf.length < 4 + len) break;
          buf = buf.subarray(4 + len);
          sock.write(withRecordMarking(expected)); // echo one canned reply
        }
      });
    });
    await new Promise<void>((res) => server.listen(0, "127.0.0.1", res));
    servers.push(server);
    const port = (server.address() as { port: number }).port;
    const conn = await defaultNfsDial("127.0.0.1", port, 2000);
    try {
      await conn.write(Buffer.from("ping"));
      const rec = await conn.readRecord();
      assert.deepEqual(rec, expected);
    } finally {
      conn.close();
    }
  });
});

describe("XDR helpers", () => {
  it("round-trips u32 and strings with padding", () => {
    const b = Buffer.concat([xdrU32(0xdeadbeef), xdrString("hi"), xdrString("")]);
    const r = new XdrReader(b);
    assert.equal(r.u32(), 0xdeadbeef);
    assert.equal(r.str(), "hi");
    assert.equal(r.str(), "");
    assert.equal(r.rest().length, 0);
  });

  it("throws on truncated input instead of reading past the buffer", () => {
    assert.throws(() => new XdrReader(Buffer.from([0x00, 0x01])).u32(), /truncated/);
    assert.throws(
      () => new XdrReader(Buffer.concat([xdrU32(10), Buffer.from("ab")])).str(),
      /truncated/,
    );
  });

  it("parseRpcReply rejects failed calls with the accept status", () => {
    const reply = rpcReply(1234, Buffer.from("ok"), 2);
    assert.throws(() => parseRpcReply(reply, 1234), /accept status 2/);
    const good = parseRpcReply(rpcReply(1234, Buffer.from("ok")), 1234);
    assert.deepEqual(good, Buffer.from("ok"));
    assert.throws(() => parseRpcReply(rpcReply(9999, Buffer.alloc(0)), 1234), /xid mismatch/);
  });
});

describe("HostExecutor.nfsEnum", () => {
  function fakeNfs(exports: { export: string; groups: string[] }[] = []): { t: NfsTransport; calls: number } {
    let calls = 0;
    const t: NfsTransport = {
      async enumerateExports() {
        calls++;
        return exports;
      },
      async close() {},
    };
    return { t, calls };
  }

  it("rejects out-of-scope hosts before any dial", async () => {
    const { t, calls } = fakeNfs();
    const ex = new HostExecutor({ nfs: () => t, env: FAKE_ENV });
    const r = await ex.nfsEnum({ host: "10.99.0.99", scopeHosts: SCOPE });
    assert.equal(r.ok, false);
    assert.equal(r.transport, "nfs");
    assert.ok(r.refused?.includes("out of scope"), r.refused ?? "no refusal reason");
    assert.equal(calls, 0);
  });

  it("honors the kill switch", async () => {
    const { t, calls } = fakeNfs();
    const ex = new HostExecutor({ nfs: () => t, env: FAKE_ENV });
    ex.killSwitch.aborted = true;
    const r = await ex.nfsEnum({ host: "10.9.0.12", scopeHosts: SCOPE });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("kill switch"));
    assert.equal(calls, 0);
  });

  it("needs no credentials and reports the export list", async () => {
    const { t } = fakeNfs([
      { export: "/data", groups: ["10.9.0.0/24"] },
      { export: "/home", groups: [] },
    ]);
    const ex = new HostExecutor({ nfs: () => t, env: {} });
    const r = await ex.nfsEnum({ host: "10.9.0.12", scopeHosts: SCOPE });
    assert.equal(r.ok, true);
    assert.equal(r.transport, "nfs");
    assert.match(r.summary, /2 export\(s\) enumerated/);
    assert.ok(r.output.includes("/data  [10.9.0.0/24]"));
    assert.ok(r.output.includes("/home  [no group restriction listed]"));
  });

  it("reports transport failures without leaking anything", async () => {
    const t: NfsTransport = {
      async enumerateExports() {
        throw new Error("portmapper unreachable");
      },
      async close() {},
    };
    const ex = new HostExecutor({ nfs: () => t, env: FAKE_ENV });
    const r = await ex.nfsEnum({ host: "10.9.0.12", scopeHosts: SCOPE });
    assert.equal(r.ok, false);
    assert.match(r.summary, /enumeration failed/);
    assert.ok(!r.summary.includes(SECRET) && !r.output.includes(SECRET));
  });

  it("times out a hanging transport (executor backstop)", async () => {
    const t: NfsTransport = {
      async enumerateExports() {
        await new Promise(() => undefined); // never resolves, ignores signal
        throw new Error("unreachable");
      },
      async close() {},
    };
    const ex = new HostExecutor({ nfs: () => t, env: FAKE_ENV });
    const r = await ex.nfsEnum({ host: "10.9.0.12", scopeHosts: SCOPE, timeoutMs: 50 });
    assert.equal(r.ok, false);
    assert.match(r.summary, /timed out/);
  });
});

// ---------------------------------------------------------------------------
// SSH agent-forwarding audit (LX-018/LX-019)
// ---------------------------------------------------------------------------

const SOCKET_CHECK_PRESENT = [
  "SOCK=/tmp/ssh-abc/agent.123",
  "SOCK_PRESENT",
  "srwxr-xr-x 1 testuser testuser 0 Oct  3 00:00 /tmp/ssh-abc/agent.123",
  "owner=testuser group=testuser mode=700",
].join("\n");

const SOCKET_CHECK_ABSENT = ["SOCK=", "SOCK_ABSENT"].join("\n");

const ABUSE_PATH_REACHABLE = [
  "uid=1000(testuser) gid=1000(testuser) groups=1000(testuser),27(sudo)",
  "srwx------ 1 testuser testuser 0 Oct  3 00:00 /tmp/ssh-abc/agent.123",
  "testuser testuser 700",
].join("\n");

const ABUSE_PATH_NOT_REACHABLE = [
  "uid=1001(other) gid=1001(other) groups=1001(other)",
  "srwx------ 1 testuser testuser 0 Oct  3 00:00 /tmp/ssh-abc/agent.123",
  "testuser testuser 700",
].join("\n");

describe("ssh agent-forwarding audit", () => {
  it("fixed audit commands pass the destructive denylist", () => {
    assert.equal(checkDestructive(SSH_AGENT_AUDIT_SOCKET_CHECK), null);
    assert.equal(checkDestructive(SSH_AGENT_AUDIT_ABUSE_PATH), null);
  });

  it("resolves the agent socket from REDTEAM_SSH_AGENT_SOCKET, then SSH_AUTH_SOCK", () => {
    assert.equal(resolveAgentSocketPath({ REDTEAM_SSH_AGENT_SOCKET: "/tmp/a.sock" }), "/tmp/a.sock");
    assert.equal(resolveAgentSocketPath({ SSH_AUTH_SOCK: "/tmp/b.sock" }), "/tmp/b.sock");
    assert.throws(() => resolveAgentSocketPath({}), /REDTEAM_SSH_AGENT_SOCKET/);
  });

  it("passes agentForward:true and the socket path through to the transport", async () => {
    const { t, seen } = fakeSsh({ output: SOCKET_CHECK_PRESENT });
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshAgentAudit({ host: "10.9.0.12", mode: "socket-check", scopeHosts: SCOPE });
    assert.equal(r.ok, true);
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.agentForward, true);
    assert.equal(seen[0]!.agentSocketPath, "/tmp/fake-agent.sock");
    assert.equal(seen[0]!.command, SSH_AGENT_AUDIT_SOCKET_CHECK);
  });

  it("socket-check reports a present socket with owner/group/mode", async () => {
    const { t } = fakeSsh({ output: SOCKET_CHECK_PRESENT });
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshAgentAudit({ host: "10.9.0.12", mode: "socket-check", scopeHosts: SCOPE });
    assert.match(r.summary, /PRESENT/);
    assert.match(r.summary, /\/tmp\/ssh-abc\/agent\.123/);
    assert.match(r.summary, /mode=700/);
    assert.ok(r.output.includes("socketPresent=true"));
    assert.ok(!r.summary.includes(SECRET) && !r.output.includes(SECRET));
  });

  it("socket-check reports an absent socket", async () => {
    const { t } = fakeSsh({ output: SOCKET_CHECK_ABSENT });
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshAgentAudit({ host: "10.9.0.12", mode: "socket-check", scopeHosts: SCOPE });
    assert.match(r.summary, /ABSENT/);
    assert.ok(r.output.includes("socketPresent=false"));
  });

  it("abuse-path reports REACHABLE when the session user owns the socket", async () => {
    const { t, seen } = fakeSsh({ output: ABUSE_PATH_REACHABLE });
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshAgentAudit({ host: "10.9.0.12", mode: "abuse-path", scopeHosts: SCOPE });
    assert.equal(seen[0]!.command, SSH_AGENT_AUDIT_ABUSE_PATH);
    assert.match(r.summary, /REACHABLE/);
    assert.match(r.summary, /owner \(testuser\)/);
    assert.ok(r.output.includes("ANALYSIS ONLY"));
  });

  it("abuse-path reports not reachable for an unrelated user", async () => {
    const { t } = fakeSsh({ output: ABUSE_PATH_NOT_REACHABLE });
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshAgentAudit({ host: "10.9.0.12", mode: "abuse-path", scopeHosts: SCOPE });
    assert.match(r.summary, /not reachable/);
    assert.match(r.summary, /via other/);
  });

  it("refuses fast with an actionable error when no agent socket is configured", async () => {
    const { t, seen } = fakeSsh();
    const env: NodeJS.ProcessEnv = { REDTEAM_SSH_USER: "testuser", REDTEAM_SSH_PASSWORD: "x" };
    const ex = new HostExecutor({ ssh: () => t, env });
    const r = await ex.sshAgentAudit({ host: "10.9.0.12", mode: "socket-check", scopeHosts: SCOPE });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("REDTEAM_SSH_AGENT_SOCKET"), r.refused ?? "no refusal reason");
    assert.equal(seen.length, 0, "transport must never be touched");
  });

  it("rejects out-of-scope hosts before connecting", async () => {
    const { t, seen } = fakeSsh();
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshAgentAudit({ host: "10.99.0.99", mode: "socket-check", scopeHosts: SCOPE });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("out of scope"));
    assert.equal(seen.length, 0);
  });

  it("honors the kill switch", async () => {
    const { t, seen } = fakeSsh();
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    ex.killSwitch.aborted = true;
    const r = await ex.sshAgentAudit({ host: "10.9.0.12", mode: "abuse-path", scopeHosts: SCOPE });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("kill switch"));
    assert.equal(seen.length, 0);
  });

  it("redacts secrets from failure summaries", async () => {
    const { t } = fakeSsh({ fail: `auth failed for testuser with ${SECRET}` });
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshAgentAudit({ host: "10.9.0.12", mode: "socket-check", scopeHosts: SCOPE });
    assert.equal(r.ok, false);
    assert.ok(!r.summary.includes(SECRET), r.summary);
    assert.ok(r.summary.includes("[REDACTED]"));
  });

  it("times out a hanging transport (executor backstop)", async () => {
    const { t } = fakeSsh({ hang: true });
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshAgentAudit({ host: "10.9.0.12", mode: "socket-check", scopeHosts: SCOPE, timeoutMs: 50 });
    assert.equal(r.ok, false);
    assert.match(r.summary, /timed out/);
  });
});

describe("agent-audit output parsing (pure functions)", () => {
  it("parseAgentSocketCheck handles present and absent", () => {
    const p = parseAgentSocketCheck(SOCKET_CHECK_PRESENT);
    assert.match(p.summary, /PRESENT/);
    assert.match(p.detail, /socketPresent=true/);
    const a = parseAgentSocketCheck(SOCKET_CHECK_ABSENT);
    assert.match(a.summary, /ABSENT/);
    assert.match(a.detail, /socketPresent=false/);
  });

  it("parseAgentAbusePath handles unparseable stat output honestly", () => {
    const p = parseAgentAbusePath("uid=1000(testuser) gid=1000(testuser) groups=1000(testuser)\n");
    assert.match(p.summary, /could not determine reachability/);
  });

  it("parseAgentAbusePath grants group reachability via the group write bit", () => {
    const out = [
      "uid=1000(testuser) gid=1000(testuser) groups=1000(testuser),50(staff)",
      "srwxrwx--- 1 root staff 0 Oct  3 00:00 /tmp/ssh-abc/agent.123",
      "root staff 770",
    ].join("\n");
    const p = parseAgentAbusePath(out);
    assert.match(p.summary, /REACHABLE/);
    assert.match(p.summary, /group \(staff\)/);
  });
});
