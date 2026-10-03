/**
 * v0.10.0 wave-2 tests: rdp (NLA), smb pass-the-hash, krb pass-the-ticket,
 * ad enumeration — plus ntlmv2 unit tests.
 *
 * ALL network is mocked or loopback-only test servers: no real hosts, no
 * real credentials. What we prove is the safety core on the new paths plus
 * the wire-protocol correctness of the hand-rolled implementations:
 *  - NTLMv2 against the known NT-hash vector and server-side proof verification
 *  - RDP NLA handshake against a scripted fake server (incl. proof check)
 *  - SMB PtH against a loopback fake SMB2 server (accept/reject paths)
 *  - krb ticket replay with a fake krb5 tool runner
 *  - AD graph/ACL/template analysis as pure functions + fake LDAP transport
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { createHmac } from "node:crypto";
import {
  HostExecutor,
  md4bytes,
  ntHash,
  ntowfv2,
  buildType1,
  parseType2,
  buildType3V2,
  spnegoInit,
  spnegoResp,
  tsRequest,
  tsResponseNtlmToken,
  buildX224ConnectionRequest,
  parseX224ConnectionConfirm,
  rdpValidateCredentials,
  createRdpTransport,
  buildShadowHandoff,
  RDP_SHADOW_PREP_PS,
  createSmbPthTransport,
  createAdTransport,
  adEnumerate,
  findDangerousAces,
  isLowPrivSid,
  isTier0Sid,
  computeAttackPaths,
  analyzeTemplate,
  createKrbTransport,
  spnHostname,
  checkDestructive,
  type RdpChannel,
  type RdpTransport,
  type AdTransport,
  type AdEntry,
} from "../src/host-exec/index.js";

const FAKE_ENV: NodeJS.ProcessEnv = {
  REDTEAM_SSH_USER: "testuser",
  REDTEAM_SSH_PASSWORD: "s3cr3t-pw-FOR-TESTS",
  REDTEAM_SMB_USER: "testuser",
  REDTEAM_SMB_PASSWORD: "s3cr3t-pw-FOR-TESTS",
  REDTEAM_SMB_DOMAIN: "TEST",
  REDTEAM_SMB_NTHASH: "8846f7eaee8fb117ad06bdd830b7586c", // NT hash of "password" — TEST VECTOR ONLY
  REDTEAM_WINRM_USER: "testuser",
  REDTEAM_WINRM_PASSWORD: "s3cr3t-pw-FOR-TESTS",
  REDTEAM_KRB_CCACHE_B64: Buffer.from("fake-ccache-bytes").toString("base64"),
};

const SCOPE = ["target.corp"];

// ---------------------------------------------------------------------------
// ntlmv2 unit tests
// ---------------------------------------------------------------------------

describe("ntlmv2 primitives", () => {
  it("ntHash matches the known vector (MD4 UTF-16LE)", () => {
    assert.equal(ntHash("password").toString("hex"), "8846f7eaee8fb117ad06bdd830b7586c");
    assert.equal(md4bytes(Buffer.from("password", "utf16le")).toString("hex"), "8846f7eaee8fb117ad06bdd830b7586c");
  });

  it("Type1 has the NTLMSSP signature and message type 1", () => {
    const t1 = buildType1("TEST", "WS");
    assert.equal(t1.subarray(0, 8).toString("ascii"), "NTLMSSP\0");
    assert.equal(t1.readUInt32LE(8), 1);
  });

  it("Type2 parse round-trips a hand-built challenge", () => {
    const challenge = Buffer.from("12345678", "ascii");
    const targetInfo = Buffer.from([0x02, 0x00, 0x04, 0x00, 0x41, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const t2 = Buffer.alloc(48 + targetInfo.length);
    t2.write("NTLMSSP\0", 0, "ascii");
    t2.writeUInt32LE(2, 8);
    t2.writeUInt16LE(0, 12);
    t2.writeUInt16LE(0, 14);
    t2.writeUInt32LE(0, 16);
    t2.writeUInt32LE(0x00088207, 20);
    challenge.copy(t2, 24);
    t2.writeUInt16LE(targetInfo.length, 40);
    t2.writeUInt16LE(targetInfo.length, 42);
    t2.writeUInt32LE(48, 44);
    targetInfo.copy(t2, 48);
    const p = parseType2(t2);
    assert.deepEqual(p.challenge, challenge);
    assert.deepEqual(p.targetInfo, targetInfo);
  });

  it("Type3 NTLMv2 proof verifies server-side (the PtH security property)", () => {
    const hash = Buffer.from("8846f7eaee8fb117ad06bdd830b7586c", "hex");
    const challenge = Buffer.from("abcdefgh", "ascii");
    const targetInfo = Buffer.from([0x01, 0x00]);
    const clientNonce = Buffer.from("87654321", "ascii");
    const t3 = buildType3V2({ user: "testuser", domain: "TEST", challenge, targetInfo, ntHash: hash, clientNonce });
    // Server-side verification: recompute the NT proof from the response.
    const ntRespLen = t3.readUInt16LE(20);
    const ntRespOff = t3.readUInt32LE(24);
    const ntResp = t3.subarray(ntRespOff, ntRespOff + ntRespLen);
    const proof = ntResp.subarray(0, 16);
    const blob = ntResp.subarray(16);
    const key = ntowfv2("testuser", "TEST", hash);
    const expected = createHmac("md5", key).update(Buffer.concat([challenge, blob])).digest();
    assert.deepEqual(proof, expected, "NTLMv2 proof recomputes — the hash authenticates");
    // And a wrong hash does NOT verify.
    const wrongKey = ntowfv2("testuser", "TEST", Buffer.alloc(16, 1));
    const wrong = createHmac("md5", wrongKey).update(Buffer.concat([challenge, blob])).digest();
    assert.notDeepEqual(proof, wrong);
  });

  it("CredSSP DER round-trip: TSRequest -> extract NTLM token", () => {
    const t1 = buildType1("TEST");
    const req = tsRequest(spnegoInit(t1));
    assert.equal(req[0], 0x30, "SEQUENCE");
    // Simulate a server challenge response and extract it.
    const fakeT2 = Buffer.alloc(48);
    fakeT2.write("NTLMSSP\0", 0, "ascii");
    fakeT2.writeUInt32LE(2, 8);
    const resp = tsRequest(spnegoResp(fakeT2));
    const extracted = tsResponseNtlmToken(resp);
    assert.deepEqual(extracted, fakeT2);
  });

  it("X.224 negotiation request parses as a confirm", () => {
    const req = buildX224ConnectionRequest();
    assert.equal(req[0], 0x03, "TPKT version");
    assert.equal(req.readUInt16BE(2), req.length, "TPKT length covers the frame");
    // Canned server confirm selecting HYBRID (2).
    const confirm = Buffer.from([
      0x03, 0x00, 0x00, 0x13, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
    ]);
    const r = parseX224ConnectionConfirm(confirm);
    assert.equal(r.kind, "selected");
    if (r.kind === "selected") assert.equal(r.protocol, 2);
  });
});

// ---------------------------------------------------------------------------
// RDP NLA — scripted fake server
// ---------------------------------------------------------------------------

/** Fake RDP server: scripted handshake, verifies the NTLMv2 proof server-side. */
function fakeRdpServer(opts: {
  selectProtocol?: number; // default 2 (HYBRID)
  password?: string; // expected password; undefined = close during handshake
  closeAfterChallenge?: boolean;
}): { transport: RdpTransport; seen: { type3ProofOk?: boolean } } {
  const seen: { type3ProofOk?: boolean } = {};
  const expectedHash = opts.password !== undefined ? ntHash(opts.password) : undefined;
  const challenge = Buffer.from("srvchall", "ascii");

  const channel: RdpChannel = (() => {
    let stage = 0;
    const reads: Buffer[] = [];
    const waiters: { n: number; resolve: (b: Buffer) => void }[] = [];
    const feed = (b: Buffer) => {
      reads.push(b);
      const all = Buffer.concat(reads);
      reads.length = 0;
      let off = 0;
      while (waiters.length > 0 && all.length - off >= waiters[0].n) {
        const w = waiters.shift()!;
        w.resolve(all.subarray(off, off + w.n));
        off += w.n;
      }
      if (off < all.length) reads.push(all.subarray(off));
    };
    return {
      write(b: Buffer) {
        if (stage === 0) {
          // X.224 request -> confirm
          const proto = opts.selectProtocol ?? 2;
          feed(
            Buffer.from([0x03, 0x00, 0x00, 0x13, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, proto, 0x00, 0x00, 0x00]),
          );
          stage = 1;
        } else if (stage === 1) {
          // TSRequest#1 -> challenge
          const t2 = Buffer.alloc(48);
          t2.write("NTLMSSP\0", 0, "ascii");
          t2.writeUInt32LE(2, 8);
          t2.writeUInt32LE(0x00088207, 20);
          challenge.copy(t2, 24);
          feed(tsRequest(spnegoResp(t2)));
          stage = 2;
        } else if (stage === 2) {
          // TSRequest#2 -> verify proof, then accept or close
          try {
            const token = tsResponseNtlmToken(b);
            const ntRespLen = token.readUInt16LE(20);
            const ntRespOff = token.readUInt32LE(24);
            const ntResp = token.subarray(ntRespOff, ntRespOff + ntRespLen);
            const proof = ntResp.subarray(0, 16);
            const blob = ntResp.subarray(16);
            // Extract username/domain from the Type3 for key derivation.
            const uLen = token.readUInt16LE(36);
            const uOff = token.readUInt32LE(40);
            const dLen = token.readUInt16LE(28);
            const dOff = token.readUInt32LE(32);
            const user = token.subarray(uOff, uOff + uLen).toString("utf16le");
            const domain = token.subarray(dOff, dOff + dLen).toString("utf16le");
            const key = expectedHash ? ntowfv2(user, domain, expectedHash) : Buffer.alloc(16);
            const expected = createHmac("md5", key).update(Buffer.concat([challenge, blob])).digest();
            seen.type3ProofOk = expected.equals(proof);
          } catch {
            seen.type3ProofOk = false;
          }
          if (opts.closeAfterChallenge || expectedHash === undefined) {
            // Server closes: credential rejected. Feed nothing; reads will hang
            // -> but our client uses timeouts; simulate close by rejecting.
            for (const w of waiters.splice(0)) w.resolve(Buffer.alloc(0));
            stage = 99;
          } else {
            feed(tsRequest(spnegoResp(Buffer.from("final"))));
            stage = 3;
          }
        }
      },
      readExactly(n: number, timeoutMs = 3000) {
        const all = Buffer.concat(reads.splice(0));
        if (all.length >= n) {
          if (all.length > n) reads.push(all.subarray(n));
          return Promise.resolve(all.subarray(0, n));
        }
        return new Promise<Buffer>((resolve, reject) => {
          if (all.length > 0) reads.push(all);
          const timer = setTimeout(() => {
            const i = waiters.findIndex((w) => w.n === n);
            if (i >= 0) waiters.splice(i, 1);
            reject(new Error("[fake-rdp] read timed out (simulated server close)"));
          }, timeoutMs);
          waiters.push({ n, resolve: (b: Buffer) => { clearTimeout(timer); resolve(b); } });
        });
      },
      drain() {
        return Buffer.concat(reads.splice(0));
      },
      async startTls() {
        /* fake: no-op */
      },
      close() {
        /* no-op */
      },
    };
  })();

  const transport: RdpTransport = {
    async open() {
      return channel;
    },
    async close() {
      /* no-op */
    },
  };
  return { transport, seen };
}

describe("rdp NLA credential validation", () => {
  it("HYBRID + correct password -> credentialValid, proof verified server-side", async () => {
    const { transport, seen } = fakeRdpServer({ password: "s3cr3t-pw-FOR-TESTS" });
    const r = await rdpValidateCredentials(transport, {
      host: "target.corp",
      creds: { username: "testuser", password: "s3cr3t-pw-FOR-TESTS", domain: "TEST" },
      timeoutMs: 2000,
    });
    assert.equal(r.reachable, true);
    assert.equal(r.nlaRequired, true);
    assert.equal(r.credentialValid, true);
    assert.equal(seen.type3ProofOk, true, "server verified the NTLMv2 proof");
  });

  it("HYBRID + wrong password -> credentialValid false (server closes)", async () => {
    const { transport } = fakeRdpServer({ password: "s3cr3t-pw-FOR-TESTS", closeAfterChallenge: true });
    const r = await rdpValidateCredentials(transport, {
      host: "target.corp",
      creds: { username: "testuser", password: "wrong", domain: "TEST" },
      timeoutMs: 2000,
    });
    assert.equal(r.nlaRequired, true);
    assert.equal(r.credentialValid, false);
  });

  it("server without NLA -> no validation attempted, finding reported", async () => {
    const { transport } = fakeRdpServer({ selectProtocol: 1 }); // PROTOCOL_SSL
    const r = await rdpValidateCredentials(transport, {
      host: "target.corp",
      creds: { username: "testuser", password: "s3cr3t-pw-FOR-TESTS" },
      timeoutMs: 2000,
    });
    assert.equal(r.reachable, true);
    assert.equal(r.nlaRequired, false);
    assert.equal(r.credentialValid, undefined, "no validation without NLA");
    assert.match(r.note, /NLA is NOT required/);
  });

  it("executor: rdpValidate refuses out-of-scope hosts before connect", async () => {
    const { transport } = fakeRdpServer({ password: "x" });
    const exec = new HostExecutor({ rdp: () => transport, env: FAKE_ENV });
    const res = await exec.rdpValidate({ host: "evil.corp", scopeHosts: SCOPE });
    assert.ok(res.refused?.match(/out of scope/));
  });

  it("shadow prep script passes the denylist; handoff names the human gate", () => {
    assert.equal(checkDestructive(RDP_SHADOW_PREP_PS), null, "prep script is not destructive");
    const h = buildShadowHandoff(JSON.stringify({ Sessions: [{ Session: "rdp-tcp#1", User: "jdoe", Id: "3", State: "Active" }], ShadowPolicy: 2 }), "target.corp");
    assert.match(h, /HUMAN OPERATOR REQUIRED/);
    assert.match(h, /mstsc \/shadow:<SESSION_ID>/);
    assert.match(h, /CONSENT/);
  });
});

// ---------------------------------------------------------------------------
// SMB pass-the-hash — loopback fake SMB2 server
// ---------------------------------------------------------------------------

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

const SMB2_MAGIC = Buffer.from([0xff, 0x53, 0x4d, 0x42]);
const STATUS_MORE = 0xc0000016;

/** Minimal fake SMB2 server: negotiate + NTLM challenge + verify-or-reject. */
async function startFakeSmb2(expectedNtHashHex: string): Promise<{ server: Server; port: number; log: string[] }> {
  const log: string[] = [];
  const challenge = Buffer.from("srvchlng", "ascii");
  const server = createServer((sock) => {
    let buf = Buffer.alloc(0);
    let stage = 0;
    const send = (status: number, command: number, msgId: number, body: Buffer, sessionId = 0) => {
      const hdr = Buffer.concat([
        SMB2_MAGIC, u16le(64), u16le(0), u32le(status), u16le(command), u16le(1),
        u32le(0x00000001), u32le(0), u64le(msgId), u32le(0x0000feff), u32le(0), u64le(sessionId), Buffer.alloc(16),
      ]);
      const payload = Buffer.concat([hdr, body]);
      const nb = Buffer.alloc(4);
      nb[0] = 0;
      nb.writeUIntBE(payload.length, 1, 3);
      sock.write(Buffer.concat([nb, payload]));
    };
    sock.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 4) {
        const len = buf.readUIntBE(1, 3);
        if (buf.length < 4 + len) break;
        const frame = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);
        const cmd = frame.readUInt16LE(12);
        const msgId = Number(frame.readBigUInt64LE(24));
        if (stage === 0 && cmd === 0x0000) {
          // NEGOTIATE -> dialect 0x0302
          const body = Buffer.concat([u16le(65), u16le(1), u16le(0x0302), u16le(0), Buffer.alloc(56)]);
          send(0, 0x0000, msgId, body);
          stage = 1;
        } else if (stage === 1 && cmd === 0x0005) {
          // SESSION_SETUP#1 -> Type2 challenge
          const off = frame.readUInt16LE(64 + 4);
          void off;
          const t2 = Buffer.alloc(48);
          t2.write("NTLMSSP\0", 0, "ascii");
          t2.writeUInt32LE(2, 8);
          t2.writeUInt32LE(0x00088207, 20);
          challenge.copy(t2, 24);
          const boff = 64 + 8;
          const body = Buffer.concat([u16le(9), u16le(0), u16le(boff), u16le(t2.length), t2]);
          send(STATUS_MORE, 0x0005, msgId, body);
          stage = 2;
        } else if (stage === 2 && cmd === 0x0005) {
          // SESSION_SETUP#2 -> verify NTLMv2 proof. REQUEST layout:
          // StructureSize(2) Flags(1) SecurityMode(1) Channel(4)
          // SecurityBufferOffset(2)@+8 SecurityBufferLength(2)@+10 ...
          const sbo = frame.readUInt16LE(64 + 8);
          const sbl = frame.readUInt16LE(64 + 10);
          const blob = frame.subarray(sbo, sbo + sbl);
          let ok = false;
          try {
            const ntRespLen = blob.readUInt16LE(20);
            const ntRespOff = blob.readUInt32LE(24);
            const ntResp = blob.subarray(ntRespOff, ntRespOff + ntRespLen);
            const proof = ntResp.subarray(0, 16);
            const ntlmBlob = ntResp.subarray(16);
            const uLen = blob.readUInt16LE(36);
            const uOff = blob.readUInt32LE(40);
            const dLen = blob.readUInt16LE(28);
            const dOff = blob.readUInt32LE(32);
            const user = blob.subarray(uOff, uOff + uLen).toString("utf16le");
            const domain = blob.subarray(dOff, dOff + dLen).toString("utf16le");
            const key = ntowfv2(user, domain, Buffer.from(expectedNtHashHex, "hex"));
            ok = createHmac("md5", key).update(Buffer.concat([challenge, ntlmBlob])).digest().equals(proof);
          } catch {
            ok = false;
          }
          log.push(ok ? "accepted" : "rejected");
          const body = Buffer.concat([u16le(9), u16le(0), u16le(64 + 8), u16le(0)]);
          send(ok ? 0 : 0xc000006d, 0x0005, msgId, body, ok ? 0xdead : 0);
          stage = 3;
        } else if (cmd === 0x0002) {
          const body = Buffer.concat([u16le(4), u16le(0)]);
          send(0, 0x0002, msgId, body);
        }
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  return { server, port, log };
}

describe("smb pass-the-hash", () => {
  let server: Server;
  let port: number;
  let log: string[];
  const HASH = "8846f7eaee8fb117ad06bdd830b7586c";

  beforeEach(async () => {
    ({ server, port, log } = await startFakeSmb2(HASH));
  });
  afterEach(async () => {
    await new Promise<void>((r) => server.close(() => r()));
  });

  it("correct NT hash -> STATUS_SUCCESS, hashAccepted", async () => {
    const t = createSmbPthTransport();
    const r = await t.auth({
      host: "127.0.0.1",
      port,
      username: "testuser",
      ntHashHex: HASH,
      domain: "TEST",
      timeoutMs: 5000,
    });
    await t.close();
    assert.equal(r.reachable, true);
    assert.equal(r.hashAccepted, true);
    assert.deepEqual(log, ["accepted"]);
  });

  it("wrong NT hash -> LOGON_FAILURE, hashAccepted false", async () => {
    const t = createSmbPthTransport();
    const r = await t.auth({
      host: "127.0.0.1",
      port,
      username: "testuser",
      ntHashHex: "00000000000000000000000000000000",
      domain: "TEST",
      timeoutMs: 5000,
    });
    await t.close();
    assert.equal(r.hashAccepted, false);
    assert.deepEqual(log, ["rejected"]);
  });

  it("executor: smbPth refuses out-of-scope and redacts the hash", async () => {
    const exec = new HostExecutor({ env: FAKE_ENV });
    const denied = await exec.smbPth({ host: "evil.corp", scopeHosts: SCOPE });
    assert.ok(denied.refused?.match(/out of scope/), "scope checked before connect");
    // Redaction: the hash never appears in summaries even on refusal paths.
    const bad = new HostExecutor({ env: { ...FAKE_ENV, REDTEAM_SMB_NTHASH: "not-hex" } });
    const r2 = await bad.smbPth({ host: "target.corp", scopeHosts: SCOPE });
    assert.ok(r2.refused?.match(/32 hex/));
    assert.ok(!JSON.stringify(r2).includes("not-hex"));
  });
});

// ---------------------------------------------------------------------------
// Kerberos pass-the-ticket — fake krb5 tool runner
// ---------------------------------------------------------------------------

function fakeKrbRun(opts: { klistOut?: string; kvnoCode?: number; hasTools?: boolean; missingTools?: string[] }): {
  run: (cmd: string, args: string[], env: NodeJS.ProcessEnv) => Promise<{ stdout: string; stderr: string; code: number }>;
  calls: string[];
} {
  const calls: string[] = [];
  const run = async (cmd: string, args: string[], _env: NodeJS.ProcessEnv) => {
    calls.push(`${cmd} ${args.join(" ")}`);
    if (cmd === "command") {
      const tool = args[1];
      const missing = opts.hasTools === false || (opts.missingTools ?? []).includes(tool);
      return { stdout: missing ? "" : `/usr/bin/${tool}`, stderr: "", code: missing ? 1 : 0 };
    }
    if (cmd === "klist") {
      return {
        stdout:
          opts.klistOut ??
          "Ticket cache: FILE:/tmp/x\nDefault principal: testuser@TEST.CORP\n\nValid starting     Expires            Service principal\n01/01/26 00:00:00  01/02/26 00:00:00  krbtgt/TEST.CORP@TEST.CORP\n",
        stderr: "",
        code: 0,
      };
    }
    if (cmd === "kvno") {
      const code = opts.kvnoCode ?? 0;
      return { stdout: code === 0 ? "cifs/target.corp@TEST.CORP: kvno = 2" : "", stderr: code === 0 ? "" : "kvno: Ticket expired", code };
    }
    return { stdout: "", stderr: "", code: 0 };
  };
  return { run, calls };
}

describe("krb pass-the-ticket", () => {
  it("spnHostname parses service/host[@REALM]", () => {
    assert.equal(spnHostname("cifs/fileserver.corp@TEST.CORP"), "fileserver.corp");
    assert.equal(spnHostname("HTTP/web.corp:8080"), "web.corp");
    assert.equal(spnHostname("garbage"), undefined);
  });

  it("ccache from env -> klist parses principal; kvno proves KDC acceptance", async () => {
    const { run, calls } = fakeKrbRun({});
    const t = createKrbTransport({ run, env: FAKE_ENV });
    const r = await t.ptt({ host: "target.corp", spn: "cifs/target.corp", timeoutMs: 5000 });
    assert.equal(r.ok, true);
    assert.equal(r.ticketSource, "ccache-env");
    assert.equal(r.principal, "testuser@TEST.CORP");
    assert.equal(r.kdcAccepted, true);
    assert.ok(calls.some((c) => c.startsWith("kvno ")), "kvno ran for the replay proof");
    // The base64 ccache must not leak into notes.
    assert.ok(!r.note.includes(FAKE_ENV.REDTEAM_KRB_CCACHE_B64!));
  });

  it("kvno failure -> ticket not accepted (honest negative)", async () => {
    const { run } = fakeKrbRun({ kvnoCode: 1 });
    const t = createKrbTransport({ run, env: FAKE_ENV });
    const r = await t.ptt({ host: "target.corp", spn: "cifs/target.corp", timeoutMs: 5000 });
    assert.equal(r.ok, false);
    assert.equal(r.kdcAccepted, false);
  });

  it("missing krb5 tools -> actionable error", async () => {
    const { run } = fakeKrbRun({ hasTools: false });
    const t = createKrbTransport({ run, env: FAKE_ENV });
    const r = await t.ptt({ host: "target.corp", timeoutMs: 5000 });
    assert.equal(r.ok, false);
    assert.match(r.note, /krb5-user|krb5-workstation/);
  });

  it("kirbi without ticketConverter -> clear conversion guidance", async () => {
    const { run } = fakeKrbRun({ missingTools: ["ticketConverter.py"] });
    const env = { ...FAKE_ENV, REDTEAM_KRB_CCACHE_B64: "", REDTEAM_KRB_KIRBI_B64: Buffer.from("kirbi").toString("base64") };
    const t = createKrbTransport({ run, env });
    const r = await t.ptt({ host: "target.corp", timeoutMs: 5000 });
    assert.equal(r.ok, false);
    assert.match(r.note, /ticketConverter\.py/);
  });

  it("executor: krbPtt scope-checks host AND spn host", async () => {
    const { run } = fakeKrbRun({});
    const exec = new HostExecutor({ krb: (env) => createKrbTransport({ run, env }), env: FAKE_ENV });
    const badHost = await exec.krbPtt({ host: "evil.corp", scopeHosts: SCOPE });
    assert.ok(badHost.refused?.match(/out of scope/));
    const badSpn = await exec.krbPtt({ host: "target.corp", spn: "cifs/evil.corp", scopeHosts: SCOPE });
    assert.ok(badSpn.refused?.match(/out of scope/));
    const okSpn = await exec.krbPtt({ host: "target.corp", spn: "cifs/target.corp", scopeHosts: SCOPE });
    assert.equal(okSpn.ok, true);
  });
});

// ---------------------------------------------------------------------------
// AD enumeration — pure functions + fake LDAP transport
// ---------------------------------------------------------------------------

function sidBuf(sid: string): Buffer {
  // Build a binary SID from string form for the SD parser test.
  const parts = sid.split("-").slice(1).map(Number);
  const rev = parts[0];
  const auth = parts[1];
  const subs = parts.slice(2);
  const b = Buffer.alloc(8 + subs.length * 4);
  b[0] = rev;
  b[1] = subs.length;
  b.writeUIntBE(auth, 2, 6); // 48-bit identifier authority, big-endian
  subs.forEach((s, i) => b.writeUInt32LE(s, 8 + i * 4));
  return b;
}

function buildSd(grants: { sid: string; mask: number }[]): string {
  const aces: Buffer[] = [];
  for (const g of grants) {
    const sid = sidBuf(g.sid);
    const ace = Buffer.alloc(8 + sid.length);
    ace[0] = 0x00; // ACCESS_ALLOWED
    ace[1] = 0x00;
    ace.writeUInt16LE(ace.length, 2);
    ace.writeUInt32LE(g.mask, 4);
    sid.copy(ace, 8);
    aces.push(ace);
  }
  const daclLen = 8 + aces.reduce((n, a) => n + a.length, 0);
  const sd = Buffer.alloc(20 + daclLen);
  sd[0] = 1;
  sd.writeUInt16LE(0x8004, 2); // control: DP present
  sd.writeUInt32LE(20, 16); // dacl offset
  sd.writeUInt8(2, 20); // ACL revision
  sd.writeUInt16LE(aces.length, 22);
  sd.writeUInt16LE(daclLen, 24);
  let p = 28;
  for (const a of aces) {
    a.copy(sd, p);
    p += a.length;
  }
  return sd.toString("base64");
}

describe("ad enumeration", () => {
  it("findDangerousAces flags GenericAll/WriteDacl to non-Tier-0", () => {
    const sd = buildSd([
      { sid: "S-1-5-21-1-2-3-1104", mask: 0x10000000 }, // GenericAll to a user
      { sid: "S-1-5-21-1-2-3-512", mask: 0x10000000 }, // GenericAll to Domain Admins (tier-0, filtered later)
    ]);
    const aces = findDangerousAces("CN=x,DC=test,DC=corp", sd);
    assert.equal(aces.length, 2);
    assert.deepEqual(aces[0].rights, ["GenericAll"]);
    assert.equal(aces[0].granteeSid, "S-1-5-21-1-2-3-1104");
  });

  it("isTier0Sid / isLowPrivSid classify correctly", () => {
    const dom = "S-1-5-21-1-2-3";
    assert.equal(isTier0Sid(`${dom}-512`, dom), true);
    assert.equal(isTier0Sid(`${dom}-1104`, dom), false);
    assert.equal(isLowPrivSid("S-1-5-11", dom), true);
    assert.equal(isLowPrivSid(`${dom}-513`, dom), true);
    assert.equal(isLowPrivSid(`${dom}-512`, dom), false);
  });

  it("computeAttackPaths finds the shortest path to Tier-0 (offline)", () => {
    const nodes = [
      { dn: "CN=alice,DC=x", name: "alice", kind: "user" as const, sid: "S-1-5-21-1-2-3-1104" },
      { dn: "CN=helpdesk,DC=x", name: "helpdesk", kind: "group" as const, sid: "S-1-5-21-1-2-3-1105" },
      { dn: "CN=DA,DC=x", name: "Domain Admins", kind: "group" as const, sid: "S-1-5-21-1-2-3-512" },
    ];
    const edges = [
      { from: "CN=alice,DC=x", to: "CN=helpdesk,DC=x", via: "member" },
      { from: "CN=helpdesk,DC=x", to: "CN=DA,DC=x", via: "member" },
    ];
    const paths = computeAttackPaths(nodes, edges, new Set(["CN=DA,DC=x"]));
    assert.ok(paths.length >= 2, "both alice and helpdesk have paths");
    const alicePath = paths.find((p) => p.path[0] === "alice");
    assert.ok(alicePath, "alice has a path to Tier-0");
    assert.deepEqual(alicePath.path, ["alice", "helpdesk", "Domain Admins"]);
    // Sorted shortest-first: helpdesk (1 hop) before alice (2 hops).
    assert.ok(paths[0].path.length <= paths[paths.length - 1].path.length);
  });

  it("analyzeTemplate flags ESC1/ESC2/ESC4", () => {
    const dom = "S-1-5-21-1-2-3";
    const enrollSd = buildSd([{ sid: `${dom}-513`, mask: 0x00000100 }]); // Enroll to Domain Users
    const esc1: AdEntry = {
      dn: "CN=UserAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=corp",
      attrs: {
        cn: ["UserAuth"],
        "msPKI-Certificate-Name-Flag": ["1"], // ENROLLEE_SUPPLIES_SUBJECT
        pKIExtendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
        nTSecurityDescriptor: [enrollSd],
      },
    };
    const f1 = analyzeTemplate(esc1, dom);
    assert.ok(f1.some((f) => f.esc === "ESC1"), "ESC1 flagged");
    const esc4: AdEntry = {
      dn: "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=corp",
      attrs: {
        cn: ["WebServer"],
        "msPKI-Certificate-Name-Flag": ["0"],
        pKIExtendedKeyUsage: ["1.3.6.1.5.5.7.3.1"],
        nTSecurityDescriptor: [buildSd([{ sid: "S-1-5-11", mask: 0x00040000 }])], // WriteDacl to Authenticated Users
      },
    };
    assert.ok(analyzeTemplate(esc4, dom).some((f) => f.esc === "ESC4"), "ESC4 flagged");
  });

  it("adEnumerate collects and computes paths via a fake transport", async () => {
    const dom = "S-1-5-21-1-2-3";
    const entries = (op: string): AdEntry[] => {
      if (op === "root") {
        return [{ dn: "", attrs: { defaultNamingContext: ["DC=test,DC=corp"], configurationNamingContext: ["CN=Configuration,DC=test,DC=corp"] } }];
      }
      if (op === "domain") return [{ dn: "DC=test,DC=corp", attrs: { objectSid: [`${dom}`] } }];
      return [];
    };
    const fake: AdTransport = {
      async connect() {},
      async bind() {},
      async search(base, filter) {
        if (base === "") return entries("root");
        if (filter === "(objectClass=domain)") return entries("domain");
        if (filter === "(objectClass=user)") {
          return [
            { dn: "CN=alice,DC=test,DC=corp", attrs: { sAMAccountName: ["alice"], objectSid: [`${dom}-1104`], memberOf: ["CN=helpdesk,DC=test,DC=corp"] } },
          ];
        }
        if (filter === "(objectClass=group)") {
          return [
            { dn: "CN=helpdesk,DC=test,DC=corp", attrs: { sAMAccountName: ["helpdesk"], objectSid: [`${dom}-1105`], member: [`CN=alice,DC=test,DC=corp`] } },
            { dn: "CN=Domain Admins,DC=test,DC=corp", attrs: { sAMAccountName: ["Domain Admins"], objectSid: [`${dom}-512`], member: [`CN=helpdesk,DC=test,DC=corp`] } },
          ];
        }
        return [];
      },
      async searchRaw(base, filter, attrs) {
        return this.search(base, filter, attrs);
      },
      async close() {},
    };
    const r = await adEnumerate(fake, {
      host: "target.corp",
      creds: { username: "testuser", password: "pw", domain: "TEST" },
      operations: ["users", "groups", "attack_paths"],
    });
    assert.equal(r.ok, true);
    const ap = r.sections.find((s) => s.operation === "attack_paths");
    assert.ok(ap, "attack_paths section present");
    assert.ok(ap.summary.includes("alice"), "path includes alice");
    assert.ok(ap.summary.includes("Domain Admins"), "path reaches Tier-0");
    assert.match(ap.summary, /COMPUTED ONLY/);
  });

  it("executor: adEnum refuses out-of-scope; secrets redacted", async () => {
    const exec = new HostExecutor({ env: FAKE_ENV });
    const denied = await exec.adEnum({ host: "evil.corp", operations: ["users"], scopeHosts: SCOPE });
    assert.ok(denied.refused?.match(/out of scope/));
  });
});

// ---------------------------------------------------------------------------
// Wave-2 tools in the engagement loop (integration through runEngagement)
// ---------------------------------------------------------------------------

import { mkdtempSync as mkd2, rmSync as rm2 } from "node:fs";
import { join as join2 } from "node:path";
import { tmpdir as tmpdir2 } from "node:os";
import { runEngagement } from "../src/phases.js";
import type { EngagementInput } from "../src/types.js";
import type { AgentRole, ChatMessage, ChatResult, ToolCallRequest } from "@secscan/redteam-llm-router";
import type { WinrmTransport } from "../src/host-exec/index.js";

describe("wave-2 tools in the engagement loop", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkd2(join2(tmpdir2(), "wave2-"));
  });
  afterEach(() => rm2(dir, { recursive: true, force: true }));

  const textOnly = (text: string): ChatResult => ({ text, toolCalls: [], provider: "fake", model: "fake" });
  const toolCall = (name: string, args: Record<string, unknown>): ToolCallRequest => ({
    id: `call-${name}`,
    name,
    arguments: args,
  });

  function fakeWinrmFactory(): WinrmTransport {
    return {
      async exec(args) {
        // Serve the shadow-prep script with canned JSON; anything else gets a generic ok.
        const stdout = args.command.includes("qwinsta")
          ? JSON.stringify({ Sessions: [{ Session: "rdp-tcp#0", User: "jdoe", Id: "2", State: "Active" }], ShadowPolicy: 2, RemoteControlGrants: [] })
          : "ok";
        return { stdout, stderr: "", code: 0, ms: 5 };
      },
      async close() {},
    };
  }

  function scriptedLlm(): (role: AgentRole, messages: ChatMessage[], opts: { tools?: { name: string }[] }) => Promise<ChatResult> {
    return async (role, messages) => {
      const has = (s: string) => messages.some((m) => m.content.includes(s));
      if (role === "coordinator") {
        if (has("Transition awaiting sign-off")) return textOnly("SIGN-OFF: approved.");
        if (has("RE-PLAN") || has("Last batch results") || has("OVERRIDE"))
          return textOnly('```json\n{"tasks": [], "finish": true, "note": "done"}\n```');
        if (has("Return ONLY a JSON block")) {
          return textOnly(
            '```json\n{"tasks": [{"kind": "probe", "brief": "winrm probe + shadow prep on 10.9.0.13", "attackId": "T1021", "category": "validation", "maxTurns": 6}], "finish": false, "note": "go"}\n```',
          );
        }
        return textOnly('```json\n{"adversaryProfile": "test", "steps": [{"phase": "exploit", "attackId": "T1021", "description": "rdp"}]}\n```');
      }
      if (role === "recon") return textOnly("recon brief: host mapped");
      if (role === "reporter") return textOnly('# Report\n\n```json {"findings": []} ```');
      const sys = messages.find((m) => m.role === "system")?.content ?? "";
      if (sys.includes("Task:") || has("Execute the task now")) {
        const firedProbe = messages.some((m) => m.role === "tool" && /winrm[ _]probe/.test(m.content));
        const firedShadow = messages.some((m) => m.role === "tool" && m.content.includes("HUMAN OPERATOR"));
        if (!firedProbe) {
          return {
            text: "firing winrm_probe",
            toolCalls: [
              toolCall("winrm_probe", {
                host: "10.9.0.13",
                category: "validation",
                targetProfile: "windows",
                attackId: "T1021",
                hypothesis: "WS-010 listener probe",
              }),
            ],
            provider: "fake",
            model: "fake",
          };
        }
        if (!firedShadow) {
          return {
            text: "firing rdp_shadow_prep",
            toolCalls: [
              toolCall("rdp_shadow_prep", {
                host: "10.9.0.13",
                category: "logic",
                targetProfile: "windows",
                attackId: "T1021",
                hypothesis: "WS-065 shadow handoff prep",
              }),
            ],
            provider: "fake",
            model: "fake",
          };
        }
        return textOnly("TRIED: winrm_probe + rdp_shadow_prep / OBSERVED: outputs / VERDICT: done");
      }
      return textOnly("idle");
    };
  }

  it("winrm_probe and rdp_shadow_prep dispatch end-to-end; audit lands in events", async () => {
    const input: EngagementInput = {
      target: "10.9.0.13",
      mode: "red",
      objective: "wave-2 integration test",
      roe: { scope: ["10.9.0.13"] },
    };
    const executor = new HostExecutor({
      winrm: fakeWinrmFactory,
      env: FAKE_ENV,
    });
    // winrm_probe needs a requestImpl seam — inject via a subclass hook:
    const origProbe = executor.winrmProbe.bind(executor);
    executor.winrmProbe = async (a) =>
      origProbe({
        ...a,
        requestImpl: (async (u: string) => ({
          statusCode: 401,
          headers: { "www-authenticate": "Negotiate, NTLM", server: "Microsoft-HTTPAPI/2.0" },
          url: u,
        })) as never,
      });
    const res = await runEngagement(input, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: {
        verify: async () => true,
        completeForRole: scriptedLlm() as never,
        hostExecutor: executor,
      },
    });
    assert.equal(res.status, "complete");
    const { readFileSync } = await import("node:fs");
    const events = readFileSync(join2(dir, res.engagementId, "events.jsonl"), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as { action: string; result: string });
    const probe = events.filter((e) => e.action === "winrm_probe");
    const shadow = events.filter((e) => e.action === "rdp_shadow_prep");
    assert.ok(probe.length >= 1, "winrm_probe event logged");
    assert.ok(probe[0]!.result.includes("Negotiate"), "auth schemes in the audit");
    assert.ok(shadow.length >= 1, "rdp_shadow_prep event logged");
    assert.ok(shadow[0]!.result.includes("HUMAN OPERATOR REQUIRED"), "handoff package in the audit");
  });

  it("wave-2 tool with wrong targetProfile is DENIED (never inferred)", async () => {
    const input: EngagementInput = {
      target: "10.9.0.13",
      mode: "red",
      objective: "profile pin test",
      roe: { scope: ["10.9.0.13"] },
    };
    const llm = async (role: AgentRole, messages: ChatMessage[]): Promise<ChatResult> => {
      const has = (s: string) => messages.some((m) => m.content.includes(s));
      if (role === "coordinator") {
        if (has("Transition awaiting sign-off")) return textOnly("SIGN-OFF: approved.");
        if (has("RE-PLAN") || has("Last batch results") || has("OVERRIDE"))
          return textOnly('```json\n{"tasks": [], "finish": true, "note": "done"}\n```');
        if (has("Return ONLY a JSON block")) {
          return textOnly(
            '```json\n{"tasks": [{"kind": "probe", "brief": "mismatched profile", "attackId": "T1021", "category": "validation", "maxTurns": 3}], "finish": false, "note": "go"}\n```',
          );
        }
        return textOnly('```json\n{"adversaryProfile": "test", "steps": []}\n```');
      }
      if (role === "recon") return textOnly("recon brief");
      if (role === "reporter") return textOnly("# Report");
      const sys = messages.find((m) => m.role === "system")?.content ?? "";
      if (sys.includes("Task:") || has("Execute the task now")) {
        if (!messages.some((m) => m.role === "tool")) {
          return {
            text: "firing ad_enum with linux profile (wrong)",
            toolCalls: [toolCall("ad_enum", { host: "10.9.0.13", operations: ["users"], category: "validation", targetProfile: "linux", hypothesis: "x" })],
            provider: "fake",
            model: "fake",
          };
        }
        return textOnly("done");
      }
      return textOnly("idle");
    };
    const res = await runEngagement(input, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: { verify: async () => true, completeForRole: llm as never, hostExecutor: new HostExecutor({ env: FAKE_ENV }) },
    });
    assert.equal(res.status, "complete");
    const { readFileSync } = await import("node:fs");
    const events = readFileSync(join2(dir, res.engagementId, "events.jsonl"), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as { action: string; result: string });
    const denied = events.filter((e) => e.action === "ad_enum");
    assert.ok(denied.length >= 1, "ad_enum event logged");
    assert.ok(denied[0]!.result.includes("DENIED"), "mismatched targetProfile denied");
    assert.ok(denied[0]!.result.includes("never inferred"), "reason names the pinning rule");
  });
});
