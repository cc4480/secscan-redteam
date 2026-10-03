/**
 * RDP credential validation via NLA (CredSSP) — battery WS-019 (v0.10.0).
 *
 * LIBRARY DECISION, stated plainly: the only pure-JS Node RDP client with
 * NLA support is yogi-ra/node-rdpjs, a GitHub fork licensed AGPL-3.0.
 * Depending on AGPL code inside a commercial B2B product is a legal risk
 * the runner will not take silently — so this module implements the
 * MINIMUM viable NLA handshake itself, from the public protocol specs
 * (MS-RDPBCGR §2.2.1, MS-CSSP, MS-NLMP):
 *
 *   1. X.224 Connection Request asking for PROTOCOL_SSL|PROTOCOL_HYBRID
 *   2. If the server selects HYBRID: TLS upgrade, then CredSSP —
 *      TSRequest/SPNEGO carrying NTLMSSP NEGOTIATE → CHALLENGE →
 *      AUTHENTICATE (NTLMv2, see ntlmv2.ts)
 *   3. The moment the server affirmatively accepts the handshake, the
 *      credential is VALID — we close immediately. No MCS connect, no
 *      desktop session is ever established or driven. Credential
 *      validation, not session hijacking.
 *
 * If the server does NOT offer NLA (SSL or legacy RDP security), we report
 * nlaRequired:false and do NOT attempt credential validation — validating
 * creds without NLA would require a full interactive logon, which a
 * headless runner must not fake. The absent NLA is itself the finding.
 *
 * On handshake failure (server closes/resets mid-handshake — the standard
 * Windows behavior for bad NLA credentials) we report credentialValid:false
 * with the observation, never an exception-as-verdict.
 */

import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import {
  buildType1,
  parseType2,
  buildType3V2,
  ntHash,
  spnegoInit,
  spnegoResp,
  tsRequest,
  tsResponseNtlmToken,
  type Type2,
} from "./ntlmv2.js";
import { HOST_EXEC_TIMEOUT_MS, type HostCredentials } from "./common.js";

// ---------------------------------------------------------------------------
// X.224 / RDP negotiation (MS-RDPBCGR 2.2.1.1)
// ---------------------------------------------------------------------------

const PROTOCOL_RDP = 0;
const PROTOCOL_SSL = 1;
const PROTOCOL_HYBRID = 2;
const PROTOCOL_HYBRID_EX = 8;

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

// ---------------------------------------------------------------------------
// Channel abstraction (injectable for tests)
// ---------------------------------------------------------------------------

export interface RdpChannel {
  write(b: Buffer): void;
  readExactly(n: number, timeoutMs: number): Promise<Buffer>;
  /** Take whatever is currently buffered (may be empty). */
  drain(): Buffer;
  /** Upgrade the underlying socket to TLS (CredSSP runs inside TLS). */
  startTls(): Promise<void>;
  close(): void;
}

export interface RdpTransport {
  open(host: string, port: number, timeoutMs: number, signal?: AbortSignal): Promise<RdpChannel>;
  close(): Promise<void>;
}

class RealRdpChannel implements RdpChannel {
  private sock: Socket | TLSSocket;
  private buf = Buffer.alloc(0);
  private waiters: { n: number; resolve: (b: Buffer) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }[] = [];
  private closedFlag = false;

  constructor(sock: Socket) {
    this.sock = sock;
    sock.on("data", (d: Buffer) => this.onData(d));
    sock.on("close", () => this.onClose(new Error("[rdp] connection closed by peer")));
    sock.on("error", (e) => this.onClose(e instanceof Error ? e : new Error(String(e))));
  }

  private onData(d: Buffer): void {
    this.buf = Buffer.concat([this.buf, d]);
    this.pump();
  }

  private pump(): void {
    while (this.waiters.length > 0 && this.buf.length >= this.waiters[0].n) {
      const w = this.waiters.shift()!;
      clearTimeout(w.timer);
      const out = this.buf.subarray(0, w.n);
      this.buf = this.buf.subarray(w.n);
      w.resolve(out);
    }
  }

  private onClose(err: Error): void {
    if (this.closedFlag) return;
    this.closedFlag = true;
    for (const w of this.waiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(err);
    }
  }

  write(b: Buffer): void {
    if (this.closedFlag) throw new Error("[rdp] write on closed channel");
    this.sock.write(b);
  }

  readExactly(n: number, timeoutMs: number): Promise<Buffer> {    if (this.buf.length >= n) {
      const out = this.buf.subarray(0, n);
      this.buf = this.buf.subarray(n);
      return Promise.resolve(out);
    }
    return new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this.waiters.findIndex((w) => w.resolve === resolve);
        if (i >= 0) this.waiters.splice(i, 1);
        reject(new Error(`[rdp] read timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.waiters.push({ n, resolve, reject, timer });
    });
  }

  drain(): Buffer {
    const out = this.buf;
    this.buf = Buffer.alloc(0);
    return out;
  }

  async startTls(): Promise<void> {
    const sock = this.sock;
    if (this.closedFlag) throw new Error("[rdp] cannot TLS-upgrade a closed channel");
    // Carry any already-buffered bytes back so the TLS layer sees them.
    const leftover = this.buf;
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    const tlsSock = tlsConnect({
      socket: sock,
      // The server certificate is part of the observation (self-signed is
      // expected on RDP); this is an operator-scoped test host, not a trust
      // decision. Documented, deliberate.
      rejectUnauthorized: false,
    });
    await new Promise<void>((resolve, reject) => {
      tlsSock.once("secureConnect", () => resolve());
      tlsSock.once("error", reject);
    });
    if (leftover.length > 0) tlsSock.unshift(leftover);
    this.sock = tlsSock;
    tlsSock.on("data", (d: Buffer) => this.onData(d));
    tlsSock.on("close", () => this.onClose(new Error("[rdp] TLS connection closed by peer")));
    tlsSock.on("error", (e) => this.onClose(e instanceof Error ? e : new Error(String(e))));
  }

  close(): void {
    this.closedFlag = true;
    try {
      this.sock.destroy();
    } catch {
      /* best effort */
    }
  }
}

export function createRdpTransport(): RdpTransport {
  const channels: RealRdpChannel[] = [];
  return {
    async open(host, port, timeoutMs, signal): Promise<RdpChannel> {
      if (signal?.aborted) throw new Error("[rdp] aborted by kill switch before connect");
      const sock = netConnect({ host, port });
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          sock.destroy();
          reject(new Error(`[rdp] TCP connect timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        const onAbort = () => {
          clearTimeout(timer);
          sock.destroy();
          reject(new Error("[rdp] aborted by kill switch"));
        };
        signal?.addEventListener("abort", onAbort, { once: true });
        sock.once("connect", () => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          resolve();
        });
        sock.once("error", (e) => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          reject(new Error(`[rdp] TCP connect failed: ${(e as Error).message}`));
        });
      });
      const ch = new RealRdpChannel(sock);
      channels.push(ch);
      signal?.addEventListener("abort", () => ch.close(), { once: true });
      return ch;
    },
    async close(): Promise<void> {
      for (const c of channels.splice(0)) {
        try {
          c.close();
        } catch {
          /* best effort */
        }
      }
    },
  };
}

// ---------------------------------------------------------------------------
// NLA credential validation
// ---------------------------------------------------------------------------

export interface RdpValidateArgs {
  host: string;
  port?: number;
  creds: HostCredentials;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface RdpValidateResult {
  reachable: boolean;
  nlaRequired: boolean;
  /** Set only when the NLA handshake ran to a verdict. */
  credentialValid?: boolean;
  selectedProtocol?: string;
  note: string;
}

/** Read one TPKT frame (4-byte header + payload). */
async function readTpkt(ch: RdpChannel, timeoutMs: number): Promise<Buffer> {
  const hdr = await ch.readExactly(4, timeoutMs);
  if (hdr[0] !== 0x03) throw new Error("[rdp] not a TPKT frame");
  const len = hdr.readUInt16BE(2);
  if (len < 4 || len > 65535) throw new Error("[rdp] bad TPKT length");
  const rest = await ch.readExactly(len - 4, timeoutMs);
  return Buffer.concat([hdr, rest]);
}

/** Read one CredSSP response: first byte, brief settle, then drain. */
async function readCredssp(ch: RdpChannel, timeoutMs: number): Promise<Buffer> {
  // CredSSP TSRequest responses are < 4KB. Read the first byte (proves the
  // server answered), give the rest of the record a moment, then drain.
  const first = await ch.readExactly(1, timeoutMs);
  await new Promise((r) => setTimeout(r, 150));
  return Buffer.concat([first, ch.drain()]);
}

export async function rdpValidateCredentials(
  transport: RdpTransport,
  args: RdpValidateArgs,
): Promise<RdpValidateResult> {
  const port = args.port ?? 3389;
  const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
  let ch: RdpChannel | undefined;
  try {
    ch = await transport.open(args.host, port, timeoutMs, args.signal);

    // 1. X.224 negotiation.
    ch.write(buildX224ConnectionRequest());
    const confirm = await readTpkt(ch, timeoutMs);
    const neg = parseX224ConnectionConfirm(confirm);
    if (neg.kind === "failure") {
      return {
        reachable: true,
        nlaRequired: false,
        note: `RDP negotiation failed (code 0x${neg.code.toString(16)}) — no NLA handshake attempted.`,
      };
    }
    const selected = protocolName(neg.protocol);
    if (neg.protocol !== PROTOCOL_HYBRID && neg.protocol !== PROTOCOL_HYBRID_EX) {
      return {
        reachable: true,
        nlaRequired: false,
        selectedProtocol: selected,
        note:
          `Server selected ${selected}: NLA is NOT required. Credential validation was NOT attempted — ` +
          `without NLA, validating credentials needs a full interactive logon, which this headless runner ` +
          `does not perform. NLA-absence is the finding (WS-009 corroborates the listener fingerprint).`,
      };
    }

    // 2. TLS upgrade, then CredSSP.
    await ch.startTls();
    const domain = args.creds.domain ?? "";
    const hash = args.creds.password ? ntHash(args.creds.password) : undefined;
    if (!hash) {
      return {
        reachable: true,
        nlaRequired: true,
        selectedProtocol: selected,
        note: "NLA required, but no password credential was provided — validation not attempted.",
      };
    }
    ch.write(tsRequest(spnegoInit(buildType1(domain))));

    let challenge: Type2;
    try {
      const resp1 = await readCredssp(ch, timeoutMs);
      const token = tsResponseNtlmToken(resp1);
      challenge = parseType2(token);
    } catch (err) {
      return {
        reachable: true,
        nlaRequired: true,
        selectedProtocol: selected,
        credentialValid: false,
        note: `NLA handshake aborted by server before challenge (${(err as Error).message}) — credential not validated.`,
      };
    }

    // 3. AUTHENTICATE with NTLMv2 keyed by the password-derived hash.
    const type3 = buildType3V2({
      user: args.creds.username,
      domain,
      challenge: challenge.challenge,
      targetInfo: challenge.targetInfo,
      ntHash: hash,
    });
    ch.write(tsRequest(spnegoResp(type3)));

    // 4. Verdict: an affirmative server TSRequest means the credential was
    // accepted; a close/reset during the handshake is Windows' standard
    // signal for rejected NLA credentials.
    try {
      const resp2 = await readCredssp(ch, timeoutMs);
      tsResponseNtlmToken(resp2); // must at least parse as a TSResponse
      return {
        reachable: true,
        nlaRequired: true,
        credentialValid: true,
        selectedProtocol: selected,
        note:
          "NLA (CredSSP/NTLMv2) handshake completed — the test-account credential was ACCEPTED. " +
          "Connection closed immediately after validation; no desktop session was established or driven.",
      };
    } catch {
      return {
        reachable: true,
        nlaRequired: true,
        credentialValid: false,
        selectedProtocol: selected,
        note:
          "Server closed the connection during the NLA handshake — the standard Windows signal for " +
          "rejected credentials. Credential NOT valid (or NLA policy rejected the attempt).",
      };
    }
  } catch (err) {
    return {
      reachable: false,
      nlaRequired: false,
      note: `RDP unreachable: ${(err as Error).message}`,
    };
  } finally {
    try {
      ch?.close();
    } catch {
      /* best effort */
    }
  }
}

// ---------------------------------------------------------------------------
// RDP session-shadowing exposure — HUMAN-GATED (WS-065).
//
// Shadowing a live user's session is inherently interactive: an operator
// sits in a GUI session and views another person's live desktop. A headless
// agent cannot meaningfully automate that, and must not pretend to.
// What the runner CAN do — and what rdpShadowPrep() does — is prepare
// EVERYTHING up to the human step via read-only WinRM enumeration:
// live session IDs, the shadow permission state, the exact shadow command,
// and the consent/ROE checklist. The item keeps needs:"human operator".
// ---------------------------------------------------------------------------

/** Read-only PowerShell: enumerate live RDP sessions + shadow policy state. */
export const RDP_SHADOW_PREP_PS = [
  "$err = $null",
  "$sessions = @(qwinsta 2>$null | Select-Object -Skip 1 | ForEach-Object {",
  "  $p = $_ -split '\\s+', 6",
  "  if ($p.Count -ge 4) { [pscustomobject]@{ Session=$p[0].Trim('>'); User=$p[1]; Id=$p[2]; State=$p[3] } }",
  "} | Where-Object { $_.State -match 'Active|Disc' })",
  "$shadowPol = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name Shadow -ErrorAction SilentlyContinue",
  "$ts = Get-CimInstance -Namespace root/cimv2/terminalservices -ClassName Win32_TSAccount -ErrorAction SilentlyContinue |",
  "  Select-Object AccountName, @{n='RemoteControl';e={ $_.PermissionsAllowed -band 16 }}",
  "[pscustomobject]@{",
  "  Sessions = $sessions",
  "  ShadowPolicy = if ($shadowPol) { $shadowPol.Shadow } else { 'not-set (server default applies)' }",
  "  RemoteControlGrants = @($ts)",
  "} | ConvertTo-Json -Depth 4 -Compress",
].join("\n");

/**
 * Build the human handoff package for RDP shadowing from the read-only
 * enumeration output. Pure function — tested directly.
 */
export function buildShadowHandoff(prepJson: string, host: string): string {
  let sessions = "unknown";
  let policy = "unknown";
  try {
    const o = JSON.parse(prepJson) as {
      Sessions?: { Session?: string; User?: string; Id?: string; State?: string }[];
      ShadowPolicy?: unknown;
    };
    const list = Array.isArray(o.Sessions) ? o.Sessions : [];
    sessions =
      list.length > 0
        ? list.map((s) => `session "${s.Session ?? "?"}" id=${s.Id ?? "?"} user=${s.User ?? "?"} state=${s.State ?? "?"}`).join("; ")
        : "no active/disconnected user sessions enumerated";
    policy = String(o.ShadowPolicy ?? "unknown");
  } catch {
    sessions = `enumeration output was not JSON — raw: ${prepJson.slice(0, 300)}`;
  }
  return [
    `RDP SHADOW HANDOFF — ${host} (HUMAN OPERATOR REQUIRED)`,
    `Live sessions: ${sessions}`,
    `Shadow consent policy (0=disable,1=full w/o consent,2=full w/ consent,3=view w/o consent,4=view w/ consent): ${policy}`,
    `Exact command (run from an RDP session on ${host} as the authorized test account): mstsc /shadow:<SESSION_ID> [/control] [/noConsentPrompt only if ROE explicitly allows]`,
    `ROE / CONSENT CHECKLIST — all must be true before shadowing:`,
    `  1. The engagement ROE explicitly authorizes session shadowing (it is surveillance otherwise).`,
    `  2. The target session's user has consented, OR the consent policy + ROE waives it — never assume.`,
    `  3. Record: session ID shadowed, start/end time, consent basis, what was observed (facts only).`,
    `  4. Black mode: shadowing a live user session is never acceptable — report the permission state only.`,
    `What to observe and record: whether a consent prompt appeared on the target session, what the operator could see/do, and whether the shadow event was logged (Event ID 20510/20506 class).`,
  ].join("\n");
}
