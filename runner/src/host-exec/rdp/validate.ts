
// ---------------------------------------------------------------------------
// NLA credential validation

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
} from "../ntlmv2.js";
import { HOST_EXEC_TIMEOUT_MS, type HostCredentials } from "../common.js";
import {
  PROTOCOL_HYBRID,
  PROTOCOL_HYBRID_EX,
  buildX224ConnectionRequest,
  parseX224ConnectionConfirm,
  protocolName,
} from "./x224.js";
import type { RdpChannel, RdpTransport } from "./channel.js";

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
