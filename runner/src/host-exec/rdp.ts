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

/**
 * RDP (see above) — split into submodules (public export surface unchanged):
 *  - rdp/x224.ts     — X.224 / RDP negotiation (MS-RDPBCGR 2.2.1.1)
 *  - rdp/channel.ts  — injectable socket channel + TLS upgrade
 *  - rdp/validate.ts — NLA (CredSSP) credential validation
 *  - rdp/shadow.ts   — human-gated WS-065 shadow prep
 */
export { createRdpTransport, type RdpTransport, type RdpChannel } from "./rdp/channel.js";
export {
  rdpValidateCredentials,
  type RdpValidateArgs,
  type RdpValidateResult,
} from "./rdp/validate.js";
export { buildX224ConnectionRequest, parseX224ConnectionConfirm, protocolName, type RdpNegResult } from "./rdp/x224.js";
export { RDP_SHADOW_PREP_PS, buildShadowHandoff } from "./rdp/shadow.js";
