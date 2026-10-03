/**
 * host-exec barrel — the runner's hands on hosts (v0.10.0).
 *
 * Execution tools plus unauthenticated recon, one shared safety core:
 *  - ssh.ts   — command execution over SSH (Linux targets), via `ssh2`;
 *    also carries the SSH agent-forwarding audit (LX-018/LX-019)
 *  - smb.ts   — share reachability + file listing over SMB (Windows), via `@marsaud/smb2`
 *  - winrm.ts — command execution over WinRM (Windows), via `winrm-client`;
 *    also carries the unauthenticated WinRM listener probe (WS-010)
 *  - nfs.ts   — NFS export enumeration over userland ONC RPC (LX-041);
 *    never mounts — the export list is the evidence
 *  - ntlmv2.ts — shared NTLMv2 / CredSSP / DER primitives (no network):
 *    NT hash, NTOWFv2, Type1/2/3 builders, SPNEGO + TSRequest encoding
 *  - rdp.ts   — RDP credential validation via NLA/CredSSP (WS-019), pure-Node
 *    X.224+TLS+CredSSP (no AGPL dependency); also the read-only RDP shadow
 *    preparation for the human-gated WS-065
 *  - krb.ts   — pass-the-ticket via MIT krb5 user tools (WS-064): ccache /
 *    kirbi ingestion, klist validity, kvno KDC-acceptance proof
 *  - ad.ts    — read-only LDAP AD enumeration via ldapts (WS-038 attack-path
 *    computation, WS-043 AD CS template audit); binary SD parsing, offline BFS
 *  - common.ts — scope enforcement, destructive-command denylist, credential
 *    hygiene, timeouts, output caps. Every tool goes through it, fail closed.
 *  - executor.ts — HostExecutor facade; transports injectable for tests.
 */
export * from "./common.js";
export {
  createSshTransport,
  resolveAgentSocketPath,
  SSH_AGENT_AUDIT_SOCKET_CHECK,
  SSH_AGENT_AUDIT_ABUSE_PATH,
  type SshTransport,
  type SshExecArgs,
  type SshExecResult,
} from "./ssh.js";
export { createSmbTransport, WELL_KNOWN_SHARES, type SmbTransport, type SmbArgs, type SmbDirEntry } from "./smb.js";
export { createSmbPthTransport, type SmbPthTransport, type SmbPthArgs, type SmbPthResult } from "./smb.js";
export {
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
  derParse,
  type Type2,
} from "./ntlmv2.js";
export {
  createRdpTransport,
  rdpValidateCredentials,
  buildX224ConnectionRequest,
  parseX224ConnectionConfirm,
  protocolName,
  RDP_SHADOW_PREP_PS,
  buildShadowHandoff,
  type RdpTransport,
  type RdpChannel,
  type RdpValidateArgs,
  type RdpValidateResult,
} from "./rdp.js";
export {
  createKrbTransport,
  spnHostname,
  krbCredentialNames,
  type KrbTransport,
  type KrbPttArgs,
  type KrbPttResult,
} from "./krb.js";
export {
  createAdTransport,
  adEnumerate,
  findDangerousAces,
  isLowPrivSid,
  isTier0Sid,
  computeAttackPaths,
  analyzeTemplate,
  type AdTransport,
  type AdEntry,
  type AdEnumArgs,
  type AdEnumResult,
  type AdOperation,
  type DangerousAce,
} from "./ad.js";
export {
  createWinrmTransport,
  probeWinrmListener,
  defaultWinrmProbeRequest,
  parseWwwAuthenticate,
  WINRM_PROBE_PORTS,
  type WinrmTransport,
  type WinrmExecArgs,
  type WinrmExecResult,
  type WinrmProbeArgs,
  type WinrmProbeResult,
  type WinrmProbeRequest,
  type WinrmProbeResponse,
  type WinrmProbeRequestImpl,
} from "./winrm.js";
export {
  createNfsTransport,
  defaultNfsDial,
  parseRpcReply,
  RpcAcceptError,
  RPC_PROG_MISMATCH,
  XdrReader,
  xdrU32,
  xdrString,
  type NfsTransport,
  type NfsExport,
  type NfsEnumerateArgs,
  type NfsConnection,
  type NfsDialFn,
} from "./nfs.js";
export {
  HostExecutor,
  parseAgentSocketCheck,
  parseAgentAbusePath,
  type HostExecDeps,
  type HostExecResult,
} from "./executor.js";
