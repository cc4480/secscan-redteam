/**
 * host-exec barrel — the runner's hands on hosts (v0.9.0).
 *
 * Three execution tools, one shared safety core:
 *  - ssh.ts   — command execution over SSH (Linux targets), via `ssh2`
 *  - smb.ts   — share reachability + file listing over SMB (Windows), via `@marsaud/smb2`
 *  - winrm.ts — command execution over WinRM (Windows), via `winrm-client`
 *  - common.ts — scope enforcement, destructive-command denylist, credential
 *    hygiene, timeouts, output caps. Every tool goes through it, fail closed.
 *  - executor.ts — HostExecutor facade; transports injectable for tests.
 */
export * from "./common.js";
export { createSshTransport, type SshTransport, type SshExecArgs, type SshExecResult } from "./ssh.js";
export { createSmbTransport, WELL_KNOWN_SHARES, type SmbTransport, type SmbArgs, type SmbDirEntry } from "./smb.js";
export { createWinrmTransport, type WinrmTransport, type WinrmExecArgs, type WinrmExecResult } from "./winrm.js";
export { HostExecutor, type HostExecDeps, type HostExecResult } from "./executor.js";
