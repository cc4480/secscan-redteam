/**
 * Host-executor public types (v0.19.0 refactor — extracted from executor.ts).
 */
import {  } from "../common.js";
import { type AdTransport } from "../ad.js";
import { type KrbTransport } from "../krb.js";
import { type NfsTransport } from "../nfs.js";
import { type RdpTransport } from "../rdp.js";
import { type SmbPthTransport, type SmbTransport } from "../smb.js";
import { type SshTransport } from "../ssh.js";
import { type WinrmTransport } from "../winrm.js";

export interface HostExecDeps {
  ssh?: () => SshTransport;
  smb?: () => SmbTransport;
  smbPth?: () => SmbPthTransport;
  winrm?: () => WinrmTransport;
  rdp?: () => RdpTransport;
  ad?: () => AdTransport;
  /** Receives the executor's env so ticket-material resolution stays hermetic in tests. */
  krb?: (env: NodeJS.ProcessEnv) => KrbTransport;
  nfs?: () => NfsTransport;
  env?: NodeJS.ProcessEnv;
}

export interface HostExecResult {
  ok: boolean;
  transport: "ssh" | "smb" | "winrm" | "nfs";
  host: string;
  /** Redacted one-line summary for audit logs and events. */
  summary: string;
  /** Redacted, capped output. */
  output: string;
  ms: number;
  exitCode?: number;
  /** Set when the safety core refused before connecting. */
  refused?: string;
}
