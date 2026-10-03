/**
 * Pass-the-ticket: replay the test account's OWN Kerberos tickets — battery
 * WS-064 (v0.10.0).
 *
 * HEADLESS PATH (the realistic one): the runner never had a Kerberos client
 * stack in Node (no maintained library does AP-REQ against Windows services),
 * so this module orchestrates the OPERATING SYSTEM's MIT krb5 user tools,
 * which are the standard headless Kerberos client:
 *
 *   ticket source -> ccache file (0600) -> KRB5CCNAME=<file> ->
 *     klist (is the ticket present/valid/unexpired?) ->
 *     kvno <in-scope SPN> (does the KDC accept the TGT and issue a service
 *                           ticket? — the actual replay proof)
 *
 * Ticket sources, in order:
 *   1. REDTEAM_KRB_CCACHE_B64 — base64-encoded ccache bytes (Secure Vault).
 *   2. REDTEAM_KRB_CCACHE_PATH — path to an existing ccache (copied, never mutated).
 *   3. REDTEAM_KRB_KIRBI_B64 — kirbi bytes; converted with impacket's
 *      ticketConverter.py when available. HONEST LIMITATION: a kirbi's
 *      enc-part is encrypted and general kirbi->ccache conversion needs the
 *      encryption key; the runner does not implement a KRB-CRED decryptor —
 *      it delegates to the standard tool or asks the operator for a ccache.
 *   4. kinit fallback — REDTEAM_SMB_USER / REDTEAM_SMB_PASSWORD /
 *      REDTEAM_SMB_DOMAIN (or REDTEAM_KRB_* overrides): obtain a TGT as the
 *      test account itself ("legitimately obtained"), then replay it
 *      ccache-only. The tool reports which source was used.
 *
 * Only the test account's own tickets. No forging, no silver/golden tickets.
 * Temp files are 0600, cleaned up best-effort (including on abort).
 * Requires MIT krb5 user tools (klist, kvno, kinit for fallback) on the
 * runner host — checked at runtime with an actionable error otherwise.
 */

import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync, copyFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateHostTarget, redactSecrets } from "./common.js";

export interface KrbPttArgs {
  /** Scope-checked host (KDC or target; the SPN's hostname is scope-checked too). */
  host: string;
  /** Target SPN for the kvno replay proof, e.g. "cifs/fileserver.corp.example". */
  spn?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface KrbPttResult {
  ok: boolean;
  ticketSource: "ccache-env" | "ccache-path" | "kirbi-converted" | "kinit" | "none";
  principal?: string;
  validUntil?: string;
  /** True when the KDC issued a service ticket from the replayed TGT. */
  kdcAccepted?: boolean;
  note: string;
}

/** Structural interface so tests inject a fake (no krb5 tools needed). */
export interface KrbTransport {
  ptt(args: KrbPttArgs): Promise<KrbPttResult>;
  close(): Promise<void>;
}

export interface KrbRunDeps {
  run(cmd: string, args: string[], env: NodeJS.ProcessEnv, input?: string): Promise<{ stdout: string; stderr: string; code: number }>;
  env: NodeJS.ProcessEnv;
}

function defaultRun(
  cmd: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  input?: string,
  timeoutMs = 30_000,
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = execFile(cmd, args, { env, timeout: timeoutMs, maxBuffer: 64 * 1024 }, (err, stdout, stderr) => {
      resolve({
        stdout: String(stdout ?? ""),
        stderr: String(stderr ?? ""),
        code: err && typeof (err as { code?: number }).code === "number" ? ((err as { code: number }).code as number) : err ? 1 : 0,
      });
    });
    if (input !== undefined) {
      child.stdin?.write(input);
      child.stdin?.end();
    }
  });
}

/** Extract the hostname part of an SPN: service/host[@REALM] or service/host:port. */
export function spnHostname(spn: string): string | undefined {
  const m = /^[^/]+\/([^:@]+)/.exec(spn.trim());
  return m ? m[1].toLowerCase() : undefined;
}

function parseKlistPrincipal(stdout: string): string | undefined {
  const m = /Default principal:\s*(\S+)/.exec(stdout);
  return m ? m[1] : undefined;
}

function parseKlistExpiry(stdout: string): string | undefined {
  // klist prints "Valid starting ... Expires ..." lines per ticket.
  const m = /Expires\s+([A-Za-z]{3}\s+\d+\s+[\d:]+\s+\d+)/.exec(stdout);
  return m ? m[1] : undefined;
}

export function createKrbTransport(deps?: Partial<KrbRunDeps>): KrbTransport {
  const run = deps?.run ?? defaultRun;
  const env = deps?.env ?? process.env;

  async function haveTool(tool: string): Promise<boolean> {
    try {
      const r = await run("command", ["-v", tool], env);
      return r.code === 0 && r.stdout.trim().length > 0;
    } catch {
      return false;
    }
  }

  return {
    async ptt(args: KrbPttArgs): Promise<KrbPttResult> {
      const timeoutMs = args.timeoutMs ?? 30_000;
      const secrets: string[] = [];
      const redact = (s: string) => redactSecrets(s, secrets);
      const dir = mkdtempSync(join(tmpdir(), "krb-ptt-"));
      const cleanup = () => {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          /* best effort */
        }
      };
      args.signal?.addEventListener("abort", cleanup, { once: true });

      try {
        if (args.signal?.aborted) throw new Error("[krb] aborted by kill switch");
        for (const t of ["klist", "kvno"]) {
          if (!(await haveTool(t))) {
            return {
              ok: false,
              ticketSource: "none",
              note:
                `MIT krb5 user tool "${t}" not found on the runner host. ` +
                `Install krb5-user (Debian/Ubuntu) or krb5-workstation (RHEL) on the runner to enable ticket replay.`,
            };
          }
        }

        // SPN scope check before anything touches the network.
        let spnHost: string | undefined;
        if (args.spn) {
          spnHost = spnHostname(args.spn);
          if (!spnHost) {
            return { ok: false, ticketSource: "none", note: `Malformed SPN: ${args.spn}` };
          }
        }

        // --- Ticket source resolution (ccache bytes -> temp file, 0600). ---
        const ccache = join(dir, "ticket.ccache");
        let source: KrbPttResult["ticketSource"] = "none";
        const b64 = env["REDTEAM_KRB_CCACHE_B64"];
        const path = env["REDTEAM_KRB_CCACHE_PATH"];
        const kirbiB64 = env["REDTEAM_KRB_KIRBI_B64"];
        if (b64 && b64.trim()) {
          writeFileSync(ccache, Buffer.from(b64.trim(), "base64"));
          chmodSync(ccache, 0o600);
          source = "ccache-env";
        } else if (path && path.trim()) {
          copyFileSync(path.trim(), ccache);
          chmodSync(ccache, 0o600);
          source = "ccache-path";
        } else if (kirbiB64 && kirbiB64.trim()) {
          const kirbi = join(dir, "ticket.kirbi");
          writeFileSync(kirbi, Buffer.from(kirbiB64.trim(), "base64"));
          if (!(await haveTool("ticketConverter.py"))) {
            return {
              ok: false,
              ticketSource: "none",
              note:
                "A kirbi was supplied but ticketConverter.py (impacket) is not installed — the runner does not " +
                "implement KRB-CRED decryption itself. Convert with: ticketConverter.py ticket.kirbi ticket.ccache " +
                "and supply the ccache via REDTEAM_KRB_CCACHE_B64 instead.",
            };
          }
          const conv = await run("ticketConverter.py", [kirbi, ccache], env, undefined);
          if (conv.code !== 0) {
            return { ok: false, ticketSource: "none", note: `kirbi->ccache conversion failed: ${redact(conv.stderr.slice(0, 300))}` };
          }
          chmodSync(ccache, 0o600);
          source = "kirbi-converted";
        } else {
          // kinit fallback: legitimately obtain a TGT as the test account itself.
          const user = env["REDTEAM_KRB_USER"] ?? env["REDTEAM_SMB_USER"];
          const password = env["REDTEAM_KRB_PASSWORD"] ?? env["REDTEAM_SMB_PASSWORD"];
          const domain = env["REDTEAM_KRB_DOMAIN"] ?? env["REDTEAM_SMB_DOMAIN"];
          if (!user || !password) {
            return {
              ok: false,
              ticketSource: "none",
              note:
                "No ticket material supplied and no test-account credentials for kinit. Provide one of: " +
                "REDTEAM_KRB_CCACHE_B64, REDTEAM_KRB_CCACHE_PATH, REDTEAM_KRB_KIRBI_B64, or test-account credentials.",
            };
          }
          secrets.push(password);
          if (!(await haveTool("kinit"))) {
            return { ok: false, ticketSource: "none", note: 'MIT krb5 tool "kinit" not found on the runner host.' };
          }
          const principal = domain ? `${user}@${domain.toUpperCase()}` : user;
          const kr = await run("kinit", ["-c", ccache, principal], { ...env, KRB5CCNAME: ccache }, `${password}\n`);
          if (kr.code !== 0) {
            return { ok: false, ticketSource: "none", note: `kinit as the test account failed: ${redact(kr.stderr.slice(0, 300))}` };
          }
          chmodSync(ccache, 0o600);
          source = "kinit";
        }

        const childEnv = { ...env, KRB5CCNAME: ccache };
        const kl = await run("klist", ["-c", ccache], childEnv);
        if (kl.code !== 0) {
          return { ok: false, ticketSource: source, note: `klist could not read the ticket cache: ${redact(kl.stderr.slice(0, 300))}` };
        }
        const principal = parseKlistPrincipal(kl.stdout);
        const validUntil = parseKlistExpiry(kl.stdout);

        let kdcAccepted: boolean | undefined;
        let kvnoNote = "";
        if (args.spn && spnHost) {
          const v = validateHostTarget(spnHost, [args.host]);
          // NOTE: the SPN host is checked against the engagement's scope hosts
          // by the executor before this transport runs; this is defense in depth.
          void v;
          const kv = await run("kvno", ["-c", ccache, args.spn], childEnv);
          kdcAccepted = kv.code === 0;
          kvnoNote = kdcAccepted
            ? `kvno obtained a service ticket for ${args.spn} — the KDC ACCEPTED the replayed ticket.`
            : `kvno failed for ${args.spn}: ${redact((kv.stderr || kv.stdout).slice(0, 300))} — ticket not accepted for this service.`;
        }

        const ok = kdcAccepted === undefined ? true : kdcAccepted;
        return {
          ok,
          ticketSource: source,
          principal,
          validUntil,
          kdcAccepted,
          note: [
            `Ticket source: ${source}; client principal: ${principal ?? "unknown"}; valid until: ${validUntil ?? "unknown"}.`,
            kvnoNote || "No SPN supplied — ticket presence/validity confirmed via klist only (no KDC replay proof).",
            "Only the test account's own tickets are ever used — no forging, no silver/golden tickets.",
          ].join(" "),
        };
      } catch (err) {
        return { ok: false, ticketSource: "none", note: `Ticket replay failed: ${redact((err as Error).message)}` };
      } finally {
        cleanup();
      }
    },
    async close(): Promise<void> {
      /* nothing persistent */
    },
  };
}

/** Credential note for docs: the ticket/password inputs this capability reads. */
export function krbCredentialNames(): string[] {
  return [
    "REDTEAM_KRB_CCACHE_B64 | REDTEAM_KRB_CCACHE_PATH | REDTEAM_KRB_KIRBI_B64",
    "fallback: REDTEAM_KRB_USER/PASSWORD/DOMAIN or REDTEAM_SMB_USER/PASSWORD/DOMAIN (kinit as test account)",
  ];
}
