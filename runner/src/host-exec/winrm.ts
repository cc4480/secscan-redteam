/**
 * WinRM command execution (Windows targets).
 *
 * LIBRARY CHOICE: `winrm-client` (v0.0.12, published 2026 — the most
 * recently maintained Node WinRM client found) — SOAP-based WinRM with
 * automatic auth detection: Basic for local usernames, NTLM for
 * domain-prefixed (DOMAIN\\user) or UPN (user@domain) formats. Evaluated
 * alternatives: `nodejs-winrm` (1.1.3, 2020, stale), hand-rolled SOAP
 * (NTLM handshake is error-prone to reimplement; the library's js-md4
 * based NTLM is the safer path).
 *
 * HONEST LIMITATION, stated plainly: the library exposes no abort handle
 * for in-flight requests. The kill switch therefore RACES the abort signal
 * against the request: on abort the runner abandons the promise and reports
 * termination, but the underlying HTTP request may run to the server-side
 * timeout. Commands are still bounded by timeoutMs, non-interactive, and
 * denylisted — the abandon is a runner-side guarantee, not a wire guarantee.
 *
 * Non-interactive commands only. Prefer `runPowershell` for structured
 * enumeration (Get-Service, Get-ScheduledTask, registry reads); plain
 * `runCommand` for cmd.exe builtins.
 */

import { runCommand, runPowershell } from "winrm-client";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { HOST_EXEC_TIMEOUT_MS, type HostCredentials } from "./common.js";

export interface WinrmExecArgs {
  host: string;
  port?: number;
  creds: HostCredentials;
  command: string;
  /** PowerShell (true) vs cmd.exe (false). Default true — most battery items are PowerShell. */
  powershell?: boolean;
  useTls?: boolean;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface WinrmExecResult {
  stdout: string;
  stderr: string;
  code: number;
  ms: number;
}

/** Structural interface so tests inject a fake (no network). */
export interface WinrmTransport {
  exec(args: WinrmExecArgs): Promise<WinrmExecResult>;
  close(): Promise<void>;
}

function qualname(creds: HostCredentials): string {
  // winrm-client auto-detects NTLM from DOMAIN\user or user@domain formats.
  if (creds.domain && !creds.username.includes("\\") && !creds.username.includes("@")) {
    return `${creds.domain}\\${creds.username}`;
  }
  return creds.username;
}

export function createWinrmTransport(): WinrmTransport {
  return {
    async exec(args: WinrmExecArgs): Promise<WinrmExecResult> {
      if (args.signal?.aborted) throw new Error("[winrm] aborted by kill switch before exec");
      const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
      const started = Date.now();
      const user = qualname(args.creds);
      const password = args.creds.password ?? "";
      const port = args.port ?? (args.useTls ? 5986 : 5985);

      // The library has no abort handle: race the kill-switch signal against
      // the request. On abort we abandon the promise (runner-side termination);
      // the request itself runs to the server-side timeout at worst.
      const run = (async () => {
        if (args.powershell === false) {
          return runCommand(args.command.slice(0, 4000), args.host, user, password, port, false, !!args.useTls);
        }
        return runPowershell(args.command.slice(0, 4000), args.host, user, password, port, !!args.useTls);
      })();

      const winner = await Promise.race([
        run.then((r) => ({ kind: "done" as const, r })),
        new Promise<{ kind: "timeout" }>((_, reject) => setTimeout(() => reject(new Error(`[winrm] command timed out after ${timeoutMs}ms`)), timeoutMs)),
        ...(args.signal
          ? [
              new Promise<{ kind: "aborted" }>((_, reject) => {
                args.signal!.addEventListener("abort", () => reject(new Error("[winrm] aborted by kill switch — request abandoned")), { once: true });
              }),
            ]
          : []),
      ]);

      if (winner.kind !== "done") throw new Error("[winrm] unreachable");
      const r = winner.r as { stdout?: string; stderr?: string; exitCode?: number; statusCode?: number };
      return {
        stdout: String(r.stdout ?? "").slice(0, 8192),
        stderr: String(r.stderr ?? "").slice(0, 8192),
        code: typeof r.exitCode === "number" ? r.exitCode : typeof r.statusCode === "number" ? r.statusCode : -1,
        ms: Date.now() - started,
      };
    },
    async close(): Promise<void> {
      // Stateless per-call library: nothing to close.
    },
  };
}

// ---------------------------------------------------------------------------
// WinRM listener probe (battery WS-010) — unauthenticated reconnaissance.
//
// Sends a single unauthenticated POST /wsman per port and reads what the
// listener volunteers: a real WinRM listener answers 401 with
// WWW-Authenticate headers advertising its auth schemes (Negotiate, NTLM,
// Kerberos, CredSSP, Basic) and usually a Server header. That 401 IS the
// finding — it confirms a listener, its TLS posture, and its auth surface —
// without creating a session, sending credentials, or running a command.
//
// TLS: port 5986 is probed with rejectUnauthorized: false. This is
// deliberate and documented: the target is an operator-scoped test host, and
// the certificate itself (issuer, expiry, SANs) is part of the observation,
// not a trust decision. Never use this against hosts outside the declared
// ROE scope — the executor enforces that before the probe runs.
//
// Pure Node http/https — no new dependencies.
// ---------------------------------------------------------------------------

/** Default WinRM ports: 5985 (HTTP) and 5986 (HTTPS). */
export const WINRM_PROBE_PORTS = [5985, 5986] as const;

/** Minimal SOAP envelope — any well-formed body elicits the 401 from a listener. */
const WINRM_PROBE_BODY =
  '<?xml version="1.0" encoding="utf-8"?>' +
  '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' +
  "<s:Header/>" +
  "<s:Body><probe/></s:Body>" +
  "</s:Envelope>";

export interface WinrmProbeRequest {
  host: string;
  port: number;
  useTls: boolean;
  timeoutMs: number;
  signal?: AbortSignal;
}

export interface WinrmProbeResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
}

/**
 * Injectable request seam: production uses {@link defaultWinrmProbeRequest}
 * (real HTTP/S); tests inject a fake. Never sends credentials.
 */
export type WinrmProbeRequestImpl = (req: WinrmProbeRequest) => Promise<WinrmProbeResponse>;

export interface WinrmProbeArgs {
  host: string;
  ports?: number[];
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Test seam — production callers leave this unset. */
  requestImpl?: WinrmProbeRequestImpl;
}

export interface WinrmProbeResult {
  port: number;
  reachable: boolean;
  useTls: boolean;
  authSchemes: string[];
  serverHeader?: string;
  note: string;
}

/** Real HTTP/S implementation of the probe request. No credentials, no session. */
export function defaultWinrmProbeRequest(req: WinrmProbeRequest): Promise<WinrmProbeResponse> {
  return new Promise((resolve, reject) => {
    if (req.signal?.aborted) {
      reject(new Error("[winrm-probe] aborted by kill switch before request"));
      return;
    }
    const body = Buffer.from(WINRM_PROBE_BODY, "utf8");
    const doRequest = req.useTls ? httpsRequest : httpRequest;
    const clientReq = doRequest(
      {
        host: req.host,
        port: req.port,
        path: "/wsman",
        method: "POST",
        headers: {
          "Content-Type": "application/soap+xml;charset=UTF-8",
          "Content-Length": body.length,
        },
        // The cert is observed, not trusted: the target is an
        // operator-scoped test host (see module docstring above).
        rejectUnauthorized: false,
        timeout: req.timeoutMs,
      },
      (res) => {
        // Drain the body — we only care about status + headers.
        res.resume();
        res.on("end", () => {
          const headers: Record<string, string | string[] | undefined> = {};
          for (const [k, v] of Object.entries(res.headers)) headers[k] = v;
          resolve({ statusCode: res.statusCode ?? 0, headers });
        });
      },
    );
    const fail = (err: Error) => {
      clientReq.destroy();
      reject(err);
    };
    clientReq.on("error", (err) => fail(err as Error));
    clientReq.on("timeout", () =>
      fail(new Error(`[winrm-probe] ${req.host}:${req.port} timed out after ${req.timeoutMs}ms`)),
    );
    req.signal?.addEventListener("abort", () => fail(new Error("[winrm-probe] aborted by kill switch — request destroyed")), {
      once: true,
    });
    clientReq.end(body);
  });
}

/**
 * Parse WWW-Authenticate headers into advertised scheme names.
 * HONEST LIMITATION: splitting on commas breaks on quoted parameters that
 * contain commas (rare in practice for auth schemes, e.g. `Basic
 * realm="a,b"`). Scheme names themselves never contain commas, so the
 * scheme list is still correct; only exotic parameter values could merge.
 */
export function parseWwwAuthenticate(headers: Record<string, string | string[] | undefined>): string[] {
  const raw = headers["www-authenticate"];
  const values = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const schemes: string[] = [];
  for (const v of values) {
    for (const part of v.split(",")) {
      const scheme = part.trim().split(/\s+/)[0] ?? "";
      if (scheme && !schemes.some((s) => s.toLowerCase() === scheme.toLowerCase())) {
        schemes.push(scheme);
      }
    }
  }
  return schemes;
}

function headerValue(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  const v = headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Probe each port for a WinRM listener. Unauthenticated: sends one POST
 * /wsman and reads the status + headers. Ports are probed sequentially so
 * abort semantics stay simple; each port gets its own timeout.
 */
export async function probeWinrmListener(args: WinrmProbeArgs): Promise<WinrmProbeResult[]> {
  const ports = args.ports ?? [...WINRM_PROBE_PORTS];
  const timeoutMs = args.timeoutMs ?? HOST_EXEC_TIMEOUT_MS;
  const requestImpl = args.requestImpl ?? defaultWinrmProbeRequest;
  const results: WinrmProbeResult[] = [];
  for (const port of ports) {
    const useTls = port === 5986;
    try {
      const res = await requestImpl({ host: args.host, port, useTls, timeoutMs, signal: args.signal });
      const authSchemes = parseWwwAuthenticate(res.headers);
      const serverHeader = headerValue(res.headers, "server");
      const status = res.statusCode;
      let note: string;
      if (status === 401 && authSchemes.length > 0) {
        note = `401 Unauthorized — WinRM listener present, advertising auth: ${authSchemes.join(", ")}`;
      } else if (status === 401) {
        note = "401 Unauthorized — listener present but advertised no auth schemes";
      } else {
        note = `HTTP ${status} — responded without the expected 401 challenge; listener uncertain`;
      }
      results.push({ port, reachable: true, useTls, authSchemes, serverHeader, note });
    } catch (err) {
      results.push({
        port,
        reachable: false,
        useTls,
        authSchemes: [],
        note: `not reachable: ${(err as Error).message}`,
      });
    }
    if (args.signal?.aborted) break;
  }
  return results;
}
