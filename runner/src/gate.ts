/**
 * Engagement-level gating. Every check fails closed: uncertainty → deny.
 *
 * Layers (all must pass before aggressive work):
 *  1. Server-authoritative ownership verification (auth-gate's isServerVerified)
 *     of EVERY host in the ROE scope — not just the primary domain; the
 *     local-sandbox exemption applies per private/loopback host only.
 *  2. Scope: every probed/scanned URL's hostname must be an exact in-scope host.
 *  3. Technique exclusions: always-excluded + mode defaults + ROE exclusions.
 *  4. Blackout windows: the runner pauses, it does not skip.
 *  5. Test window: the runner refuses to run outside the agreed window.
 */

import { isServerVerified as authGateIsServerVerified } from "@secscan/redteam-auth-gate";
import { extractDomain } from "@secscan/redteam-auth-gate";
import { resolveExcludedTechniques } from "./attack.js";
import { isPrivateOrLoopbackHost } from "./prober.js";
import type { BlackoutWindow, EngagementMode, RulesOfEngagement } from "./types.js";

export interface GateVerdict {
  allowed: boolean;
  reason?: string;
}

/** Normalize ROE scope entries (URLs or bare hosts) to lowercase hostnames. */
export function scopeHosts(roe: RulesOfEngagement): string[] {
  const hosts: string[] = [];
  for (const entry of roe.scope) {
    try {
      hosts.push(extractDomain(entry));
    } catch {
      // Unparseable scope entry — fail closed downstream by matching nothing.
    }
  }
  return [...new Set(hosts)];
}

/** True when the URL's hostname is exactly one of the in-scope hosts. */
export function urlInScope(url: string, hosts: string[]): boolean {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return hosts.includes(host);
  } catch {
    return false;
  }
}

/**
 * True when `now` falls inside any blackout window. Windows are daily,
 * "HH:MM" 24h, and may cross midnight. Evaluated in the window's tz (or the
 * runner's local tz when unset).
 */
export function inBlackout(now: Date, windows: BlackoutWindow[] | undefined): BlackoutWindow | null {
  if (!windows || windows.length === 0) return null;
  for (const w of windows) {
    const tz = w.tz;
    const parts = new Intl.DateTimeFormat("en-GB", {
      timeZone: tz,
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    })
      .format(now)
      .split(":");
    const cur = Number(parts[0]) * 60 + Number(parts[1]);
    const [sh, sm] = w.start.split(":").map(Number);
    const [eh, em] = w.end.split(":").map(Number);
    if ([sh, sm, eh, em].some((n) => Number.isNaN(n))) continue; // malformed → ignore window, never block on garbage
    const start = sh * 60 + sm;
    const end = eh * 60 + em;
    const inside = start <= end ? cur >= start && cur < end : cur >= start || cur < end;
    if (inside) return w;
  }
  return null;
}

/** True when `now` is inside the agreed test window (or no window was set). */
export function inTestWindow(now: Date, roe: RulesOfEngagement): boolean {
  if (!roe.testWindow) return true;
  const t = now.getTime();
  return t >= Date.parse(roe.testWindow.start) && t <= Date.parse(roe.testWindow.end);
}

/** True when the ATT&CK technique may be used in this engagement. */
export function techniqueAllowed(
  attackId: string | undefined,
  mode: EngagementMode,
  roe: RulesOfEngagement,
): boolean {
  if (!attackId) return true; // unmapped actions are allowed; the mapping is advisory
  const excluded = resolveExcludedTechniques(mode, roe.excludedTechniques);
  return !excluded.includes(attackId.toUpperCase());
}

export interface ServerGateConfig {
  mcpEndpoint: string;
  mcpToken: string;
}

/** The SecScan-server ownership check. Injectable so tests never touch the network. */
export type VerifyFn = (
  domain: string,
  cfg: { endpoint: string; token: string },
) => Promise<boolean>;

export interface CheckAuthorizationOptions {
  /**
   * LOCAL SANDBOX MODE ONLY. When true, skips the server verification call
   * for a host that is itself private/loopback (e.g. localhost, 127.0.0.1, a
   * RFC1918 address). The exemption is PER-HOST: in a multi-host scope it
   * covers only the private/loopback hosts and never extends to any
   * non-private scope host — those still face the server check and the
   * engagement still fails closed exactly as before. This exists so a
   * locally-hosted sandbox target (Juice Shop/DVWA on 127.0.0.1) can be
   * engaged without needing DNS TXT ownership proof, which can't exist for
   * a loopback address anyway. Default false; must be explicitly opted
   * into (CLI --local-sandbox / REDTEAM_LOCAL_SANDBOX=1), never implied.
   */
  allowLocalSandbox?: boolean;
}

/** How one scope host earned (or failed to earn) authorization. */
export interface HostAuthorization {
  /** Normalized hostname that was checked. */
  host: string;
  allowed: boolean;
  /**
   * "server" = the SecScan server lists the host as ownership-verified;
   * "local-sandbox" = per-host private/loopback exemption under
   * --local-sandbox (covers THIS host only); "none" = denied.
   */
  basis: "server" | "local-sandbox" | "none";
  reason?: string;
}

export interface ScopeAuthorizationVerdict extends GateVerdict {
  /** Per-host results, in scope order — every scope host was checked. */
  hosts: HostAuthorization[];
}

/** The per-host check behind both authorization entry points. Fails closed. */
async function checkOneHost(
  host: string,
  cfg: ServerGateConfig,
  verify: VerifyFn,
  opts: CheckAuthorizationOptions,
): Promise<HostAuthorization> {
  let target: string;
  try {
    target = extractDomain(host);
  } catch {
    return { host, allowed: false, basis: "none", reason: `unparseable target: ${host}` };
  }
  if (opts.allowLocalSandbox && isPrivateOrLoopbackHost(target)) {
    return {
      host: target,
      allowed: true,
      basis: "local-sandbox",
      reason:
        `LOCAL SANDBOX MODE: ${target} is a private/loopback target — server ownership ` +
        `verification was skipped (no DNS TXT proof is possible for a loopback address). ` +
        `This bypass never applies to a non-private domain.`,
    };
  }
  let verified = false;
  try {
    verified = await verify(target, { endpoint: cfg.mcpEndpoint, token: cfg.mcpToken });
  } catch {
    verified = false;
  }
  if (!verified) {
    return {
      host: target,
      allowed: false,
      basis: "none",
      reason:
        `domain ${target} is not ownership-verified (server check). ` +
        `Publish the SecScan challenge (start_domain_verification → TXT at ` +
        `_secscan-challenge.${target}) and re-run. Both red and black modes ` +
        `require this proof — covert means covert vs the blue team, never vs ` +
        `the authorization gate.`,
    };
  }
  return { host: target, allowed: true, basis: "server" };
}

/**
 * The single-domain authorization gate: the SecScan server must positively
 * list the domain as verified. Network errors, timeouts, missing token →
 * denied (fail closed). `verify` is injectable so unit tests never touch
 * the network. Kept for single-domain callers; engagements authorize the
 * whole scope via checkScopeAuthorization.
 */
export async function checkAuthorization(
  domain: string,
  cfg: ServerGateConfig,
  verify: VerifyFn = (d, c) => authGateIsServerVerified(d, c),
  opts: CheckAuthorizationOptions = {},
): Promise<GateVerdict> {
  const r = await checkOneHost(domain, cfg, verify, opts);
  return r.reason ? { allowed: r.allowed, reason: r.reason } : { allowed: r.allowed };
}

/**
 * THE engagement authorization gate: EVERY host in the ROE scope must be
 * authorized before aggressive testing — not just the primary domain.
 *  - Private/loopback hosts under --local-sandbox: exempt, per-host only.
 *  - Every other host: the SecScan server must list it ownership-verified.
 * No short-circuit: all hosts are checked, so a denial names every
 * unverified host. Check errors/timeouts deny (fail closed), as always.
 */
export async function checkScopeAuthorization(
  hosts: readonly string[],
  cfg: ServerGateConfig,
  verify: VerifyFn = (d, c) => authGateIsServerVerified(d, c),
  opts: CheckAuthorizationOptions = {},
): Promise<ScopeAuthorizationVerdict> {
  const unique = [...new Set(hosts.map((h) => h.trim().toLowerCase()).filter(Boolean))];
  if (unique.length === 0) {
    return { allowed: false, reason: "no scope hosts to authorize — refusing to run.", hosts: [] };
  }
  const results: HostAuthorization[] = [];
  for (const host of unique) {
    results.push(await checkOneHost(host, cfg, verify, opts));
  }
  const denied = results.filter((r) => !r.allowed);
  if (denied.length > 0) {
    return {
      allowed: false,
      hosts: results,
      reason:
        `ownership verification failed for scope host(s): ${denied.map((r) => r.host).join(", ")} — ` +
        `every host in the ROE scope must be ownership-verified before aggressive testing. ` +
        denied.map((r) => r.reason).filter(Boolean).join(" "),
    };
  }
  const sandbox = results.filter((r) => r.basis === "local-sandbox");
  if (sandbox.length > 0) {
    if (results.length === 1) {
      return { allowed: true, hosts: results, reason: results[0]!.reason };
    }
    const names = sandbox.map((r) => r.host).join(", ");
    const tail =
      sandbox.length === results.length
        ? "This bypass never applies to a non-private domain."
        : "Every other scope host was ownership-verified by the SecScan server; the skip does not extend to them.";
    return {
      allowed: true,
      hosts: results,
      reason:
        `LOCAL SANDBOX MODE: server ownership verification skipped only for private/loopback ` +
        `scope host(s): ${names} (no DNS TXT proof is possible for a loopback address). ${tail}`,
    };
  }
  return { allowed: true, hosts: results };
}
