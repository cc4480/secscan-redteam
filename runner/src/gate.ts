/**
 * Engagement-level gating. Every check fails closed: uncertainty → deny.
 *
 * Layers (all must pass before aggressive work):
 *  1. Server-authoritative ownership verification (auth-gate's isServerVerified).
 *  2. Scope: every probed/scanned URL's hostname must be an exact in-scope host.
 *  3. Technique exclusions: always-excluded + mode defaults + ROE exclusions.
 *  4. Blackout windows: the runner pauses, it does not skip.
 *  5. Test window: the runner refuses to run outside the agreed window.
 */

import { isServerVerified as authGateIsServerVerified } from "@secscan/redteam-auth-gate";
import { extractDomain } from "@secscan/redteam-auth-gate";
import { resolveExcludedTechniques } from "./attack.js";
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

/**
 * The authorization gate: the SecScan server must positively list the domain
 * as verified. Network errors, timeouts, missing token → denied (fail closed).
 * `verify` is injectable so unit tests never touch the network.
 */
export async function checkAuthorization(
  domain: string,
  cfg: ServerGateConfig,
  verify: (
    domain: string,
    cfg: { endpoint: string; token: string },
  ) => Promise<boolean> = (d, c) => authGateIsServerVerified(d, c),
): Promise<GateVerdict> {
  let target: string;
  try {
    target = extractDomain(domain);
  } catch {
    return { allowed: false, reason: `unparseable target: ${domain}` };
  }
  let verified = false;
  try {
    verified = await verify(target, { endpoint: cfg.mcpEndpoint, token: cfg.mcpToken });
  } catch {
    verified = false;
  }
  if (!verified) {
    return {
      allowed: false,
      reason:
        `domain ${target} is not ownership-verified (server check). ` +
        `Publish the SecScan challenge (start_domain_verification → TXT at ` +
        `_secscan-challenge.${target}) and re-run. Both red and black modes ` +
        `require this proof — covert means covert vs the blue team, never vs ` +
        `the authorization gate.`,
    };
  }
  return { allowed: true };
}
