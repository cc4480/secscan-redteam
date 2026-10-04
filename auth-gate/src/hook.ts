/**
 * Auth-gate decision logic — pure, dependency-free, fully unit-testable.
 *
 * Policy (fail-closed):
 *   - Non-scan tools (reports, verification workflow, everything else) → allow.
 *   - scan_url WITHOUT an explicit active-testing request → allow (passive recon).
 *   - scan_url WITH an explicit active-testing request → allow ONLY if the
 *     target domain is listed by the SecScan server (injected
 *     `isServerVerified`, which must itself fail closed).
 *     Otherwise → deny, with the server verification flow as remediation.
 *
 * The SecScan server is the SOLE source of truth: there is no operator
 * allowlist or any other out-of-band bypass, matching the runner's own gate
 * (runner/src/gate.ts) and the safety case's "no operator exceptions" claim.
 * The gate never issues tokens and performs no DNS of its own.
 */

import { verificationInstructions } from "./verify.js";

export interface PreExecuteEvent {
  toolName: string;
  arguments: Record<string, unknown>;
}

export type GateDecision = { kind: "allow" } | { kind: "deny"; reason: string };

export interface GateContext {
  /**
   * Server-side verdict for a domain. MUST fail closed: any error, timeout,
   * or missing credential returns false. Injected so unit tests need no network.
   * This is the gate's only authorization input — there is no allowlist bypass.
   */
  isServerVerified: (domain: string) => Promise<boolean>;
}

/** Base tool name, tolerating the harness MCP namespace (mcp__secscan__scan_url). */
function baseName(toolName: string): string {
  const parts = toolName.split("__");
  return parts[parts.length - 1] ?? toolName;
}

/** True for the scan-dispatching tool, namespaced or not. */
export function isScanTool(toolName: string): boolean {
  return baseName(toolName) === "scan_url";
}

const URL_KEYS = ["url", "target", "target_url", "site", "site_url"];

/** Extract the target domain from tool arguments, or null. */
export function targetDomain(args: Record<string, unknown>): string | null {
  for (const key of URL_KEYS) {
    const v = args[key];
    if (typeof v === "string" && v.length > 0) {
      try {
        return new URL(v).hostname.toLowerCase();
      } catch {
        // Not a parseable URL under this key — try the next one.
      }
    }
  }
  return null;
}

/** True when the model explicitly asks for active/intrusive testing. */
export function wantsActiveTesting(args: Record<string, unknown>): boolean {
  for (const [k, v] of Object.entries(args)) {
    if (/aggress|active|intrusive/i.test(k) && !!v) return true;
    if (
      typeof v === "string" &&
      /^(aggressive|active|intrusive)([-_ ]?(test|scan|probe|mode|tier)s?)?$/i.test(v.trim())
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Pure decision function. `ctx.isServerVerified` is the only impure input
 * and is wrapped defensively: a throw can never become an allow.
 */
export async function decide(
  event: PreExecuteEvent,
  ctx: GateContext,
): Promise<GateDecision> {
  // Non-scan tools never need authorization: read-only tools, the domain
  // verification workflow itself, and everything else pass through.
  if (!isScanTool(event.toolName)) {
    return { kind: "allow" };
  }

  const args = event.arguments ?? {};

  // Passive scans are recon, not attack — always allowed.
  if (!wantsActiveTesting(args)) {
    return { kind: "allow" };
  }

  const domain = targetDomain(args);
  if (!domain) {
    return {
      kind: "deny",
      reason: "[auth-gate] denied: no parseable target URL in the scan arguments.",
    };
  }

  // The only proof path: the SecScan server's own verified-domain list.
  let verified = false;
  try {
    verified = await ctx.isServerVerified(domain);
  } catch {
    verified = false; // fail closed — a throwing checker can never approve
  }
  if (verified) {
    return { kind: "allow" };
  }

  return {
    kind: "deny",
    reason:
      `[auth-gate] ACTIVE TESTING DENIED for ${domain}.\n` +
      `No domain-ownership proof on file.\n` +
      `${verificationInstructions(domain)}\n` +
      `This block is intentional and cannot be overridden in-chat: unauthorized ` +
      `active testing is illegal. Passive (standard-tier) scans remain available.`,
  };
}
