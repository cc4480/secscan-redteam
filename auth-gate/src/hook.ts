/**
 * Harness-side auth gate: a `tools/pre-execute` hook in the documented
 * permission-gate shape (deepseek-harness docs/cookbook/extension-cookbook.md).
 *
 * Policy:
 *   - seclayer_list_scans / seclayer_get_report → always allowed (read-only).
 *   - seclayer_scan standard tier (aggressive !== true) → allowed (passive recon).
 *   - seclayer_scan aggressive=true → allowed ONLY when verifyOwnership()
 *     proves the target domain for the current engagement token.
 *   - anything else → allowed (this gate only polices active testing).
 *
 * Denials carry the exact remediation (TXT record instructions), so the
 * coordinator can relay them to the operator without guessing.
 */

import { extractDomain, verifyOwnership } from "./verify.js";

export interface PreExecuteEvent {
  toolName: string;
  arguments: Record<string, unknown>;
}

export type GateDecision = { kind: "allow" } | { kind: "deny"; reason: string };

/**
 * Pure decision function — easy to unit test, no harness imports.
 * `engagementToken` is the token issued for this engagement (env
 * SECSCAN_ENGAGEMENT_TOKEN at runtime). Undefined token ⇒ fail closed.
 */
export async function decide(
  event: PreExecuteEvent,
  engagementToken: string | undefined,
): Promise<GateDecision> {
  const { toolName, arguments: args } = event;

  // Read-only tools never need authorization.
  if (toolName === "seclayer_list_scans" || toolName === "seclayer_get_report") {
    return { kind: "allow" };
  }

  if (toolName !== "seclayer_scan") {
    return { kind: "allow" };
  }

  // Standard tier is passive recon — always allowed.
  if (args["aggressive"] !== true) {
    return { kind: "allow" };
  }

  const rawUrl = typeof args["url"] === "string" ? args["url"] : "";
  let domain: string;
  try {
    domain = extractDomain(rawUrl);
  } catch {
    return { kind: "deny", reason: `[auth-gate] denied: '${rawUrl}' is not a valid URL.` };
  }

  const proof = await verifyOwnership(rawUrl, engagementToken);
  if (proof.ok) {
    return { kind: "allow" };
  }

  return {
    kind: "deny",
    reason:
      `[auth-gate] ACTIVE TESTING DENIED for ${domain}.\n` +
      `No domain-ownership proof found for the current engagement token.\n` +
      `${proof.instructions ?? ""}\n` +
      `This block is intentional and cannot be overridden in-chat: unauthorized ` +
      `active testing is illegal. Passive (standard-tier) scans remain available.`,
  };
}

/**
 * Installs the gate on a harness context. The context shape is structural
 * (see harness-plugin/src/harness-types.ts) so this package stays
 * dependency-free.
 */
export function installAuthGate(
  ctx: {
    on(
      event: "tools/pre-execute",
      handler: (exec: PreExecuteEvent, next: () => Promise<GateDecision>) => Promise<GateDecision>,
    ): void;
  },
  getEngagementToken: () => string | undefined,
): void {
  ctx.on("tools/pre-execute", async (exec, next) => {
    const decision = await decide(exec, getEngagementToken());
    if (decision.kind === "deny") return decision;
    return next();
  });
}
