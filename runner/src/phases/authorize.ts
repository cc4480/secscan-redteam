/**
 * Authorization phase (v0.19.0 refactor — extracted from phases.ts).
 */
import { type Ctx } from "../context.js";
import { type GateVerdict, checkAuthorization } from "../gate.js";
import { join } from "node:path";

export async function authorizePhase(ctx: Ctx): Promise<GateVerdict> {
  const verdict = await checkAuthorization(
    ctx.domain,
    { mcpEndpoint: ctx.config.mcpEndpoint, mcpToken: ctx.config.mcpToken },
    ctx.deps.verify,
    { allowLocalSandbox: ctx.config.localSandbox },
  );
  if (!verdict.allowed) {
    ctx.events.append({ phase: "authorize", actor: "coordinator", action: "authorization_denied", target: ctx.domain, result: verdict.reason ?? "denied" });
    ctx.events.updateState({ status: "blocked", phase: "blocked", blockedReason: verdict.reason });
    return verdict;
  }
  ctx.verifiedAt = new Date().toISOString();
  ctx.verificationProof = verdict.reason
    ? `${verdict.reason} (${ctx.verifiedAt})`
    : `SecScan server lists ${ctx.domain} as ownership-verified (${ctx.verifiedAt}).`;
  ctx.events.append({
    phase: "authorize",
    actor: "coordinator",
    action: "authorization_basis",
    target: ctx.domain,
    result: `${ctx.verificationProof} Mode: ${ctx.input.mode.toUpperCase()}. Objective: ${ctx.input.objective}. Scope: ${ctx.hosts.join(", ")}.`,
  });
  ctx.events.updateState({
    status: "running",
    verified: true,
    verificationTs: ctx.verifiedAt,
    verificationProof: ctx.verificationProof,
  });
  return verdict;
}

