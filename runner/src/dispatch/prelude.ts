/**
 * Dispatch prelude helpers (v0.19.0 refactor — extracted from dispatch.ts).
 */
import { type Ctx } from "../context.js";
import { checkAuthorization } from "../gate.js";

export async function recheckVerified(ctx: Ctx): Promise<boolean> {
  // Cache the authorize-phase proof for 5 minutes; re-check after that.
  if (ctx.verifiedAt && Date.now() - Date.parse(ctx.verifiedAt) < 5 * 60_000) return true;
  const v = await checkAuthorization(
    ctx.domain,
    { mcpEndpoint: ctx.config.mcpEndpoint, mcpToken: ctx.config.mcpToken },
    ctx.deps.verify,
    { allowLocalSandbox: ctx.config.localSandbox },
  );
  if (v.allowed) ctx.verifiedAt = new Date().toISOString();
  return v.allowed;
}


/** Optional string arg: trimmed, or undefined when absent/blank. */
export function optStr(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/** Optional positive-number arg, or undefined when absent/invalid. */
export function numArg(v: unknown): number | undefined {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() ? Number(v) : NaN;
  return Number.isFinite(n) && n > 0 ? n : undefined;
}
