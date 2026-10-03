/**
 * Best-effort Slack lifecycle notifications (v0.19.0 refactor — extracted from report.ts).
 */
import { type Ctx } from "../context.js";
import { SlackEvent, notifySlack, resolveSlackConfig } from "../integrations/index.js";

export async function fireSlack(ctx: Ctx, ev: Omit<SlackEvent, "engagementId" | "target" | "mode">): Promise<void> {
  try {
    const cfg = resolveSlackConfig();
    if (!cfg.configured) return;
    await notifySlack(cfg, {
      ...ev,
      engagementId: ctx.events.engagementId,
      target: ctx.input.target,
      mode: ctx.input.mode,
    });
  } catch {
    // best-effort only
  }
}
