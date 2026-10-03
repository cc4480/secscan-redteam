/**
 * Loop watch cycles on the profile's cadence until aborted.
 */

import { loadWatchProfile } from "../profile.js";
import type { WatchCycleOptions } from "./types.js";
import { runWatchCycle } from "./cycle.js";

export async function watchLoop(
  opts: WatchCycleOptions,
  signal?: AbortSignal,
): Promise<void> {
  for (;;) {
    if (signal?.aborted) return;
    let intervalHours = 24;
    try {
      const profile = loadWatchProfile(opts.profilePath);
      intervalHours = profile.cadence.intervalHours;
      const result = await runWatchCycle({ ...opts, once: true });
      console.log(
        `[watch] cycle ${result.status}${result.engagementId ? ` ${result.engagementId}` : ""}` +
          (result.drift
            ? ` — new:${result.drift.newFindings.length} reopened:${result.drift.reopened.length} remediated:${result.drift.remediated.length} needs-review:${result.drift.needsReview.length}`
            : "") +
          (result.reason ? ` — ${result.reason}` : ""),
      );
    } catch (err) {
      console.log(`[watch] cycle error (loop continues): ${(err as Error).message}`);
    }
    const waitMs = Math.max(60_000, intervalHours * 3600_000);
    await new Promise<void>((resolve) => {
      const t = setTimeout(resolve, waitMs);
      signal?.addEventListener("abort", () => {
        clearTimeout(t);
        resolve();
      }, { once: true });
    });
  }
}
