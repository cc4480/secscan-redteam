/**
 * Webapp target profile - a GENERIC client web application (v0.35.0).
 *
 * This is the customer-facing battery (WA-001..WA-120). It is the executable
 * form of the SecScan (VibeScan-Enterprise-Build) and Seclayer (seclayer.io2026)
 * scan corpora, so the agents run those checks natively against a client's
 * application instead of only through the two scanner products.
 *
 * It is OPT-IN: `--targets webapp` (CLI) or the start_engagement `targets`
 * argument (harness/agents). It is deliberately NOT part of
 * FULL_BATTERY_TARGETS, because against secscan.us / seclayer.app the generic
 * webapp battery would duplicate the SS-* / SL-* product-surface batteries.
 *
 * Unlike the four vendor batteries, the target host is the engagement's own
 * scope, so baseUrl is a placeholder rather than a fixed host.
 *
 * Non-destructive always: no request whose success changes customer data;
 * writes only as dry runs (for example Supabase INSERT with
 * `Prefer: tx=rollback` against a field no real schema has); DELETE only
 * against identifiers that cannot exist; no PUT; no bulk data extraction.
 * Items whose prerequisite is absent carry `needs` and report under Honest
 * limits - never pretending a test ran.
 */

import type { TargetBatteryItem, TargetProfile } from "./types.js";
import { WEBAPP_PART_1 } from "./webapp-part-1.js";
import { WEBAPP_PART_2 } from "./webapp-part-2.js";
import { WEBAPP_PART_3 } from "./webapp-part-3.js";
import { WEBAPP_PART_4 } from "./webapp-part-4.js";
import { WEBAPP_PART_5 } from "./webapp-part-5.js";

const WEBAPP_BATTERY: TargetBatteryItem[] = [
  ...WEBAPP_PART_1,
  ...WEBAPP_PART_2,
  ...WEBAPP_PART_3,
  ...WEBAPP_PART_4,
  ...WEBAPP_PART_5,
];

export const WEBAPP_PROFILE: TargetProfile = {
  id: "webapp",
  name: "Webapp - client web application",
  baseUrl: "(engagement target)",
  kind: "webapp",
  authModel:
    "Per engagement, stated in the ROE: anonymous, a supplied session cookie or Bearer token, a headless form login, or (for access-control items) two independent test accounts.",
  scopeNotes:
    "In-scope: the engagement's declared hosts only, exactly as the ROE scope lists them. Out-of-scope: any host not in scope; no emails to real users; no real data extraction; no destructive writes (dry-run writes only, no PUT, DELETE only against identifiers that cannot exist).",
  battery: WEBAPP_BATTERY,
};
