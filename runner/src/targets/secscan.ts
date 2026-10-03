/**
 * SecScan target profile — the scanner webapp (https://secscan.us).
 *
 * EXHAUSTIVE battery (v0.7.0): surface × technique. Every distinct attacker
 * intent against the real surface is one item. Surfaces: scan intake
 * (URL field + options), SSRF guard, DNS TXT ownership gate, scan
 * lifecycle, scan listing, report view/export, share links, AI opt-out,
 * rate limits, auth/session, API surface, TLS/headers/CORS, error
 * handlers, scanner-efficacy canaries, cross-cutting.
 *
 * Non-destructive always: never trigger emails to real users, never delete
 * scans/reports, benign canary content only, races are single paired
 * requests. Items needing setup say so in `needs` — honestly.
 */

import type { TargetBatteryItem, TargetProfile } from "./types.js";
import { SECSCAN_PART_1 } from "./secscan-part-1.js";
import { SECSCAN_PART_2 } from "./secscan-part-2.js";
import { SECSCAN_PART_3 } from "./secscan-part-3.js";
import { SECSCAN_PART_4 } from "./secscan-part-4.js";

const SECSCAN_BATTERY: TargetBatteryItem[] = [
  ...SECSCAN_PART_1,
  ...SECSCAN_PART_2,
  ...SECSCAN_PART_3,
  ...SECSCAN_PART_4,
];

export const SECSCAN_PROFILE: TargetProfile = {
  id: "secscan",
  name: "SecScan — scanner web app",
  baseUrl: "https://secscan.us",
  kind: "webapp",
  authModel: "DNS TXT ownership gate (_secscan-challenge.<domain>, server-authoritative) + session auth for reports/shares; scan intake rate-limited per namespace.",
  scopeNotes: "In-scope: secscan.us webapp surface (intake, scan lifecycle, reports, share links). Out-of-scope: anything not on the scoped host; no emails to real users; no scan/report deletion.",
  battery: SECSCAN_BATTERY,
};
