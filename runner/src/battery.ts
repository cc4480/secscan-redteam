/**
 * The systematic attack battery — what "ruthless" means, concretely.
 *
 * Every engagement's exploiter must form hypotheses spanning ALL THREE
 * categories before the battery is considered complete:
 *
 *  1. LOGIC FLAWS (business-logic abuse) — the app used against its own rules.
 *  2. FUNCTIONALITY ABUSE — every exposed feature exercised adversarially.
 *  3. ACCURACY / VALIDATION RIGOR — the input layer tested for strictness.
 *
 * Each item carries its OWASP reference (WSTG / API Top 10) and an ATT&CK
 * technique ID where one honestly fits; business-logic abuse mostly maps to
 * T1190 (Exploit Public-Facing Application) as the ATT&CK bucket, with the
 * specific flaw class named per-event. Where no ATT&CK technique fits, the
 * OWASP reference stands alone — the mapping is advisory, never forced.
 *
 * Black-team mode runs the SAME battery, stealth-weighted: low-noise variants
 * first (see blackNote), immediate backoff on any detection signal.
 *
 * Non-destructive always: race conditions are single paired requests, never
 * floods; file uploads carry benign canary content only; no state is left
 * mutated beyond what the app's own normal flows would do.
 */

export type BatteryCategory = "logic" | "functionality" | "validation";

export const BATTERY_CATEGORIES: BatteryCategory[] = ["logic", "functionality", "validation"];

export const CATEGORY_LABELS: Record<BatteryCategory, string> = {
  logic: "Logic flaws (business-logic abuse)",
  functionality: "Functionality abuse",
  validation: "Accuracy / validation rigor",
};

export interface BatteryItem {
  id: string; // L-1…L-8, F-1…F-8, V-1…V-8
  category: BatteryCategory;
  name: string;
  owasp: string;
  /** ATT&CK technique ID where one honestly fits; otherwise undefined. */
  attackId?: string;
  /** What to test, concretely. */
  what: string;
  /** Stealth-weighted variant for black-team mode. */
  blackNote?: string;
}

export const BATTERY: BatteryItem[] = [
  // ---------------------------------------------------------------- LOGIC
  {
    id: "L-1", category: "logic", name: "Workflow / step-skipping",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Skip, reorder, or replay multi-step flows (checkout, onboarding, wizards). Request later steps directly without completing earlier ones; submit steps out of order.",
    blackNote: "One skipped-step probe per flow; do not crawl every permutation.",
  },
  {
    id: "L-2", category: "logic", name: "Price / quantity / currency manipulation",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Tamper with prices, quantities, totals, and currency codes client-side (cart, invoice, payment-intent creation). Try negative, zero, and fractional quantities; swap currency on an existing amount.",
  },
  {
    id: "L-3", category: "logic", name: "Coupon / discount stacking",
    owasp: "WSTG-BUSL-05", attackId: "T1190",
    what: "Reuse single-use codes, stack multiple codes, apply expired codes, apply codes to ineligible items. Never complete a purchase with a manipulated total — stop at the order-preview/validation response.",
  },
  {
    id: "L-4", category: "logic", name: "Race conditions",
    owasp: "WSTG-BUSL-04", attackId: "T1190",
    what: "Fire a SINGLE pair of near-simultaneous requests against balance/stock/coupon-redemption logic and compare outcomes. Never flood; two requests, one observation.",
    blackNote: "Only where a canary resource exists; skip if the paired request could double-spend real value.",
  },
  {
    id: "L-5", category: "logic", name: "State-machine abuse",
    owasp: "WSTG-BUSL-06", attackId: "T1190",
    what: "Drive objects through invalid transitions (paid→cancelled→refunded, used→unused), replay terminal states, resurrect closed sessions.",
  },
  {
    id: "L-6", category: "logic", name: "Auth-flow logic flaws",
    owasp: "WSTG-ATHN-04", attackId: "T1556",
    what: "Password-reset and change flows: token reuse, missing step validation, change-email without re-authentication, reset for another account's identifier. Use test accounts only; never trigger emails to real users.",
  },
  {
    id: "L-7", category: "logic", name: "Multi-role privilege boundaries",
    owasp: "WSTG-ATHZ-02", attackId: "T1190",
    what: "With the lowest-privilege context available, attempt higher-role actions: role parameter tampering, direct admin-endpoint access, cross-tenant object access.",
  },
  {
    id: "L-8", category: "logic", name: "Negative / zero values",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Wherever money or counts are involved, submit negative, zero, and absurdly large values; observe whether the app validates, clamps, or computes on them.",
  },
  // ------------------------------------------------------- FUNCTIONALITY
  {
    id: "F-1", category: "functionality", name: "IDOR / BOLA",
    owasp: "OWASP API1:2023 / WSTG-ATHZ-04", attackId: "T1190",
    what: "Swap object identifiers (numeric, UUID, encoded) across users/tenants on every object endpoint. Two observations before calling it: the anomalous response AND a control showing the boundary holds elsewhere.",
  },
  {
    id: "F-2", category: "functionality", name: "Mass assignment",
    owasp: "OWASP API3:2023", attackId: "T1190",
    what: "Add unexpected fields to JSON bodies and forms: role, isAdmin, price, balance, userId. Observe whether they bind, validate, or are ignored.",
  },
  {
    id: "F-3", category: "functionality", name: "Hidden / undocumented parameters",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Probe for debug, test, admin, and legacy parameters (debug, preview, admin, _method, callback). One probe per parameter family.",
    blackNote: "Prefer parameters already hinted at in client code over blind guessing.",
  },
  {
    id: "F-4", category: "functionality", name: "HTTP method tampering",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Replay read endpoints as POST/PUT/DELETE/PATCH; try X-HTTP-Method-Override. Note which methods the app actually honors vs rejects.",
  },
  {
    id: "F-5", category: "functionality", name: "Content-type confusion",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Send the same payload as JSON, form-encoded, and plain text; observe whether parsing/validation differs by content type.",
  },
  {
    id: "F-6", category: "functionality", name: "File-upload abuse",
    owasp: "WSTG-BUSL-08/09", attackId: "T1505.003",
    what: "Upload benign canary content with hostile packaging: double extensions, mismatched magic bytes vs extension, SVG with inert markup, oversized-but-capped files. Never upload executable or exfiltrating content.",
    blackNote: "Single canary upload per vector; verify how the app stores/serves it, then stop.",
  },
  {
    id: "F-7", category: "functionality", name: "Pagination / filter / sort abuse",
    owasp: "WSTG-BUSL-01", attackId: "T1190",
    what: "Negative/zero offsets, huge limits, sort on sensitive or non-indexed fields, filter operators (gt/lt/regex) where exposed. Observe data leaks and error differentials.",
  },
  {
    id: "F-8", category: "functionality", name: "Enumeration",
    owasp: "WSTG-ATHN", attackId: "T1087",
    what: "User/ID existence oracles via response differentials (login, reset, signup). Low rate, handful of probes — this is an oracle check, not a harvest.",
    blackNote: "Minimal probes; stop at the first differential — the oracle's existence is the finding.",
  },
  // ---------------------------------------------------------- VALIDATION
  {
    id: "V-1", category: "validation", name: "Type juggling",
    owasp: "WSTG-INPV-01", attackId: "T1190",
    what: "Send arrays where strings are expected, objects where scalars are expected, booleans as strings, numbers as strings and vice versa. Observe coercion, errors, and downstream behavior.",
  },
  {
    id: "V-2", category: "validation", name: "Boundary values",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Max lengths, integer boundaries (2^31, 2^63), empty string vs missing field vs null. One boundary family per field class.",
  },
  {
    id: "V-3", category: "validation", name: "Truncation",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Overlong inputs where storage may truncate (usernames, emails, tokens); test whether truncated values collide or bypass uniqueness.",
  },
  {
    id: "V-4", category: "validation", name: "Encoding / unicode tricks",
    owasp: "WSTG-INPV", attackId: "T1027",
    what: "Double encoding, overlong UTF-8, unicode normalization collisions, homoglyphs in identifiers. Observe whether validation happens pre- or post-normalization.",
  },
  {
    id: "V-5", category: "validation", name: "Regex bypasses",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Newline injection, unanchored-pattern abuse, case tricks against validators. Single probes — never ReDoS floods.",
  },
  {
    id: "V-6", category: "validation", name: "Client-side-only validation",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit directly what the UI forbids (disabled buttons, JS checks, max attributes). The question is always: does the server re-validate?",
  },
  {
    id: "V-7", category: "validation", name: "Error-message oracles",
    owasp: "WSTG-ERRH-01", attackId: "T1592.002",
    what: "Harvest verbose errors for stack traces, schema hints, and existence oracles (different errors for 'bad input' vs 'no such object').",
  },
  {
    id: "V-8", category: "validation", name: "Inconsistent validation between endpoints",
    owasp: "WSTG-INPV", attackId: "T1190",
    what: "Submit the same hostile field to every endpoint that accepts it (create vs update vs import vs admin). Divergent handling is the finding.",
  },
];

const byId = new Map(BATTERY.map((b) => [b.id, b]));

export function lookupBatteryItem(id: string): BatteryItem | undefined {
  return byId.get(id.toUpperCase());
}

export function batteryItemsFor(category: BatteryCategory): BatteryItem[] {
  return BATTERY.filter((b) => b.category === category);
}

/** Compact checklist text for the exploiter prompt. */
export function batteryChecklistText(mode: "red" | "black"): string {
  const lines: string[] = [];
  for (const cat of BATTERY_CATEGORIES) {
    lines.push(`### ${CATEGORY_LABELS[cat]}`);
    for (const item of batteryItemsFor(cat)) {
      const stealth = mode === "black" && item.blackNote ? ` [black: ${item.blackNote}]` : "";
      lines.push(`- ${item.id} ${item.name} (${item.owasp}${item.attackId ? `, ${item.attackId}` : ""}): ${item.what}${stealth}`);
    }
  }
  return lines.join("\n");
}
