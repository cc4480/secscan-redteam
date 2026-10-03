/**
 * Staging → production graduation (v0.13.0) — the production safety case.
 *
 * Buyers graduate testing: the full battery runs against staging freely;
 * production requires an explicit operator decision plus tighter limits.
 * This is MECHANICAL, not prompt-based:
 *
 *  - `staging` (default): full battery, configured rate limits.
 *  - `production`: requires explicit confirmation
 *    (REDTEAM_PROD_CONFIRM=1 or CLI --confirm-production) — without it the
 *    runner refuses to start, fail fast, before any packet. Production also
 *    caps the per-host rate limit at 2 rps even if configured higher.
 *
 * The manifest records the environment and whether confirmation was given,
 * so the compliance pack's safety section shows the graduation decision.
 */

export type TestEnvironment = "staging" | "production";

export const PROD_CONFIRM_ENV = "REDTEAM_PROD_CONFIRM";
export const ENV_SELECT_ENV = "REDTEAM_ENV";

/** Parse the environment from CLI/env; anything unknown fails closed to staging? No — fails LOUD. */
export function parseEnvironment(raw: string | undefined): TestEnvironment {
  const v = (raw ?? "").trim().toLowerCase();
  if (!v || v === "staging") return "staging";
  if (v === "production" || v === "prod") return "production";
  throw new Error(
    `[safety] unknown test environment ${JSON.stringify(raw)} — want "staging" or "production". Refusing to guess.`,
  );
}

/** True when the operator explicitly confirmed a production run. */
export function productionConfirmed(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = (env[PROD_CONFIRM_ENV] ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

/**
 * Mechanical graduation gate. Call before ANY active testing (the runner
 * calls it at engagement start, before the authorize phase). Production
 * without explicit confirmation is a hard refusal — the operator must type
 * the confirmation, not the agent.
 */
export function requireGraduation(environment: TestEnvironment, confirmed: boolean): void {
  if (environment === "production" && !confirmed) {
    throw new Error(
      `[safety] PRODUCTION environment selected but not confirmed. ` +
        `Set ${PROD_CONFIRM_ENV}=1 (or pass --confirm-production) to confirm you intend to test PRODUCTION infrastructure. ` +
        `Without explicit operator confirmation the runner refuses to start.`,
    );
  }
}

/** One-line description for the manifest and the engagement_start event. */
export function describeEnvironment(environment: TestEnvironment, confirmed: boolean): string {
  return environment === "production"
    ? `production (operator-confirmed${confirmed ? "" : " — INVALID STATE"})`
    : "staging";
}
