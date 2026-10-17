/**
 * Operator pairing for the UI console (v0.34.0).
 *
 * Today the console generates a 256-bit bearer token at startup and prints it.
 * That is fine when the operator sits at the machine and wrong when they do not:
 * a long token gets pasted into chat, into a ticket, into a shell history. The
 * pairing flow replaces the paste with a short-lived, single-use, guess-limited
 * code exchanged for a session token over the authenticated channel.
 *
 * Ported from AlterEgo's verified implementation (6-digit, 30-minute TTL,
 * single-use, 5-guess lockout, manual re-arm). Deliberately transport-agnostic:
 * `exchange()` takes the presented code and returns a token, so the server route
 * and the CLI can share one implementation, and the whole thing is unit-testable
 * without a socket.
 *
 * Opt-in: REDTEAM_PAIRING=1 enables it. Without that the console keeps the
 * printed-token behaviour exactly as before.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";

export const PAIRING_TTL_MS = 30 * 60 * 1000;
export const PAIRING_MAX_ATTEMPTS = 5;
export const PAIRING_ENV_ENABLE = "REDTEAM_PAIRING";

export interface PairingState {
  locked: boolean;
  consumed: boolean;
  attemptsRemaining: number;
  expiresAt: number;
}

export interface ExchangeResult {
  ok: boolean;
  token?: string;
  reason?: string;
  state: PairingState;
}

/** True when the operator opted into pairing. */
export function pairingEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return (env[PAIRING_ENV_ENABLE] ?? "").trim() === "1";
}

export class PairingManager {
  private code = "";
  private expiresAt = 0;
  private consumed = false;
  private failures = 0;
  private readonly now: () => number;
  /** Token factory is injectable so tests are deterministic. */
  private readonly mintToken: () => string;

  constructor(opts: { now?: () => number; mintToken?: () => string } = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.mintToken = opts.mintToken ?? (() => randomBytes(32).toString("hex"));
  }

  /** Mint a fresh 6-digit code, resetting consumption and failures. */
  newCode(): string {
    this.code = String(Math.floor(Math.random() * 1_000_000)).padStart(6, "0");
    this.expiresAt = this.now() + PAIRING_TTL_MS;
    this.consumed = false;
    this.failures = 0;
    return this.code;
  }

  state(): PairingState {
    return {
      locked: this.isLocked(),
      consumed: this.consumed,
      attemptsRemaining: Math.max(0, PAIRING_MAX_ATTEMPTS - this.failures),
      expiresAt: this.expiresAt,
    };
  }

  isLocked(): boolean {
    return this.failures >= PAIRING_MAX_ATTEMPTS;
  }

  /** True when a fresh code should be minted (consumed or expired, not locked). */
  needsRefresh(): boolean {
    return !this.isLocked() && (this.consumed || this.now() > this.expiresAt);
  }

  /** Operator-side re-arm: clears the lockout. */
  rearm(): void {
    this.failures = 0;
  }

  /** Constant-time code comparison. Never reveals how close a guess was. */
  private matches(presented: string): boolean {
    const a = Buffer.from(presented.trim());
    const b = Buffer.from(this.code);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  }

  /**
   * Exchange a presented code for a session token. Fails closed and never
   * distinguishes "wrong code" from "expired" beyond the honest reason text.
   */
  exchange(presented: string): ExchangeResult {
    if (this.isLocked()) return { ok: false, reason: "pairing unavailable (locked — re-arm to continue)", state: this.state() };
    if (this.consumed) return { ok: false, reason: "pairing code already used", state: this.state() };
    if (this.code === "" || this.now() > this.expiresAt) {
      return { ok: false, reason: "pairing code expired — request a new one", state: this.state() };
    }
    if (!this.matches(presented)) {
      this.failures += 1;
      const remaining = Math.max(0, PAIRING_MAX_ATTEMPTS - this.failures);
      return { ok: false, reason: `wrong code (${remaining} attempt${remaining === 1 ? "" : "s"} remaining)`, state: this.state() };
    }
    this.consumed = true;
    return { ok: true, token: this.mintToken(), state: this.state() };
  }
}

/** Render the operator-facing instructions for the console banner. */
export function pairingInstructions(code: string): string {
  return [
    `Pairing code: ${code}`,
    `Valid ${PAIRING_TTL_MS / 60000} minutes, single use, ${PAIRING_MAX_ATTEMPTS} attempts.`,
    "Exchange it with: redteam-runner pair --code <code> --url <console-url>",
  ].join("\n");
}
