/**
 * Token auth for the UI server (v0.22.0).
 *
 * The UI controls live pentest tooling, so it is a privileged console:
 *  - binds loopback only by default (see server.ts)
 *  - a random 256-bit token is generated at startup and printed to the
 *    terminal — it is never written to disk
 *  - every /api/* call needs it as `Authorization: Bearer <token>` or the
 *    HttpOnly SameSite=Strict cookie set by POST /api/auth
 *  - the dashboard page itself is gated the same way
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";

export const UI_COOKIE = "redteam_ui";

export function generateToken(): string {
  return randomBytes(32).toString("hex");
}

function bearerToken(req: IncomingMessage): string | undefined {
  const h = req.headers["authorization"];
  if (typeof h === "string" && h.startsWith("Bearer ")) {
    const t = h.slice(7).trim();
    return t ? t : undefined;
  }
  return undefined;
}

function cookieToken(req: IncomingMessage): string | undefined {
  const h = req.headers["cookie"];
  if (typeof h !== "string") return undefined;
  for (const part of h.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === UI_COOKIE) {
      const v = rest.join("=").trim();
      return v ? decodeURIComponent(v) : undefined;
    }
  }
  return undefined;
}

/** Constant-time token check against bearer header or auth cookie. */
export function tokensEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function isAuthorized(req: IncomingMessage, token: string): boolean {
  const presented = bearerToken(req) ?? cookieToken(req);
  if (!presented) return false;
  return tokensEqual(presented, token);
}

/**
 * Fail fast on a weak explicit REDTEAM_UI_TOKEN (v0.28.0). A generated
 * token is 64 hex chars; anything operator-supplied must clear a floor:
 * at least 16 characters and not a well-known weak value. Loopback-only
 * binding mitigates network exposure, but this console drives live pentest
 * tooling — "password" must never unlock it.
 */
const WEAK_TOKENS = new Set([
  "password", "passw0rd", "admin", "redteam", "secscan", "token", "secret",
  "changeme", "12345678", "123456789", "qwerty", "letmein", "redteam-ui",
]);
export function assertStrongToken(token: string): void {
  const t = token.trim();
  if (t.length < 16 || WEAK_TOKENS.has(t.toLowerCase())) {
    throw new Error(
      "[ui] REDTEAM_UI_TOKEN is too weak — use at least 16 characters that are not a common password. " +
        "Unset it to have the server generate a strong random token at startup instead.",
    );
  }
}

/** Set-Cookie value for a successful POST /api/auth. */
export function authCookie(token: string): string {
  return `${UI_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`;
}
