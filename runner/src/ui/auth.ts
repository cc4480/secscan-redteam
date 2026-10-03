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
export function isAuthorized(req: IncomingMessage, token: string): boolean {
  const presented = bearerToken(req) ?? cookieToken(req);
  if (!presented) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(token);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Set-Cookie value for a successful POST /api/auth. */
export function authCookie(token: string): string {
  return `${UI_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`;
}
