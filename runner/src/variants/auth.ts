/**
 * Auth/session variant library (v0.20.0) — parameter and header
 * combinations for access-control probing. Detection only: no credential
 * brute force beyond ROE-authorized test accounts, no state-changing
 * method overrides (overrides use safe values).
 */
import type { VariantClass, VariantPayload } from "./types.js";

function v(kind: VariantClass, payload: string, whatItTests: string): VariantPayload {
  return { kind, payload, whatItTests };
}

export const AUTH_VARIANTS: VariantPayload[] = [
  v("auth", "?admin=true", "boolean admin parameter"),
  v("auth", "?role=admin", "role parameter"),
  v("auth", "?user_id=1", "identifier parameter (read-only IDOR shape)"),
  v("auth", "?id=1&id=2", "duplicate-parameter pollution"),
  v("auth", "X-Original-URL: /admin", "original-URL header override"),
  v("auth", "X-Rewrite-URL: /admin", "rewrite-URL header override"),
  v("auth", "X-HTTP-Method-Override: GET", "method-override header (safe value)"),
  v("auth", "?_method=GET", "method parameter (safe value)"),
  v("auth", "Referer: https://trusted.example/", "referer check bypass shape"),
  v("auth", "Origin: https://trusted.example/", "origin check bypass shape"),
  v("auth", "?debug=true", "debug-mode parameter"),
  v("auth", "?test=1", "test-mode parameter"),
  v("auth", "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJwcm9iZSJ9.", "JWT none-algorithm acceptance shape (unsigned sentinel, detection only)"),
  v("auth", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uL2tleSJ9.cHJvYmU.c2ln", "JWT kid-traversal shape (synthetic token, detection only)"),
  v("auth", "Cookie: sessionid=FIXATION_PROBE_000", "session fixation shape (benign sentinel value)"),
  v("auth", "Cookie: session=probe; Secure", "Secure cookie-attribute observation shape"),
  v("auth", "Cookie: session=probe; HttpOnly", "HttpOnly cookie-attribute observation shape"),
  v("auth", "Cookie: session=probe; SameSite=None", "SameSite cookie-attribute observation shape"),
  v("auth", "?response_type=token", "OAuth implicit-flow parameter shape"),
  v("auth", "?redirect_uri=https://trusted.example/cb", "OAuth redirect-uri parameter shape (benign value)"),
  v("auth", "?api_key=PROBE_KEY_000", "API key in query parameter shape (sentinel value)"),
  v("auth", "X-API-Key: PROBE_KEY_000", "API key in header shape (sentinel value)"),
  v("auth", "?role_id=1", "numeric role-ID enumeration shape"),
  v("auth", "?reset_token=PROBE_TOKEN_000", "password-reset token format shape (sentinel value)"),
];
