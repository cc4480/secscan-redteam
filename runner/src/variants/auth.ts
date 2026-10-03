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
];
