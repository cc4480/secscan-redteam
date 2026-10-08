/**
 * Header / CORS / TLS variant library (v0.20.0) — header combination
 * matrices for trust-boundary probing (client-IP headers, CORS reflection,
 * downgrade shapes). Each entry is a header (or header set) to send and
 * observe — detection only.
 */
import type { VariantClass, VariantPayload } from "./types.js";

function v(kind: VariantClass, payload: string, whatItTests: string): VariantPayload {
  return { kind, payload, whatItTests };
}

export const HEADER_VARIANTS: VariantPayload[] = [
  v("headers", "X-Forwarded-For: 127.0.0.1", "client-IP header trust"),
  v("headers", "X-Forwarded-Host: evil.example", "forwarded-host trust"),
  v("headers", "X-Real-IP: 127.0.0.1", "real-IP header trust"),
  v("headers", "Forwarded: for=127.0.0.1", "RFC 7239 forwarded header"),
  v("headers", "X-Custom-IP-Authorization: 127.0.0.1", "custom IP-auth header"),
  v("headers", "True-Client-IP: 127.0.0.1", "CDN client-IP header"),
  v("headers", "Origin: https://evil.example", "CORS origin reflection"),
  v("headers", "Origin: null", "CORS null-origin handling"),
  v("headers", "Access-Control-Request-Method: PUT", "CORS preflight method"),
  v("headers", "Access-Control-Request-Headers: x-custom", "CORS preflight headers"),
  v("headers", "Upgrade-Insecure-Requests: 0", "TLS downgrade signal"),
  v("headers", "Host: (empty)", "empty Host header handling"),
  v("headers", "Origin: https://evil-target.com", "CORS regex-bypass shape"),
  v("headers", "Origin: https://target.evil.example", "CORS subdomain-trust bypass"),
  v("headers", "X-Original-URL: /admin", "original-URL rewrite trust"),
  v("headers", "X-Rewrite-URL: /admin", "IIS rewrite-URL trust"),
  v("headers", "X-Host: evil.example", "alternate host header trust"),
  v("headers", "X-Forwarded-Proto: http", "proto-downgrade trust"),
  v("headers", "X-HTTP-Method-Override: PUT", "method-override header trust"),
  v("headers", "CF-Connecting-IP: 127.0.0.1", "Cloudflare client-IP trust"),
  v("headers", "Transfer-Encoding: chunked", "TE-only smuggling probe shape"),
  v("headers", "Content-Length: 0; Transfer-Encoding: chunked", "CL.TE desync probe shape"),
];
