/**
 * Traversal / SSRF / open-redirect variant libraries (v0.20.0).
 *
 * Honesty rule inherited from the battery's SSRF items: these are SHAPES
 * for testing a guard's verdict (does it refuse the landing?), never live
 * internal fetches. `{{CANARY}}` = operator canary host placeholder.
 * The agent substitutes canary infrastructure it controls.
 */
import type { VariantClass, VariantPayload } from "./types.js";

function v(kind: VariantClass, payload: string, whatItTests: string): VariantPayload {
  return { kind, payload, whatItTests };
}

/** Path traversal — separators, encodings, bypass shapes. Read-only targets. */
export const TRAVERSAL_VARIANTS: VariantPayload[] = [
  v("traversal", "../../../etc/passwd", "classic dot-dot-slash"),
  v("traversal", "..\\..\\..\\windows\\win.ini", "windows backslash"),
  v("traversal", "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "encoded dots"),
  v("traversal", "%252e%252e/%252e%252e/etc/passwd", "double-encoded dots"),
  v("traversal", "....//....//etc/passwd", "double-slash bypass"),
  v("traversal", "..;/..;/etc/passwd", "semicolon bypass"),
  v("traversal", "/etc/passwd", "absolute path"),
  v("traversal", "....\\/....\\/etc/passwd", "mixed slash escaping"),
  v("traversal", "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "overlong UTF-8 dots"),
  v("traversal", "/var/www/html/../../../etc/passwd", "prefixed traversal"),
  v("traversal", "....\\\\....\\\\windows\\\\win.ini", "windows double-backslash bypass"),
  v("traversal", "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", "encoded backslashes"),
  v("traversal", "..%2f..%2fetc%2fpasswd", "encoded slashes only"),
  v("traversal", ".%2e/.%2e/.%2e/etc/passwd", "dot-mixed encoding"),
  v("traversal", "..%c0%af..%c0%afetc/passwd", "mixed overlong separator"),
];

/**
 * SSRF — guard-verdict shapes. Every "internal-looking" value below is a
 * canary-shaped probe: the question is whether the GUARD refuses it, not
 * whether a fetch succeeds. Never a real internal address.
 */
export const SSRF_VARIANTS: VariantPayload[] = [
  v("ssrf", "http://{{CANARY}}/", "baseline canary fetch (control)"),
  v("ssrf", "http://127.0.0.1/", "loopback literal — guard must refuse"),
  v("ssrf", "http://localhost/", "localhost name — guard must refuse"),
  v("ssrf", "http://0.0.0.0/", "any-address — guard must refuse"),
  v("ssrf", "http://2130706433/", "decimal-encoded loopback"),
  v("ssrf", "http://0177.0.0.1/", "octal-encoded loopback"),
  v("ssrf", "http://0x7f.0.0.1/", "hex-encoded loopback"),
  v("ssrf", "http://[::ffff:127.0.0.1]/", "IPv6-mapped loopback"),
  v("ssrf", "http://{{CANARY}}@127.0.0.1/", "userinfo @ trick shape"),
  v("ssrf", "gopher://{{CANARY}}/", "gopher scheme — allowlist test"),
  v("ssrf", "dict://{{CANARY}}/", "dict scheme — allowlist test"),
  v("ssrf", "file:///etc/passwd", "file scheme — allowlist test"),
  v("ssrf", "http://127.1/", "short-form loopback"),
  v("ssrf", "http://0/", "zero-address shape"),
  v("ssrf", "https://{{CANARY}}%2e127.0.0.1/", "encoded-dot confusion shape"),
];

/** Open redirect — landing-control shapes. */
export const REDIRECT_VARIANTS: VariantPayload[] = [
  v("redirect", "//evil.example/", "scheme-relative redirect"),
  v("redirect", "https://evil.example/", "absolute external URL"),
  v("redirect", "/\\/evil.example/", "backslash confusion"),
  v("redirect", "%2f%2fevil.example%2f", "fully encoded slashes"),
  v("redirect", "//evil%2eexample/", "encoded dot in host"),
  v("redirect", "https://trusted.example@evil.example/", "userinfo @ trick"),
  v("redirect", "https://evil.example%2f..", "encoded path confusion"),
  v("redirect", "javascript:alert(1)", "javascript scheme landing"),
  v("redirect", "data:text/html,<script>alert(1)</script>", "data scheme landing"),
  v("redirect", "/%09/evil.example/", "tab-in-path confusion"),
];
