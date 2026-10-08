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

/** Path traversal Ã¢â‚¬â€ separators, encodings, bypass shapes. Read-only targets. */
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
  v("traversal", "../../../etc/passwd%00", "null byte injection (legacy)"),
  v("traversal", "%u002e%u002e/%u002e%u002e/etc/passwd", "unicode-encoded dots"),
  v("traversal", "C:\\windows\\win.ini", "windows absolute drive path"),
  v("traversal", "\\\\server\\share\\..\\..\\windows\\win.ini", "UNC path traversal"),
  v("traversal", "../../../../tmp/traversal-test", "zip slip detection (benign target)"),
  v("traversal", "../../../var/log/app.log", "log file access detection (benign)"),
];

/**
 * SSRF Ã¢â‚¬â€ guard-verdict shapes. Every "internal-looking" value below is a
 * canary-shaped probe: the question is whether the GUARD refuses it, not
 * whether a fetch succeeds. Never a real internal address.
 */
export const SSRF_VARIANTS: VariantPayload[] = [
  v("ssrf", "http://{{CANARY}}/", "baseline canary fetch (control)"),
  v("ssrf", "http://loopback.{{CANARY}}/", "loopback name guard-verdict"),
  v("ssrf", "http://localhost.{{CANARY}}/", "localhost name guard-verdict"),
  v("ssrf", "http://0.0.0.0.{{CANARY}}/", "any-address guard-verdict shape"),
  v("ssrf", "http://2130706433/", "decimal-encoded loopback"),
  v("ssrf", "http://0177.0.0.1/", "octal-encoded loopback"),
  v("ssrf", "http://0x7f.0.0.1/", "hex-encoded loopback"),
  v("ssrf", "http://[::ffff:127.0.0.1]/", "IPv6-mapped loopback"),
  v("ssrf", "http://{{CANARY}}@127.0.0.1/", "userinfo @ trick shape"),
  v("ssrf", "gopher://{{CANARY}}/", "gopher scheme — allowlist test"),
  v("ssrf", "dict://{{CANARY}}/", "dict scheme — allowlist test"),
  v("ssrf", "file:///etc/passwd", "file scheme — allowlist test"),
  v("ssrf", "http://shortloop.{{CANARY}}/", "short-form loopback guard-verdict"),
  v("ssrf", "http://zero.{{CANARY}}/", "zero-address guard-verdict shape"),
  v("ssrf", "https://{{CANARY}}%2e127.0.0.1/", "encoded-dot confusion shape"),
  v("ssrf", "http://169.254.169.254.{{CANARY}}/", "cloud metadata guard-verdict (canary-suffixed)"),
  v("ssrf", "http://[::1].{{CANARY}}/", "IPv6 loopback guard-verdict"),
  v("ssrf", "http://0x7f.0x0.0x0.0x1/", "hex-encoded loopback IP"),
  v("ssrf", "http://canary.127.0.0.1.nip.io/", "DNS rebinding detection shape"),
  v("ssrf", "http://target.com\t@{{CANARY}}/", "tab-in-userinfo parser confusion"),
];

/** Open redirect Ã¢â‚¬â€ landing-control shapes. */
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
  v("redirect", "https://trusted.evil.example/", "subdomain whitelist bypass"),
  v("redirect", "/login?next=https://evil.example/", "nested redirect parameter"),
  v("redirect", "java%09script:alert(1)", "encoded tab in scheme"),
  v("redirect", "https:evil.example/", "scheme missing slashes"),
  v("redirect", "//evil.example/%2e%2e/", "encoded traversal in redirect path"),
  v("redirect", "https://evil.example%23@trusted.example/", "encoded fragment @ confusion"),
];
