/**
 * Browser / CDP driver — INTERFACE CONTRACT (v0.34.0).
 *
 * Why: the web battery's highest-value items (cross-account IDOR, business
 * logic, JWT flows, authenticated crawling) need a real signed-in session. Today
 * `scan_url` can only send an `authHeader`, so anything behind a login form is
 * out of reach.
 *
 * This module defines the driver contract and the configuration gate. The CDP
 * *transport* (a WebSocket session to Chrome/Edge DevTools) is deliberately
 * injected rather than implemented here: a WebSocket client is a dependency
 * decision, and the transport is the part that must be smoke-tested on a real
 * host, not verified headless.
 *
 * Security posture: opt-in (env), loopback by default, and every operation is a
 * named, auditable step — no arbitrary script execution beyond `evalJs`, which
 * the caller records in the event log like any other tool call.
 */

export const BROWSER_ENV_CDP_URL = "REDTEAM_BROWSER_CDP_URL";

export interface BrowserConfig {
  /** DevTools endpoint, e.g. http://127.0.0.1:9222 or ws://127.0.0.1:9222/devtools/browser/<id> */
  endpoint: string;
}

export interface CdpTransport {
  /** Send one CDP method and resolve its result object. */
  send(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export interface BrowserDriver {
  /** Current page snapshot: URL, title, visible text (truncated). */
  snapshot(): Promise<{ url: string; title: string; text: string }>;
  /** Navigate the active page. */
  navigate(url: string): Promise<void>;
  /** Evaluate an expression in the page and return its stringified result. */
  evalJs(expression: string): Promise<string>;
  /** Type into the field whose label/placeholder matches. */
  fillField(label: string, value: string): Promise<void>;
}

/** Read the optional CDP configuration. Undefined when unset or malformed. */
export function browserConfig(env: NodeJS.ProcessEnv = process.env): BrowserConfig | undefined {
  const endpoint = (env[BROWSER_ENV_CDP_URL] ?? "").trim();
  if (!endpoint) return undefined;
  try {
    const parsed = new URL(endpoint);
    if (!["http:", "https:", "ws:", "wss:"].includes(parsed.protocol)) return undefined;
  } catch {
    return undefined;
  }
  return { endpoint };
}

export function browserConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  return browserConfig(env) !== undefined;
}

/** Guidance returned by doctor/readiness when the driver is not configured. */
export const BROWSER_SETUP_GUIDANCE =
  "Start Edge/Chrome with --remote-debugging-port=9222 (loopback) and set REDTEAM_BROWSER_CDP_URL to that endpoint. " +
  "The driver lets the web battery sign in with the operator-supplied test account before fuzzing authenticated routes.";

/**
 * Build a driver over an injected CDP transport. The transport owns connection
 * lifecycle; this class owns the operations the runner is allowed to perform.
 */
export function createCdpDriver(transport: CdpTransport): BrowserDriver {
  const MAX_TEXT = 4000;

  const evaluate = async (expression: string): Promise<Record<string, unknown>> =>
    transport.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });

  return {
    async snapshot() {
      const res = await evaluate(
        `JSON.stringify({url: location.href, title: document.title, text: (document.body && document.body.innerText || "").slice(0, ${MAX_TEXT})})`,
      );
      const raw = (res["result"] as { value?: unknown } | undefined)?.value;
      if (typeof raw !== "string") return { url: "", title: "", text: "" };
      try {
        const parsed = JSON.parse(raw) as { url?: string; title?: string; text?: string };
        return { url: parsed.url ?? "", title: parsed.title ?? "", text: parsed.text ?? "" };
      } catch {
        return { url: "", title: "", text: "" };
      }
    },

    async navigate(url: string) {
      if (!/^https?:\/\//i.test(url)) throw new Error("navigate: only http(s) URLs are allowed");
      await transport.send("Page.navigate", { url });
    },

    async evalJs(expression: string) {
      const res = await evaluate(expression);
      const value = (res["result"] as { value?: unknown } | undefined)?.value;
      return typeof value === "string" ? value : JSON.stringify(value ?? null);
    },

    async fillField(label: string, value: string) {
      // Deliberately simple and auditable: locate by label/placeholder text, set
      // the value, dispatch the events a real user would produce.
      const expr = `(() => {
        const label = ${JSON.stringify(label)};
        const value = ${JSON.stringify(value)};
        const el = [...document.querySelectorAll("input,textarea")]
          .find((e) => {
            const id = e.id ? document.querySelector('label[for="' + e.id + '"]') : null;
            const text = ((id && id.innerText) || e.getAttribute("placeholder") || e.getAttribute("aria-label") || "").toLowerCase();
            return text.includes(label.toLowerCase());
          });
        if (!el) return "not-found";
        el.focus();
        el.value = value;
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
        return "ok";
      })()`;
      const out = await this.evalJs(expr);
      if (out !== "ok") throw new Error(`fillField: no field matched ${JSON.stringify(label)}`);
    },
  };
}
