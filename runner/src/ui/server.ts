/**
 * UI HTTP server (v0.22.0).
 *
 * Security posture (non-negotiable — this console drives live pentest tooling):
 *  - binds 127.0.0.1 by default; any --listen override prints a loud warning
 *  - every /api/* route needs the startup token (Bearer or auth cookie)
 *  - / serves the dashboard only when authed, else a token login page
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { UiStore } from "./store.js";
import { authCookie, generateToken, isAuthorized, UI_COOKIE } from "./auth.js";
import { handleLaunch, handleList, handleDetail } from "./routes/engagements.js";
import { handleFeed } from "./routes/feed.js";
import { handleFindings, handleProof } from "./routes/findings.js";
import { handleCoverage, handleCompliance } from "./routes/coverage.js";
import { handleAbort, handleEscalate, handleReverify, handleJob, handleWatchProfiles, handleWatchTrigger } from "./routes/actions.js";
import { json, notFound, readJsonBody } from "./routes/http.js";
import type { UiServerOptions } from "./types.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
};

function servePublic(res: ServerResponse, name: string): void {
  const safe = name === "" || name === "/" ? "index.html" : name.replace(/^\/+/, "");
  if (!/^[A-Za-z0-9_./-]+$/.test(safe) || safe.includes("..")) {
    notFound(res);
    return;
  }
  const p = join(HERE, "public", safe);
  if (!existsSync(p)) {
    notFound(res);
    return;
  }
  try {
    const body = readFileSync(p);
    res.writeHead(200, {
      "Content-Type": MIME[extname(p)] ?? "application/octet-stream",
      "Content-Length": body.length,
      "Cache-Control": "no-store",
    });
    res.end(body);
  } catch {
    notFound(res);
  }
}

function loginPage(): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecScan RedTeam UI</title></head>
<body style="background:#0d1117;color:#e6edf3;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
<form method="post" action="/api/auth" style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:32px;max-width:380px;width:90%">
<h2 style="margin-top:0">RedTeam Console</h2>
<p style="color:#8b949e;font-size:14px">Enter the token printed in the terminal where you ran <code>redteam-runner ui</code>.</p>
<input name="token" type="password" autocomplete="off" style="width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:10px" placeholder="ui token" required>
<button type="submit" style="margin-top:12px;width:100%;background:#238636;color:#fff;border:0;border-radius:6px;padding:10px;font-size:15px;cursor:pointer">Unlock console</button>
</form></body></html>`;
}

async function route(store: UiStore, token: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  const method = req.method ?? "GET";

  // Token login: form posts urlencoded; accept JSON too.
  if (path === "/api/auth" && method === "POST") {
    const ct = req.headers["content-type"] ?? "";
    let presented: string | undefined;
    if (ct.includes("application/json")) {
      try {
        const b = (await readJsonBody(req)) as { token?: unknown };
        presented = typeof b.token === "string" ? b.token : undefined;
      } catch {
        presented = undefined;
      }
    } else {
      const raw = await new Promise<string>((resolve) => {
        let s = "";
        req.on("data", (c: Buffer) => {
          s += c.toString("utf8");
          if (s.length > 4096) req.destroy();
        });
        req.on("end", () => resolve(s));
      });
      presented = new URLSearchParams(raw).get("token") ?? undefined;
    }
    if (presented && presented === token) {
      res.writeHead(303, { "Set-Cookie": authCookie(token), Location: "/" });
      res.end();
    } else {
      await new Promise((r) => setTimeout(r, 500));
      json(res, 401, { error: "bad token" });
    }
    return;
  }

  // Everything else needs auth.
  if (!isAuthorized(req, token)) {
    if (path === "/" || !path.startsWith("/api/")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(loginPage());
      return;
    }
    json(res, 401, { error: "unauthorized" });
    return;
  }

  if (path === "/" || path === "/index.html") {
    servePublic(res, "index.html");
    return;
  }
  if (path.startsWith("/assets/")) {
    servePublic(res, path);
    return;
  }

  // --- API ---
  const seg = path.split("/").filter(Boolean); // ["api", ...]
  if (seg[0] !== "api") {
    notFound(res);
    return;
  }

  try {
    if (seg[1] === "engagements" && method === "GET" && seg.length === 2) return handleList(store, res);
    if (seg[1] === "engagements" && method === "POST" && seg.length === 2) {
      const body = await readJsonBody(req);
      return handleLaunch(store, req, res, body);
    }
    if (seg[1] === "engagements" && seg[2] && method === "GET" && seg.length === 3) return handleDetail(store, res, decodeURIComponent(seg[2]!));
    if (seg[1] === "engagements" && seg[2] && seg[3] === "events" && method === "GET") {
      return handleFeed(store, req, res, decodeURIComponent(seg[2]!), url.searchParams);
    }
    if (seg[1] === "engagements" && seg[2] && seg[3] === "abort" && method === "POST") {
      const body = await readJsonBody(req).catch(() => ({}));
      return handleAbort(store, res, decodeURIComponent(seg[2]!), body);
    }
    if (seg[1] === "engagements" && seg[2] && seg[3] === "escalate" && method === "POST") {
      const body = await readJsonBody(req).catch(() => ({}));
      return handleEscalate(store, res, decodeURIComponent(seg[2]!), body);
    }
    if (seg[1] === "engagements" && seg[2] && seg[3] === "findings" && method === "GET") {
      return handleFindings(store, res, decodeURIComponent(seg[2]!));
    }
    if (seg[1] === "engagements" && seg[2] && seg[3] === "proof" && seg[4] && method === "GET") {
      return handleProof(store, res, decodeURIComponent(seg[2]!), decodeURIComponent(seg[4]!));
    }
    if (seg[1] === "engagements" && seg[2] && seg[3] === "coverage" && method === "GET") {
      return handleCoverage(store, res, decodeURIComponent(seg[2]!));
    }
    if (seg[1] === "engagements" && seg[2] && seg[3] === "compliance" && method === "GET") {
      return handleCompliance(store, res, decodeURIComponent(seg[2]!));
    }
    if (seg[1] === "reverify" && method === "POST") {
      const body = await readJsonBody(req);
      return handleReverify(store, res, body);
    }
    if (seg[1] === "jobs" && seg[2] && method === "GET") return handleJob(store, res, decodeURIComponent(seg[2]!));
    if (seg[1] === "watch" && seg[2] === "profiles" && method === "GET") return handleWatchProfiles(res, url.searchParams);
    if (seg[1] === "watch" && seg[2] === "trigger" && method === "POST") {
      const body = await readJsonBody(req);
      return handleWatchTrigger(store, res, body);
    }
  } catch (err) {
    json(res, 500, { error: `ui error: ${(err as Error).message}` });
    return;
  }
  notFound(res);
}

export interface UiServerHandle {
  port: number;
  /** The address the socket actually bound to (asserted 127.0.0.1 in tests). */
  address: string;
  token: string;
  close: () => Promise<void>;
}

/** Start the UI server. Resolves when listening; the process stays alive. */
export async function startUiServer(opts: UiServerOptions = {}): Promise<UiServerHandle> {
  const port = opts.port ?? 8787;
  const listen = opts.listen ?? "127.0.0.1";
  const token = process.env["REDTEAM_UI_TOKEN"] || generateToken();
  const store = new UiStore(opts.engagementsDir);

  const server = createServer((req, res) => {
    route(store, token, req, res).catch((err) => {
      try {
        json(res, 500, { error: `ui error: ${(err as Error).message}` });
      } catch {
        /* socket gone */
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.on("error", reject);
    server.listen(port, listen, () => resolve());
  });

  const addr = server.address();
  const boundPort = typeof addr === "object" && addr ? addr.port : port;
  const boundAddress = typeof addr === "object" && addr ? addr.address : listen;

  if (listen !== "127.0.0.1" && listen !== "localhost" && listen !== "::1") {
    console.error(`[ui] WARNING: listening on ${listen} (not loopback). This console drives live pentest tooling — bind it to 127.0.0.1 unless you know exactly what you are doing.`);
  }
  console.log(`[ui] RedTeam console listening on http://${listen}:${boundPort}`);
  console.log(`[ui] UI token (do not share): ${token}`);
  console.log(`[ui] engagements dir: ${store.engagementsDir}`);

  const close = () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  process.on("SIGINT", () => {
    void close().then(() => process.exit(0));
  });
  return { port: boundPort, address: boundAddress, token, close };
}

// Re-exported for the CLI command and tests.
export { UiStore };
export type { UiServerOptions };
