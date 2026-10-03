/**
 * Web UI tests (v0.22.0).
 *
 * No live engagement, no network beyond loopback: engagement directories
 * are canned fixtures under a tmp dir, the abort handle is a stub, and the
 * server binds a random loopback port. Covers: token generation/uniqueness,
 * auth rejection, loopback-only binding, launch validation, the abort path,
 * SSE streaming of canned events, and findings/coverage/compliance reads.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EventEmitter } from "node:events";
import { generateToken, isAuthorized, UI_COOKIE } from "../src/ui/auth.js";
import { UiStore, isSafeEngagementId } from "../src/ui/store.js";
import { renderMarkdown } from "../src/ui/markdown.js";
import { startUiServer } from "../src/ui/server.js";
import { handleLaunch } from "../src/ui/routes/engagements.js";
import { handleAbort } from "../src/ui/routes/actions.js";
import { handleFeed } from "../src/ui/routes/feed.js";
import { handleFindings } from "../src/ui/routes/findings.js";
import { handleCoverage, handleCompliance } from "../src/ui/routes/coverage.js";

let tmp = "";
let store: UiStore;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "ui-test-"));
  store = new UiStore(tmp);
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** Minimal mock response capturing status + body. */
function mockRes() {
  const chunks: string[] = [];
  let status = 0;
  const res = {
    status,
    headers: {} as Record<string, unknown>,
    body: "",
    writeHead(s: number, h: Record<string, unknown>) {
      status = s;
      res.status = s;
      res.headers = h;
    },
    write(c: string) {
      chunks.push(c);
      return true;
    },
    end(c?: string) {
      if (c) chunks.push(c);
      res.body = chunks.join("");
      if (res.onEnd) res.onEnd();
    },
    onEnd: null as null | (() => void),
  };
  return res;
}

function cannedEngagement(id: string, status: string): string {
  const dir = join(tmp, id);
  mkdirSync(dir, { recursive: true });
  mkdirSync(join(dir, "poc"), { recursive: true });
  writeFileSync(
    join(dir, "events.jsonl"),
    [
      { seq: 1, ts: "2026-10-03T10:00:00Z", phase: "authorize", actor: "coordinator", action: "authz", result: "allowed" },
      { seq: 2, ts: "2026-10-03T10:01:00Z", phase: "recon", actor: "recon", action: "scan", result: "2 hosts up" },
    ]
      .map((e) => JSON.stringify(e))
      .join("\n") + "\n",
  );
  writeFileSync(
    join(dir, "state.json"),
    JSON.stringify({
      engagementId: id,
      target: "example.com",
      mode: "red",
      objective: "test",
      status,
      phase: "report",
      startedAt: "2026-10-03T10:00:00Z",
      updatedAt: "2026-10-03T10:05:00Z",
      findings: [
        { id: "F-1", severity: "high", title: "SQLi in search", attackIds: ["T1190"], status: "confirmed", tier: 1, target: "example.com" },
        { id: "F-2", severity: "low", title: "Verbose banner", attackIds: [], status: "confirmed", tier: 0, target: "example.com" },
      ],
      batteryCoverage: { cells: [] },
    }),
  );
  writeFileSync(join(dir, "poc", "F-1.json"), JSON.stringify({ version: 1, bundleId: "poc-1", findingId: "F-1", title: "SQLi in search", steps: [] }));
  writeFileSync(
    join(dir, "item-verdicts.json"),
    JSON.stringify([
      { key: "SS-001", disposition: "confirmed" },
      { key: "SS-002", disposition: "executed-clean" },
      { key: "SS-003", disposition: "pending" },
    ]),
  );
  writeFileSync(join(dir, "compliance-pack.md"), "# Pack\n\n<script>alert(1)</script>\n\n[evil](javascript:alert(1))\n");
  return dir;
}

describe("ui token auth", () => {
  it("generates 64-char hex tokens, unique per call", () => {
    const a = generateToken();
    const b = generateToken();
    assert.match(a, /^[0-9a-f]{64}$/);
    assert.notEqual(a, b);
  });

  it("accepts Bearer and cookie, rejects everything else", () => {
    const token = generateToken();
    const req = (headers: Record<string, string>) => ({ headers }) as never;
    assert.ok(isAuthorized(req({ authorization: `Bearer ${token}` }), token));
    assert.ok(isAuthorized(req({ cookie: `${UI_COOKIE}=${token}` }), token));
    assert.ok(!isAuthorized(req({}), token));
    assert.ok(!isAuthorized(req({ authorization: "Bearer wrong" }), token));
    assert.ok(!isAuthorized(req({ authorization: token }), token)); // missing scheme
  });
});

describe("engagement id safety", () => {
  it("rejects traversal and junk, accepts sane ids", () => {
    assert.ok(isSafeEngagementId("eng-2026-10-03-ab12"));
    assert.ok(!isSafeEngagementId("../secret"));
    assert.ok(!isSafeEngagementId("../../etc"));
    assert.ok(!isSafeEngagementId("/abs/path"));
    assert.ok(!isSafeEngagementId(""));
    assert.ok(!isSafeEngagementId("a b"));
    assert.ok(!isSafeEngagementId("x".repeat(130)));
  });
});

describe("launch validation", () => {
  const badBodies: Array<[string, unknown]> = [
    ["missing target", { mode: "red", objective: "x", scope: ["a.com"] }],
    ["bad mode", { target: "a.com", mode: "blue", objective: "x", scope: ["a.com"] }],
    ["empty scope", { target: "a.com", mode: "red", objective: "x", scope: [] }],
    ["scope not array", { target: "a.com", mode: "red", objective: "x", scope: "a.com" }],
    ["bad battery target", { target: "a.com", mode: "red", objective: "x", scope: ["a.com"], targets: ["mainframe"] }],
    ["bad environment", { target: "a.com", mode: "red", objective: "x", scope: ["a.com"], environment: "moon" }],
  ];
  for (const [name, body] of badBodies) {
    it(`rejects ${name} with 400 and launches nothing`, async () => {
      const res = mockRes();
      await handleLaunch(store, {} as never, res as never, body);
      assert.equal(res.status, 400);
      assert.match(res.body, /"error"/);
      assert.equal(store.list().length, 0, "no engagement may be registered on invalid input");
    });
  }
});

describe("abort path", () => {
  it("calls the registered abort handle and returns 200", () => {
    const dir = cannedEngagement("eng-abort-1", "running");
    let reason = "";
    store.register({ id: "eng-abort-1", dir, status: "running", startedAt: new Date().toISOString() });
    store.setAbort("eng-abort-1", (r: string) => {
      reason = r;
    });
    const res = mockRes();
    handleAbort(store, res as never, "eng-abort-1", { reason: "test abort" });
    assert.equal(res.status, 200);
    assert.equal(reason, "test abort");
  });

  it("409s when the engagement is not live in this process", () => {
    cannedEngagement("eng-abort-2", "complete");
    const res = mockRes();
    handleAbort(store, res as never, "eng-abort-2", {});
    assert.equal(res.status, 409);
  });
});

describe("SSE feed", () => {
  it("streams canned events then closes on terminal state", async () => {
    cannedEngagement("eng-feed-1", "complete");
    const req = new EventEmitter() as never;
    const res = mockRes();
    const done = new Promise<void>((resolve, reject) => {
      res.onEnd = resolve;
      setTimeout(() => reject(new Error("stream did not end")), 10000);
    });
    handleFeed(store, req, res as never, "eng-feed-1", new URLSearchParams());
    await done;
    assert.match(res.body, /event: event\ndata: \{"seq":1/);
    assert.match(res.body, /event: event\ndata: \{"seq":2/);
    assert.match(res.body, /event: state\ndata: /);
    assert.match(res.body, /event: done\ndata: \{"status":"complete"\}/);
  });

  it("404s on unknown engagement", () => {
    const req = new EventEmitter() as never;
    const res = mockRes();
    handleFeed(store, req, res as never, "nope", new URLSearchParams());
    assert.equal(res.status, 404);
  });
});

describe("findings/coverage/compliance reads", () => {
  it("returns findings with proof flags", () => {
    cannedEngagement("eng-read-1", "complete");
    const res = mockRes();
    handleFindings(store, res as never, "eng-read-1");
    assert.equal(res.status, 200);
    const findings = JSON.parse(res.body);
    assert.equal(findings.length, 2);
    assert.equal(findings[0].hasProof, true);
    assert.equal(findings[1].hasProof, false);
  });

  it("summarizes item verdicts", () => {
    cannedEngagement("eng-read-2", "complete");
    const res = mockRes();
    handleCoverage(store, res as never, "eng-read-2");
    assert.equal(res.status, 200);
    const cov = JSON.parse(res.body);
    assert.equal(cov.total, 3);
    assert.equal(cov.byDisposition["confirmed"], 1);
    assert.equal(cov.byDisposition["pending"], 1);
    assert.deepEqual(cov.pending, ["SS-003"]);
  });

  it("renders compliance markdown with hostile content neutralized", () => {
    cannedEngagement("eng-read-3", "complete");
    const res = mockRes();
    handleCompliance(store, res as never, "eng-read-3");
    assert.equal(res.status, 200);
    const c = JSON.parse(res.body);
    assert.ok(c.packHtml.includes("<h1>Pack</h1>"));
    assert.ok(!c.packHtml.includes("<script>"));
    assert.ok(!c.packHtml.includes("javascript:"));
  });
});

describe("markdown sanitizer", () => {
  it("escapes raw HTML and javascript: links, keeps real markdown", () => {
    const html = renderMarkdown("# Hi\n\n<img src=x onerror=alert(1)>\n\n[ok](https://example.com)\n\n[evil](javascript:alert(1))");
    assert.ok(html.includes("<h1>Hi</h1>"));
    assert.ok(!html.includes("<img"));
    assert.ok(html.includes('href="https://example.com"'));
    assert.ok(!html.includes("javascript:"));
  });
});

describe("server security posture", () => {
  it("binds loopback only and gates the API behind the token", async () => {
    const srv = await startUiServer({ port: 0, engagementsDir: tmp });
    try {
      assert.equal(srv.address, "127.0.0.1");
      const base = `http://127.0.0.1:${srv.port}`;

      const noAuth = await fetch(`${base}/api/engagements`);
      assert.equal(noAuth.status, 401);

      const wrong = await fetch(`${base}/api/engagements`, {
        headers: { authorization: "Bearer wrong" },
      });
      assert.equal(wrong.status, 401);

      const ok = await fetch(`${base}/api/engagements`, {
        headers: { authorization: `Bearer ${srv.token}` },
      });
      assert.equal(ok.status, 200);
      assert.deepEqual(await ok.json(), []);

      // Unauthenticated page load gets the login form, not the dashboard.
      const page = await fetch(`${base}/`);
      assert.equal(page.status, 200);
      assert.match(await page.text(), /RedTeam Console/);
    } finally {
      await srv.close();
    }
  });
});
