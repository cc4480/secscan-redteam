/**
 * Buyer integrations tests (v0.15.0) — ticketing, notifications, SIEM.
 *
 * No real network: a fake HTTP server captures every request. What we prove:
 *  - config resolvers fail closed with clear reasons when env is missing/bad
 *  - Jira: issue create payload (ADF description, priority mapping, labels),
 *    comment, and Done-transition lookup
 *  - ServiceNow: record create shape, work-notes update, resolve on verified fix
 *  - Slack: lifecycle payloads (started/phase/completed/critical/halted)
 *  - SIEM: documented schema for finding/proof/safety/completed events
 *  - ticket sync: mapping written, failures recorded not thrown, skips logged
 *  - retest loop: reverify verdicts update linked tickets correctly
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  resolveJiraConfig,
  resolveSnowConfig,
  resolveSlackConfig,
  createJiraIssue,
  commentJiraIssue,
  transitionJiraIssueDone,
  buildJiraSummary,
  buildJiraLabels,
  createSnowRecord,
  updateSnowRecord,
  notifySlack,
  buildSlackPayload,
  buildSiemEvents,
  writeSiemEvents,
  syncFindingsToTickets,
  loadTicketMapping,
  updateTicketsForReverify,
  type JiraConfig,
  type SnowConfig,
} from "../src/integrations/index.js";
import type { Finding } from "../src/types.js";
import type { PocBundle } from "../src/proof/bundle.js";
import type { ReverifyReport } from "../src/proof/reverify.js";
import type { HttpFn } from "../src/integrations/http.js";

interface Captured {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
}

function startFake(
  handler: (c: Captured) => { status: number; body: unknown },
): Promise<{ server: Server; port: number; captured: Captured[]; http: HttpFn }> {
  const captured: Captured[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let data = "";
    req.on("data", (d: Buffer) => (data += d.toString()));
    req.on("end", () => {
      const c: Captured = {
        method: req.method ?? "",
        url: req.url ?? "",
        headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), String(v)])),
        body: data,
      };
      captured.push(c);
      const out = handler(c);
      res.writeHead(out.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(out.body));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as { port: number }).port;
      resolve({ server, port, captured, http: (url, init) => fetch(url, init) });
    });
  });
}

const finding: Finding = {
  id: "F-1",
  severity: "critical",
  title: "SMB signing disabled on DC01",
  attackIds: ["T1040"],
  evidence: "smb_exec list_shares showed signing disabled",
  fix: "Enforce SMB signing via GPO.",
  retest: "Re-run smb_exec; signing must be required.",
  status: "confirmed",
};

const bundle = {
  version: 1,
  bundleId: "POC-e1-F-1",
  engagementId: "e1",
  findingId: "F-1",
  attackIds: ["T1040"],
  cve: "CVE-2017-0144",
  severity: "critical",
  title: "SMB signing disabled on DC01",
  target: "dc01.corp",
  operator: "op",
  generatedAt: "2026-10-03T00:00:00.000Z",
  steps: [],
  validationTier: "observation",
  proves: "Read-only output proves signing is disabled.",
  doesNotProve: "Full impact not proven.",
  reverifyCommand: "redteam-runner reverify --bundle poc/F-1.json",
} as PocBundle;

function reverifyReport(verdict: ReverifyReport["verdict"]): ReverifyReport {
  return {
    bundleId: bundle.bundleId,
    findingId: "F-1",
    engagementId: "e1",
    reverifiedAt: "2026-10-03T01:00:00.000Z",
    verdict,
    steps: [],
    summary: "reverify summary",
    registryNote: "registry note",
  };
}

describe("config resolvers fail closed", () => {
  it("jira: missing vars → configured:false naming the missing var", () => {
    const r = resolveJiraConfig({});
    assert.equal(r.configured, false);
    assert.match((r as { reason: string }).reason, /REDTEAM_JIRA_BASE_URL/);
  });
  it("jira: bad URL → configured:false", () => {
    const r = resolveJiraConfig({
      REDTEAM_JIRA_BASE_URL: "not-a-url",
      REDTEAM_JIRA_USER: "u",
      REDTEAM_JIRA_API_TOKEN: "t",
      REDTEAM_JIRA_PROJECT: "SEC",
    });
    assert.equal(r.configured, false);
  });
  it("jira: bad priority map JSON → configured:false", () => {
    const r = resolveJiraConfig({
      REDTEAM_JIRA_BASE_URL: "https://jira.example.com",
      REDTEAM_JIRA_USER: "u",
      REDTEAM_JIRA_API_TOKEN: "t",
      REDTEAM_JIRA_PROJECT: "SEC",
      REDTEAM_JIRA_PRIORITY_MAP: "{bad",
    });
    assert.equal(r.configured, false);
  });
  it("jira: happy path → defaults (Task type, stock priorities)", () => {
    const r = resolveJiraConfig({
      REDTEAM_JIRA_BASE_URL: "https://jira.example.com/",
      REDTEAM_JIRA_USER: "bot@example.com",
      REDTEAM_JIRA_API_TOKEN: "tok",
      REDTEAM_JIRA_PROJECT: "SEC",
    });
    assert.equal(r.configured, true);
    if (r.configured) {
      assert.equal(r.baseUrl, "https://jira.example.com");
      assert.equal(r.issueType, "Task");
      assert.equal(r.priorityMap["critical"], "1");
    }
  });
  it("snow: missing vars → configured:false", () => {
    const r = resolveSnowConfig({});
    assert.equal(r.configured, false);
    assert.match((r as { reason: string }).reason, /REDTEAM_SNOW_INSTANCE/);
  });
  it("snow: happy path defaults table to incident", () => {
    const r = resolveSnowConfig({
      REDTEAM_SNOW_INSTANCE: "https://acme.service-now.com",
      REDTEAM_SNOW_USER: "u",
      REDTEAM_SNOW_PASSWORD: "p",
    });
    assert.equal(r.configured, true);
    if (r.configured) assert.equal(r.table, "incident");
  });
  it("slack: missing webhook → configured:false; non-https → false", () => {
    assert.equal(resolveSlackConfig({}).configured, false);
    assert.equal(resolveSlackConfig({ REDTEAM_SLACK_WEBHOOK_URL: "http://x" }).configured, false);
    assert.equal(
      resolveSlackConfig({ REDTEAM_SLACK_WEBHOOK_URL: "https://hooks.slack.com/x" }).configured,
      true,
    );
  });
});

describe("jira sink", () => {
  let fake: Awaited<ReturnType<typeof startFake>>;
  beforeEach(async () => {
    fake = await startFake((c) => {
      if (c.method === "POST" && c.url === "/rest/api/3/issue") return { status: 201, body: { key: "SEC-42" } };
      if (c.url.endsWith("/transitions") && c.method === "GET")
        return { status: 200, body: { transitions: [{ id: "31", name: "Done" }, { id: "11", name: "To Do" }] } };
      return { status: 200, body: {} };
    });
  });
  afterEach(async () => {
    await new Promise<void>((r) => fake.server.close(() => r()));
  });

  function cfg(): JiraConfig {
    return {
      configured: true,
      baseUrl: `http://127.0.0.1:${fake.port}`,
      user: "bot@example.com",
      apiToken: "tok123",
      project: "SEC",
      issueType: "Task",
      priorityMap: { critical: "1", high: "2", medium: "3", low: "4", info: "5" },
    };
  }

  it("create: correct endpoint, Basic auth, ADF description, priority, labels", async () => {
    const key = await createJiraIssue(cfg(), { finding, bundle, engagementId: "e1", target: "dc01.corp" }, fake.http);
    assert.equal(key, "SEC-42");
    const c = fake.captured.find((x) => x.url === "/rest/api/3/issue")!;
    assert.equal(c.method, "POST");
    const expectedAuth = `Basic ${Buffer.from("bot@example.com:tok123").toString("base64")}`;
    assert.equal(c.headers["authorization"], expectedAuth);
    // token must not leak into URL
    assert.doesNotMatch(c.url, /tok123/);
    const body = JSON.parse(c.body);
    assert.equal(body.fields.project.key, "SEC");
    assert.equal(body.fields.priority.id, "1"); // critical → Highest
    assert.equal(body.fields.issuetype.name, "Task");
    assert.match(body.fields.summary, /\[CRITICAL\]/);
    const labels: string[] = body.fields.labels;
    assert.ok(labels.includes("t1040"), `labels: ${labels}`);
    assert.ok(labels.includes("cve-2017-0144"), `labels: ${labels}`);
    // ADF description
    assert.equal(body.fields.description.type, "doc");
    const text = JSON.stringify(body.fields.description);
    assert.match(text, /Proof of exploitation/);
    assert.match(text, /poc\/F-1\.json/);
  });

  it("summary/label builders are pure and bounded", () => {
    assert.match(buildJiraSummary({ finding, bundle, engagementId: "e1", target: "t" }), /^\[CRITICAL\]/);
    assert.ok(buildJiraSummary({ finding, bundle, engagementId: "e1", target: "t" }).length <= 255);
    assert.ok(buildJiraLabels({ finding, bundle, engagementId: "e1", target: "t" }).includes("redteam"));
  });

  it("comment + done-transition", async () => {
    await commentJiraIssue(cfg(), "SEC-42", ["hello"], fake.http);
    const comment = fake.captured.find((x) => x.url === "/rest/api/3/issue/SEC-42/comment")!;
    assert.equal(comment.method, "POST");
    assert.equal(JSON.parse(comment.body).body.type, "doc");
    const done = await transitionJiraIssueDone(cfg(), "SEC-42", fake.http);
    assert.equal(done, true);
    const tr = fake.captured.find((x) => x.url === "/rest/api/3/issue/SEC-42/transitions" && x.method === "POST")!;
    assert.equal(JSON.parse(tr.body).transition.id, "31");
  });

  it("transition returns false when no done-like transition exists", async () => {
    await fake.server.close();
    fake = await startFake(() => ({ status: 200, body: { transitions: [{ id: "11", name: "To Do" }] } }));
    const done = await transitionJiraIssueDone(cfg(), "SEC-1", fake.http);
    assert.equal(done, false);
  });
});

describe("servicenow sink", () => {
  let fake: Awaited<ReturnType<typeof startFake>>;
  beforeEach(async () => {
    fake = await startFake((c) => {
      if (c.method === "POST" && c.url === "/api/now/table/incident")
        return { status: 201, body: { result: { sys_id: "abc123" } } };
      return { status: 200, body: {} };
    });
  });
  afterEach(async () => {
    await new Promise<void>((r) => fake.server.close(() => r()));
  });

  function cfg(): SnowConfig {
    return {
      configured: true,
      instance: `http://127.0.0.1:${fake.port}`,
      user: "u",
      password: "pw",
      table: "incident",
    };
  }

  it("create: table API, urgency from severity, proof in description", async () => {
    const sysId = await createSnowRecord(cfg(), { finding, bundle, engagementId: "e1", target: "dc01.corp" }, fake.http);
    assert.equal(sysId, "abc123");
    const c = fake.captured.find((x) => x.url === "/api/now/table/incident")!;
    const body = JSON.parse(c.body);
    assert.equal(body.urgency, "1"); // critical → High
    assert.equal(body.category, "Security");
    assert.match(body.short_description, /\[CRITICAL\]/);
    assert.match(body.description, /Proof of exploitation/);
    assert.doesNotMatch(c.url, /pw/);
  });

  it("update: verified fixed → state 6 + close_notes; otherwise work_notes only", async () => {
    await updateSnowRecord(cfg(), "abc123", "VERIFIED FIXED", true, fake.http);
    let c = fake.captured.find((x) => x.method === "PUT")!;
    let body = JSON.parse(c.body);
    assert.equal(body.state, "6");
    assert.match(body.close_notes, /VERIFIED FIXED/);

    fake.captured.length = 0;
    const done = await updateSnowRecord(cfg(), "abc123", "STILL PRESENT", false, fake.http);
    assert.equal(done, "noted");
    c = fake.captured.find((x) => x.method === "PUT")!;
    body = JSON.parse(c.body);
    assert.ok(!("state" in body));
    assert.match(body.work_notes, /STILL PRESENT/);
  });
});

describe("slack sink", () => {
  it("payloads carry kind-specific content", () => {
    const p = buildSlackPayload({ kind: "completed", engagementId: "e1", target: "t", mode: "red", severityCounts: { critical: 1, low: 2 } });
    assert.match(JSON.stringify(p.blocks), /critical:1/);
    const crit = buildSlackPayload({ kind: "critical_finding", engagementId: "e1", target: "t", mode: "red", findingId: "F-1", findingTitle: "X" });
    assert.match(JSON.stringify(crit.blocks), /CRITICAL finding/);
  });

  it("notify posts blocks to the webhook", async () => {
    const fake = await startFake(() => ({ status: 200, body: "ok" }));
    try {
      await notifySlack(
        { configured: true, webhookUrl: `http://127.0.0.1:${fake.port}/hook` },
        { kind: "started", engagementId: "e1", target: "t", mode: "red" },
        fake.http,
      );
      const c = fake.captured[0]!;
      assert.equal(c.method, "POST");
      const body = JSON.parse(c.body);
      assert.ok(Array.isArray(body.blocks));
      assert.match(JSON.stringify(body.blocks), /Engagement started/);
    } finally {
      await new Promise<void>((r) => fake.server.close(() => r()));
    }
  });
});

describe("siem export", () => {
  it("emits finding + proof + safety + completed events with the documented schema", () => {
    const bundles = new Map([[finding.id, bundle]]);
    const events = buildSiemEvents({
      engagementId: "e1",
      target: "dc01.corp",
      operator: "op",
      findings: [finding],
      bundles,
      safetySummary: "zero-disruption: clean",
      severityCounts: { critical: 1 },
    });
    const types = events.map((e) => e.event_type);
    assert.deepEqual(types, ["finding", "proof_bundle", "safety_summary", "engagement_completed"]);
    for (const e of events) {
      assert.equal(e.schema_version, 1);
      assert.equal(e.vendor, "secscan-redteam");
      assert.equal(e.product, "redteam-runner");
      assert.equal(e.engagement_id, "e1");
      assert.ok(e.timestamp);
    }
    const fe = events[0]!;
    assert.equal(fe.severity, "critical");
    assert.deepEqual(fe.attack_ids, ["T1040"]);
    assert.equal(fe.cve, "CVE-2017-0144");
    assert.equal(fe.bundle_id, "POC-e1-F-1");
  });

  it("writeSiemEvents writes valid JSONL", () => {
    const dir = mkdtempSync(join(tmpdir(), "siem-"));
    try {
      const events = buildSiemEvents({
        engagementId: "e1", target: "t", operator: "op", findings: [finding],
        bundles: new Map(), safetySummary: "s", severityCounts: {},
      });
      const path = writeSiemEvents(dir, events);
      const lines = readFileSync(path, "utf8").trim().split("\n");
      assert.equal(lines.length, events.length);
      for (const l of lines) assert.doesNotThrow(() => JSON.parse(l));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("ticket sync orchestration", () => {
  it("syncs confirmed findings to both sinks and writes integrations.json", async () => {
    const fake = await startFake((c) => {
      if (c.url === "/rest/api/3/issue") return { status: 201, body: { key: "SEC-7" } };
      if (c.url === "/api/now/table/incident") return { status: 201, body: { result: { sys_id: "sid1" } } };
      return { status: 200, body: {} };
    });
    const dir = mkdtempSync(join(tmpdir(), "integ-"));
    try {
      const env = {
        REDTEAM_JIRA_BASE_URL: `http://127.0.0.1:${fake.port}`,
        REDTEAM_JIRA_USER: "u", REDTEAM_JIRA_API_TOKEN: "t", REDTEAM_JIRA_PROJECT: "SEC",
        REDTEAM_SNOW_INSTANCE: `http://127.0.0.1:${fake.port}`,
        REDTEAM_SNOW_USER: "u", REDTEAM_SNOW_PASSWORD: "p",
      };
      const { mapping, attempts } = await syncFindingsToTickets(
        { engagementId: "e1", target: "t", findings: [finding], bundles: new Map([[finding.id, bundle]]), env, http: fake.http },
        dir,
      );
      assert.equal(mapping.tickets["F-1"]?.jiraKey, "SEC-7");
      assert.equal(mapping.tickets["F-1"]?.snowSysId, "sid1");
      assert.ok(attempts.every((a) => a.status === "ok"));
      const onDisk = JSON.parse(readFileSync(join(dir, "integrations.json"), "utf8"));
      assert.equal(onDisk.tickets["F-1"].jiraKey, "SEC-7");
      // round-trip loader
      assert.deepEqual(loadTicketMapping(dir), mapping);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await new Promise<void>((r) => fake.server.close(() => r()));
    }
  });

  it("skips non-confirmed findings", async () => {
    const fake = await startFake(() => ({ status: 201, body: { key: "SEC-1" } }));
    const dir = mkdtempSync(join(tmpdir(), "integ-"));
    try {
      const killed = { ...finding, id: "F-2", status: "killed" } as Finding;
      const env = {
        REDTEAM_JIRA_BASE_URL: `http://127.0.0.1:${fake.port}`,
        REDTEAM_JIRA_USER: "u", REDTEAM_JIRA_API_TOKEN: "t", REDTEAM_JIRA_PROJECT: "SEC",
      };
      const { mapping } = await syncFindingsToTickets(
        { engagementId: "e1", target: "t", findings: [killed], bundles: new Map(), env, http: fake.http },
        dir,
      );
      assert.deepEqual(mapping.tickets, {});
      assert.equal(fake.captured.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await new Promise<void>((r) => fake.server.close(() => r()));
    }
  });

  it("unconfigured sinks → skipped, never throws; mapping still written", async () => {
    const dir = mkdtempSync(join(tmpdir(), "integ-"));
    try {
      const { mapping, attempts } = await syncFindingsToTickets(
        { engagementId: "e1", target: "t", findings: [finding], bundles: new Map(), env: {} },
        dir,
      );
      assert.deepEqual(mapping.tickets, {});
      assert.ok(attempts.some((a) => a.sink === "jira" && a.status === "skipped"));
      assert.ok(attempts.some((a) => a.sink === "servicenow" && a.status === "skipped"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("sink 500s → failed attempts, no throw", async () => {
    const fake = await startFake(() => ({ status: 500, body: { error: "boom" } }));
    const dir = mkdtempSync(join(tmpdir(), "integ-"));
    try {
      const env = {
        REDTEAM_JIRA_BASE_URL: `http://127.0.0.1:${fake.port}`,
        REDTEAM_JIRA_USER: "u", REDTEAM_JIRA_API_TOKEN: "t", REDTEAM_JIRA_PROJECT: "SEC",
      };
      const { attempts } = await syncFindingsToTickets(
        { engagementId: "e1", target: "t", findings: [finding], bundles: new Map(), env, http: fake.http },
        dir,
      );
      const jiraAttempts = attempts.filter((a) => a.sink === "jira");
      assert.ok(jiraAttempts.every((a) => a.status === "failed"));
      assert.match(jiraAttempts[0]!.detail, /HTTP 500/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await new Promise<void>((r) => fake.server.close(() => r()));
    }
  });

  it("loadTicketMapping returns null when absent", () => {
    const dir = mkdtempSync(join(tmpdir(), "integ-"));
    try {
      assert.equal(loadTicketMapping(dir), null);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("retest loop", () => {
  it("reproduced → comment 'still present'; not-reproduced → 'verified fixed' + done transition", async () => {
    const fake = await startFake((c) => {
      if (c.url.endsWith("/transitions") && c.method === "GET")
        return { status: 200, body: { transitions: [{ id: "31", name: "Done" }] } };
      return { status: 200, body: {} };
    });
    try {
      const env = {
        REDTEAM_JIRA_BASE_URL: `http://127.0.0.1:${fake.port}`,
        REDTEAM_JIRA_USER: "u", REDTEAM_JIRA_API_TOKEN: "t", REDTEAM_JIRA_PROJECT: "SEC",
      };
      const mapping = { engagementId: "e1", writtenAt: "x", tickets: { "F-1": { jiraKey: "SEC-7" } } };

      const r1 = await updateTicketsForReverify(mapping, bundle, reverifyReport("reproduced"), { env, http: fake.http });
      assert.ok(r1.attempts.some((a) => a.status === "ok"));
      const comment1 = fake.captured.find((x) => x.url.endsWith("/comment"))!;
      assert.match(JSON.stringify(comment1.body), /STILL PRESENT/);
      // reproduced must NOT attempt a transition
      assert.ok(!fake.captured.some((x) => x.url.endsWith("/transitions") && x.method === "POST"));

      fake.captured.length = 0;
      const r2 = await updateTicketsForReverify(mapping, bundle, reverifyReport("not-reproduced"), { env, http: fake.http });
      const comment2 = fake.captured.find((x) => x.url.endsWith("/comment"))!;
      assert.match(JSON.stringify(comment2.body), /VERIFIED FIXED/);
      const tr = fake.captured.find((x) => x.url.endsWith("/transitions") && x.method === "POST")!;
      assert.equal(JSON.parse(tr.body).transition.id, "31");
      assert.ok(r2.attempts.some((a) => a.status === "ok" && /transitioned to done/.test(a.detail)));
    } finally {
      await new Promise<void>((r) => fake.server.close(() => r()));
    }
  });

  it("target-changed → comment only, no transition", async () => {
    const fake = await startFake(() => ({ status: 200, body: { transitions: [{ id: "31", name: "Done" }] } }));
    try {
      const env = {
        REDTEAM_JIRA_BASE_URL: `http://127.0.0.1:${fake.port}`,
        REDTEAM_JIRA_USER: "u", REDTEAM_JIRA_API_TOKEN: "t", REDTEAM_JIRA_PROJECT: "SEC",
      };
      const mapping = { engagementId: "e1", writtenAt: "x", tickets: { "F-1": { jiraKey: "SEC-7" } } };
      await updateTicketsForReverify(mapping, bundle, reverifyReport("target-changed"), { env, http: fake.http });
      const comment = fake.captured.find((x) => x.url.endsWith("/comment"))!;
      assert.match(JSON.stringify(comment.body), /TARGET CHANGED/);
      assert.ok(!fake.captured.some((x) => x.url.endsWith("/transitions") && x.method === "POST"));
    } finally {
      await new Promise<void>((r) => fake.server.close(() => r()));
    }
  });

  it("no linked ticket → skipped, never throws", async () => {
    const mapping = { engagementId: "e1", writtenAt: "x", tickets: {} };
    const { attempts } = await updateTicketsForReverify(mapping, bundle, reverifyReport("reproduced"), { env: {} });
    assert.ok(attempts.some((a) => a.status === "skipped"));
  });
});
