/**
 * Per-item verdict tracking tests (v0.18.0).
 *
 * The battery may not report complete while any selected item lacks a
 * defensible disposition. No network, no API keys — pure ledger mechanics.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  buildItemLedger,
  ensureCveEntry,
  ledgerSummary,
  markAttempted,
  pendingByCell,
  resolveItemKey,
  serializeLedger,
  setDisposition,
  prerequisiteMet,
} from "../src/coverage/items.js";
import { TARGET_PROFILES, FULL_BATTERY_TARGETS } from "../src/targets/index.js";

// prerequisiteMet reads the environment — pin it for determinism.
const PREREQ_ENV = [
  "REDTEAM_MSFRPC_USER",
  "REDTEAM_MSFRPC_PASS",
  "REDTEAM_KRB_CCACHE_B64",
  "REDTEAM_KRB_CCACHE_PATH",
  "REDTEAM_KRB_KIRBI_B64",
  "REDTEAM_NFS_TEST_CLIENT",
];
let savedEnv: Record<string, string | undefined>;
beforeEach(() => {
  savedEnv = {};
  for (const k of PREREQ_ENV) {
    savedEnv[k] = process.env[k];
    delete process.env[k];
  }
});
afterEach(() => {
  for (const k of PREREQ_ENV) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

describe("buildItemLedger", () => {
  it("contains every static battery item across all four targets", () => {
    const ledger = buildItemLedger([...FULL_BATTERY_TARGETS]);
    let expected = 0;
    for (const t of FULL_BATTERY_TARGETS) expected += TARGET_PROFILES[t].battery.length;
    assert.equal(ledger.size, expected);
    assert.ok(expected >= 416, `expected >= 418 items, got ${expected}`);
    // spot-check keys
    assert.ok(ledger.has("secscan:SS-001"));
    assert.ok(ledger.has("seclayer:SL-080"));
    assert.ok(ledger.has("windows:WS-001"));
    assert.ok(ledger.has("linux:LX-001"));
  });

  it("starts pending, except unmet-prerequisite items which start blocked with the prerequisite named", () => {
    const ledger = buildItemLedger([...FULL_BATTERY_TARGETS]);
    const s = ledgerSummary(ledger);
    assert.equal(s.total, ledger.size);
    assert.equal(s.pending + s.blocked, s.total);
    assert.equal(s.confirmed, 0);
    // the known honest-prerequisite items (no env set → all unmet)
    for (const key of ["windows:WS-064", "windows:WS-065", "linux:LX-041"]) {
      const v = ledger.get(key)!;
      assert.equal(v.disposition, "blocked", `${key} should start blocked`);
      assert.match(v.reason ?? "", /Prerequisite not met:/);
    }
    // msfrpcd methodology items blocked too
    const msfBlocked = [...ledger.values()].filter(
      (v) => v.disposition === "blocked" && (v.reason ?? "").includes("msfrpcd"),
    );
    assert.ok(msfBlocked.length >= 6, `expected >= 6 msfrpcd-blocked items, got ${msfBlocked.length}`);
  });

  it("a met prerequisite unblocks the item at build time", () => {
    process.env.REDTEAM_NFS_TEST_CLIENT = "testclient.example";
    const ledger = buildItemLedger(["linux"]);
    assert.equal(ledger.get("linux:LX-041")!.disposition, "pending");
  });

  it("respects a --targets subset", () => {
    const ledger = buildItemLedger(["secscan", "seclayer"]);
    assert.equal(ledger.size, TARGET_PROFILES.secscan.battery.length + TARGET_PROFILES.seclayer.battery.length);
    assert.ok(!ledger.has("windows:WS-001"));
  });
});

describe("resolveItemKey", () => {
  it("resolves bare IDs with and without targetProfile", () => {
    assert.equal(resolveItemKey("SS-042", "secscan"), "secscan:SS-042");
    assert.equal(resolveItemKey("ss-42", "secscan"), "secscan:SS-042"); // zero-padded + case-insensitive
    assert.equal(resolveItemKey("WS-023"), "windows:WS-023"); // prefix-inferred
    assert.equal(resolveItemKey("LX-109", "linux"), "linux:LX-109");
  });
  it("resolves qualified and CVE forms", () => {
    assert.equal(resolveItemKey("secscan:SS-001"), "secscan:SS-001");
    assert.equal(resolveItemKey("cve:CVE-2021-44228"), "cve:CVE-2021-44228");
    assert.equal(resolveItemKey("CVE-2017-0144"), "cve:CVE-2017-0144");
  });
  it("rejects mismatches and garbage", () => {
    assert.equal(resolveItemKey("SS-042", "seclayer"), undefined); // prefix/target mismatch
    assert.equal(resolveItemKey("SS-042", "bogus"), undefined);
    assert.equal(resolveItemKey("not-an-id"), undefined);
    assert.equal(resolveItemKey(""), undefined);
    assert.equal(resolveItemKey("windows:SS-001"), undefined); // qualified mismatch
  });
});

describe("disposition transitions", () => {
  it("pending → executed-clean → confirmed is the happy path", () => {
    const ledger = buildItemLedger(["secscan"]);
    assert.ok(markAttempted(ledger, "secscan:SS-001"));
    assert.equal(ledger.get("secscan:SS-001")!.disposition, "executed-clean");
    setDisposition(ledger, "secscan:SS-001", "confirmed", { reason: "[high] test" });
    assert.equal(ledger.get("secscan:SS-001")!.disposition, "confirmed");
  });

  it("blocked → executed-clean when the prerequisite is met in practice", () => {
    const ledger = buildItemLedger(["windows"]);
    assert.equal(ledger.get("windows:WS-065")!.disposition, "blocked");
    assert.ok(markAttempted(ledger, "windows:WS-065"));
    assert.equal(ledger.get("windows:WS-065")!.disposition, "executed-clean");
  });

  it("killed records the decisive observation", () => {
    const ledger = buildItemLedger(["linux"]);
    setDisposition(ledger, "linux:LX-001", "killed", { reason: "no such binary on target" });
    const v = ledger.get("linux:LX-001")!;
    assert.equal(v.disposition, "killed");
    assert.equal(v.reason, "no such binary on target");
  });

  it("na without evidence is refused", () => {
    const ledger = buildItemLedger(["secscan"]);
    assert.throws(() => setDisposition(ledger, "secscan:SS-002", "na"), /requires evidence/);
    assert.throws(() => setDisposition(ledger, "secscan:SS-002", "na", { reason: "   " }), /requires evidence/);
    // still pending — the refusal changed nothing
    assert.equal(ledger.get("secscan:SS-002")!.disposition, "pending");
  });

  it("na with evidence lands", () => {
    const ledger = buildItemLedger(["secscan"]);
    setDisposition(ledger, "secscan:SS-002", "na", { reason: "target exposes no share links (verified in recon)" });
    assert.equal(ledger.get("secscan:SS-002")!.disposition, "na");
  });

  it("final dispositions cannot be overwritten", () => {
    const ledger = buildItemLedger(["secscan"]);
    setDisposition(ledger, "secscan:SS-003", "confirmed", { reason: "x" });
    assert.throws(() => setDisposition(ledger, "secscan:SS-003", "killed", { reason: "y" }), /already has final disposition/);
    assert.equal(ledger.get("secscan:SS-003")!.disposition, "confirmed");
  });

  it("reverify may reopen a final disposition to pending — and only to pending", () => {
    const ledger = buildItemLedger(["secscan"]);
    setDisposition(ledger, "secscan:SS-003", "confirmed", { reason: "x" });
    assert.throws(
      () => setDisposition(ledger, "secscan:SS-003", "killed", { reason: "y", viaReverify: true }),
      /may only move .* back to pending/,
    );
    setDisposition(ledger, "secscan:SS-003", "pending", { viaReverify: true });
    assert.equal(ledger.get("secscan:SS-003")!.disposition, "pending");
  });

  it("unknown keys throw / return false, never hand-waved", () => {
    const ledger = buildItemLedger(["secscan"]);
    assert.equal(markAttempted(ledger, "secscan:SS-999"), false);
    assert.throws(() => setDisposition(ledger, "secscan:SS-999", "confirmed"), /unknown battery item key/);
  });
});

describe("dynamic CVE instances", () => {
  it("ensureCveEntry creates a pending entry, idempotent", () => {
    const ledger = buildItemLedger(["windows"]);
    const before = ledger.size;
    const key = ensureCveEntry(ledger, "CVE-2021-44228");
    assert.equal(key, "cve:CVE-2021-44228");
    assert.equal(ledger.size, before + 1);
    assert.equal(ledger.get(key)!.disposition, "pending");
    assert.equal(ledger.get(key)!.category, "functionality");
    // idempotent
    assert.equal(ensureCveEntry(ledger, "cve-2021-44228"), key);
    assert.equal(ledger.size, before + 1);
  });

  it("CVE entries flow through the normal transitions", () => {
    const ledger = buildItemLedger(["windows"]);
    const key = ensureCveEntry(ledger, "CVE-2017-0144");
    markAttempted(ledger, key);
    setDisposition(ledger, key, "confirmed", { reason: "[critical] EternalBlue validated" });
    assert.equal(ledger.get(key)!.disposition, "confirmed");
  });

  it("rejects non-CVE ids", () => {
    const ledger = buildItemLedger(["windows"]);
    assert.throws(() => ensureCveEntry(ledger, "not-a-cve"), /not a CVE id/);
  });
});

describe("summary and coordinator visibility", () => {
  it("ledgerSummary counts every disposition", () => {
    const ledger = buildItemLedger(["secscan"]);
    markAttempted(ledger, "secscan:SS-001");
    setDisposition(ledger, "secscan:SS-001", "confirmed", { reason: "x" });
    markAttempted(ledger, "secscan:SS-002");
    setDisposition(ledger, "secscan:SS-003", "killed", { reason: "y" });
    setDisposition(ledger, "secscan:SS-004", "na", { reason: "z" });
    const s = ledgerSummary(ledger);
    assert.equal(s.confirmed, 1);
    assert.equal(s.executedClean, 1);
    assert.equal(s.killed, 1);
    assert.equal(s.na, 1);
    assert.equal(s.total, s.pending + s.confirmed + s.executedClean + s.killed + s.blocked + s.na);
  });

  it("pendingByCell groups pending IDs by target × category", () => {
    const ledger = buildItemLedger(["secscan", "windows"]);
    markAttempted(ledger, "secscan:SS-001");
    const groups = pendingByCell(ledger);
    assert.ok(groups.length > 0);
    for (const g of groups) {
      assert.ok(g.ids.length > 0);
      // none of the groups contain the attempted item
      assert.ok(!g.ids.includes("SS-001") || g.target !== "secscan");
    }
    const total = groups.reduce((n, g) => n + g.ids.length, 0);
    assert.equal(total, ledgerSummary(ledger).pending);
  });

  it("serializeLedger round-trips", () => {
    const ledger = buildItemLedger(["seclayer"]);
    const arr = serializeLedger(ledger);
    assert.equal(arr.length, ledger.size);
    assert.ok(arr.every((v) => typeof v.key === "string" && typeof v.disposition === "string"));
  });
});

describe("prerequisiteMet", () => {
  it("msfrpcd needs both user and pass", () => {
    assert.equal(prerequisiteMet("msfrpcd"), false);
    process.env.REDTEAM_MSFRPC_USER = "u";
    assert.equal(prerequisiteMet("msfrpcd"), false);
    process.env.REDTEAM_MSFRPC_PASS = "p";
    assert.equal(prerequisiteMet("msfrpcd"), true);
  });

  it("kerberos ticket material any-of", () => {
    assert.equal(prerequisiteMet("kerberos ticket material"), false);
    process.env.REDTEAM_KRB_KIRBI_B64 = "abc";
    assert.equal(prerequisiteMet("kerberos ticket material"), true);
  });

  it("human operator and unknown prerequisites never auto-met", () => {
    assert.equal(prerequisiteMet("human operator"), false);
    assert.equal(prerequisiteMet("Second test account"), false);
    assert.equal(prerequisiteMet("host-exec tooling"), false);
  });
});
