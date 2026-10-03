/**
 * host-exec tests (v0.9.0) — the runner's hands on hosts.
 *
 * ALL transports are mocked: no network, no credentials, no real hosts.
 * What we prove here is the safety core, not the wire protocols:
 *  - out-of-scope hosts are rejected BEFORE any connect attempt
 *  - credentials never appear in logs, errors, or events
 *  - the kill switch terminates in-flight executions
 *  - the destructive-command denylist refuses catastrophic commands
 *  - timeouts and output caps bound every execution
 *  - audit data (redacted summary + capped output) flows into the event model
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  HostExecutor,
  checkDestructive,
  validateHostTarget,
  redactSecrets,
  destructiveDenyList,
} from "../src/host-exec/index.js";
import type { SshTransport, SshExecResult } from "../src/host-exec/index.js";
import type { SmbTransport } from "../src/host-exec/index.js";
import type { WinrmTransport } from "../src/host-exec/index.js";
import { runEngagement } from "../src/phases.js";
import type { EngagementInput } from "../src/types.js";
import type { AgentRole, ChatMessage, ChatResult, ToolCallRequest } from "@secscan/redteam-llm-router";

const FAKE_ENV: NodeJS.ProcessEnv = {
  REDTEAM_SSH_USER: "testuser",
  REDTEAM_SSH_PASSWORD: "s3cr3t-pw-FOR-TESTS",
  REDTEAM_SMB_USER: "testuser",
  REDTEAM_SMB_PASSWORD: "s3cr3t-pw-FOR-TESTS",
  REDTEAM_SMB_DOMAIN: "TEST",
  REDTEAM_WINRM_USER: "testuser",
  REDTEAM_WINRM_PASSWORD: "s3cr3t-pw-FOR-TESTS",
};

const SECRET = "s3cr3t-pw-FOR-TESTS";

// ---------------------------------------------------------------------------
// Fake transports — record calls, never touch the network
// ---------------------------------------------------------------------------

function fakeSsh(behavior: { output?: string; hang?: boolean; fail?: string } = {}): { t: SshTransport; calls: string[] } {
  const calls: string[] = [];
  const t: SshTransport = {
    async exec(args) {
      calls.push(args.command);
      if (args.signal?.aborted) throw new Error("[ssh] aborted by kill switch before exec");
      if (behavior.fail) throw new Error(behavior.fail);
      if (behavior.hang) {
        await new Promise<void>((_, reject) => {
          args.signal?.addEventListener("abort", () => reject(new Error("[ssh] aborted by kill switch — session destroyed")), { once: true });
        });
      }
      return { stdout: behavior.output ?? "Linux testhost 6.8.0", stderr: "", code: 0, ms: 5 };
    },
    async close() {},
  };
  return { t, calls };
}

function fakeSmb(): { t: SmbTransport; calls: string[] } {
  const calls: string[] = [];
  const t: SmbTransport = {
    async probeShares(args, candidates) {
      calls.push(`probeShares:${candidates.join(",")}`);
      if (args.signal?.aborted) throw new Error("[smb] aborted by kill switch");
      return [
        { share: "C$", accessible: false, note: "session/share denied" },
        { share: "IPC$", accessible: true, note: "tree connect accepted" },
      ];
    },
    async listDir(args, share, path) {
      calls.push(`listDir:${share}:${path}`);
      return [{ name: "Windows", isDirectory: true }];
    },
    async stat() {
      return { exists: true, isDirectory: false, size: 10 };
    },
    async close() {},
  };
  return { t, calls };
}

function fakeWinrm(output = "Microsoft Windows [Version 10.0]"): { t: WinrmTransport; calls: string[] } {
  const calls: string[] = [];
  const t: WinrmTransport = {
    async exec(args) {
      calls.push(args.command);
      if (args.signal?.aborted) throw new Error("[winrm] aborted by kill switch before exec");
      return { stdout: output, stderr: "", code: 0, ms: 5 };
    },
    async close() {},
  };
  return { t, calls };
}

// ---------------------------------------------------------------------------
// Safety core units
// ---------------------------------------------------------------------------

describe("validateHostTarget", () => {
  it("accepts exact scope hosts (case-insensitive)", () => {
    assert.ok(validateHostTarget("10.9.0.12", ["10.9.0.12"]).ok);
    assert.ok(validateHostTarget("HOST.EXAMPLE", ["host.example"]).ok);
  });
  it("rejects anything not exactly in scope", () => {
    for (const h of ["10.9.0.13", "10.9.0.1", "evil.example", "", "10.9.0.12.evil.com"]) {
      const r = validateHostTarget(h, ["10.9.0.12"]);
      assert.ok(!r.ok, h);
      assert.match((r as { reason: string }).reason, /out of scope|empty host/);
    }
  });
});

describe("checkDestructive", () => {
  const bad = [
    "rm -rf /",
    "rm -rf /*",
    "sudo rm -Rf / --no-preserve-root",
    "rd /s /q C:\\",
    "Remove-Item -Recurse -Force C:\\Windows",
    "mkfs.ext4 /dev/sda1",
    "Format-Volume -DriveLetter D",
    "dd if=/dev/zero of=/dev/sda bs=1M",
    "shred /dev/sda",
    ":(){ :|:& };:",
    "shutdown -h now",
    "Restart-Computer -Force",
    "vssadmin delete shadows /all",
    "wbadmin delete catalog -quiet",
    "bcdedit /set recoveryenabled no",
    "cipher /w:C:",
  ];
  for (const cmd of bad) {
    it(`refuses: ${cmd.slice(0, 40)}`, () => {
      const hit = checkDestructive(cmd);
      assert.ok(hit, `expected denylist hit for ${cmd}`);
    });
  }
  const good = [
    "uname -a",
    "ss -tlnp",
    "sudo -l",
    "Get-Service | Select-Object Name, Status",
    "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    "ls /tmp",
    "find / -perm -4000 2>/dev/null",
    "rm /tmp/canary-marker", // narrow tmp cleanup is not root destruction
  ];
  for (const cmd of good) {
    it(`allows: ${cmd.slice(0, 40)}`, () => {
      assert.equal(checkDestructive(cmd), null);
    });
  }
  it("documents the denylist", () => {
    assert.ok(destructiveDenyList().length >= 10);
  });
});

// ---------------------------------------------------------------------------
// Executor with mocked transports
// ---------------------------------------------------------------------------

describe("HostExecutor safety", () => {
  it("rejects out-of-scope hosts before connecting", async () => {
    const { t, calls } = fakeSsh();
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshExec({ host: "10.99.0.99", command: "uname -a", scopeHosts: ["10.9.0.12"] });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("out of scope"), r.refused ?? "no refusal reason");
    assert.equal(calls.length, 0, "transport must never be touched");
  });

  it("refuses destructive commands before connecting", async () => {
    const { t, calls } = fakeSsh();
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshExec({ host: "10.9.0.12", command: "rm -rf /", scopeHosts: ["10.9.0.12"] });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("denylist"), r.refused ?? "no refusal reason");
    assert.equal(calls.length, 0);
  });

  it("fails fast with an actionable message when credentials are missing", async () => {
    const { t, calls } = fakeSsh();
    const ex = new HostExecutor({ ssh: () => t, env: {} });
    const r = await ex.sshExec({ host: "10.9.0.12", command: "uname -a", scopeHosts: ["10.9.0.12"] });
    assert.equal(r.ok, false);
    assert.match(r.refused ?? "", /REDTEAM_SSH_USER|REDTEAM_SSH_PASSWORD/);
    assert.equal(calls.length, 0);
  });

  it("never leaks credentials in summaries, output, or refusals", async () => {
    const evil: SshTransport = {
      async exec() {
        throw new Error(`auth failed for testuser with ${SECRET} on 10.9.0.12`);
      },
      async close() {},
    };
    const ex = new HostExecutor({ ssh: () => evil, env: FAKE_ENV });
    const r = await ex.sshExec({ host: "10.9.0.12", command: `echo ${SECRET}`, scopeHosts: ["10.9.0.12"] });
    for (const s of [r.summary, r.output, r.refused ?? ""]) {
      assert.ok(!s.includes(SECRET), `credential leaked in: ${s.slice(0, 120)}`);
    }
    assert.ok(r.summary.includes("[REDACTED]"));
  });

  it("kill switch refuses new work once aborted", async () => {
    const { t, calls } = fakeSsh();
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    ex.killSwitch.aborted = true;
    const r = await ex.sshExec({ host: "10.9.0.12", command: "uname -a", scopeHosts: ["10.9.0.12"] });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("kill switch"));
    assert.equal(calls.length, 0);
  });

  it("kill switch terminates in-flight execution", async () => {
    const { t } = fakeSsh({ hang: true });
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const ctrl = new AbortController();
    const p = ex.sshExec({ host: "10.9.0.12", command: "sleep 999", scopeHosts: ["10.9.0.12"], signal: ctrl.signal });
    await new Promise((r) => setTimeout(r, 20));
    ctrl.abort();
    const res = await p;
    assert.equal(res.ok, false);
    assert.match(res.summary, /kill switch/i);
  });

  it("times out runaway commands", async () => {
    const hanging: SshTransport = {
      async exec() {
        await new Promise<SshExecResult>(() => undefined); // never resolves, ignores signal
        throw new Error("unreachable");
      },
      async close() {},
    };
    const ex = new HostExecutor({ ssh: () => hanging, env: FAKE_ENV });
    const r = await ex.sshExec({ host: "10.9.0.12", command: "sleep 999", scopeHosts: ["10.9.0.12"], timeoutMs: 50 });
    assert.equal(r.ok, false);
    assert.match(r.summary, /timed out/);
  });

  it("caps output (no bulk exfiltration)", async () => {
    const { t } = fakeSsh({ output: "x".repeat(100_000) });
    const ex = new HostExecutor({ ssh: () => t, env: FAKE_ENV });
    const r = await ex.sshExec({ host: "10.9.0.12", command: "cat bigfile", scopeHosts: ["10.9.0.12"] });
    assert.ok(r.output.length < 100_000);
    assert.ok(r.output.includes("truncated"));
  });

  it("smb list_shares reports reachability via the fake", async () => {
    const { t, calls } = fakeSmb();
    const ex = new HostExecutor({ smb: () => t, env: FAKE_ENV });
    const r = await ex.smbExec({ host: "10.9.0.11", operation: "list_shares", scopeHosts: ["10.9.0.11"] });
    assert.equal(r.ok, true);
    assert.ok(r.output.includes("IPC$"));
    assert.equal(calls.length, 1);
  });

  it("smb requires a share for list_dir", async () => {
    const { t, calls } = fakeSmb();
    const ex = new HostExecutor({ smb: () => t, env: FAKE_ENV });
    const r = await ex.smbExec({ host: "10.9.0.11", operation: "list_dir", scopeHosts: ["10.9.0.11"] });
    assert.equal(r.ok, false);
    assert.ok(r.refused?.includes("requires a share"));
    assert.equal(calls.length, 0);
  });

  it("winrm executes via the fake and redacts", async () => {
    const { t, calls } = fakeWinrm();
    const ex = new HostExecutor({ winrm: () => t, env: FAKE_ENV });
    const r = await ex.winrmExec({ host: "10.9.0.11", command: "Get-Service", scopeHosts: ["10.9.0.11"] });
    assert.equal(r.ok, true);
    assert.ok(r.summary.includes("winrm 10.9.0.11"));
    assert.ok(!r.summary.includes(SECRET) && !r.output.includes(SECRET));
    assert.equal(calls.length, 1);
  });

  it("redactSecrets is total", () => {
    assert.equal(redactSecrets(`a ${SECRET} b ${SECRET} c`, [SECRET]), "a [REDACTED] b [REDACTED] c");
  });
});

// ---------------------------------------------------------------------------
// Phases integration: the agent's ssh_exec flows through dispatch → events
// ---------------------------------------------------------------------------

describe("host tools in the engagement loop", () => {
  let dir: string;
  let sshCalls: string[];
  let eventsWithSsh: { action: string; result: string }[];

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "hostexec-"));
    sshCalls = [];
    eventsWithSsh = [];
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  function fakeSshFactory(): SshTransport {
    return {
      async exec(args) {
        sshCalls.push(args.command);
        return { stdout: "Linux testhost", stderr: "", code: 0, ms: 5 };
      },
      async close() {},
    };
  }

  const textOnly = (text: string): ChatResult => ({ text, toolCalls: [], provider: "fake", model: "fake" });

  function scriptedLlm(outOfScope: boolean) {
    const toolCall = (name: string, args: Record<string, unknown>): ToolCallRequest => ({
      id: `call-${name}`,
      name,
      arguments: args,
    });
    return async (role: AgentRole, messages: ChatMessage[], opts: { tools?: { name: string }[] }): Promise<ChatResult> => {
      const has = (s: string) => messages.some((m) => m.content.includes(s));
      if (role === "coordinator") {
        if (has("Transition awaiting sign-off")) return textOnly("SIGN-OFF: approved.");
        // replan / override rounds: we're done
        if (has("RE-PLAN") || has("Last batch results") || has("OVERRIDE"))
          return textOnly('```json\n{"tasks": [], "finish": true, "note": "done"}\n```');
        // decompose directive: task the exploiter once
        if (has("Return ONLY a JSON block")) {
          const host = outOfScope ? "10.99.0.99" : "10.9.0.12";
          return textOnly(
            '```json\n{"tasks": [{"kind": "probe", "brief": "ssh recon ' +
              host +
              '", "attackId": "T1018", "category": "validation", "maxTurns": 4}], "finish": false, "note": "go"}\n```',
          );
        }
        // plan phase
        return textOnly(
          '```json\n{"adversaryProfile": "test", "steps": [{"phase": "exploit", "attackId": "T1018", "description": "ssh recon"}]}\n```',
        );
      }
      if (role === "recon") return textOnly("recon brief: host mapped");
      if (role === "reporter") return textOnly('# Report\n\n```json {"findings": []} ```');
      // exploiter task: fire one ssh_exec, then report the verdict
      const sys = messages.find((m) => m.role === "system")?.content ?? "";
      if (sys.includes("Task:") || has("Execute the task now")) {
        const toolSeen = messages.some((m) => m.role === "tool");
        if (!toolSeen) {
          return {
            text: "firing ssh_exec",
            toolCalls: [
              toolCall("ssh_exec", {
                host: outOfScope ? "10.99.0.99" : "10.9.0.12",
                command: "uname -a",
                category: "validation",
                targetProfile: "linux",
                attackId: "T1018",
                hypothesis: "LX-006 os fingerprint",
              }),
            ],
            provider: "fake",
            model: "fake",
          };
        }
        return textOnly("TRIED: ssh uname / OBSERVED: denied-or-output / VERDICT: killed - done");
      }
      return textOnly("idle");
    };
  }

  async function run(outOfScope: boolean) {
    const input: EngagementInput = {
      target: "10.9.0.12",
      mode: "red",
      objective: "host-exec integration test",
      roe: { scope: ["10.9.0.12"] },
    };
    const executor = new HostExecutor({ ssh: fakeSshFactory, env: FAKE_ENV });
    const res = await runEngagement(input, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: {
        verify: async () => true,
        completeForRole: scriptedLlm(outOfScope) as never,
        hostExecutor: executor,
      },
    });
    const events = readFileSync(join(dir, res.engagementId, "events.jsonl"), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as { action: string; result: string });
    return { res, events: events.filter((e) => e.action === "ssh_exec") };
  }

  it("out-of-scope ssh_exec is DENIED before any connect", async () => {
    const { res, events } = await run(true);
    assert.equal(res.status, "complete");
    assert.equal(sshCalls.length, 0, "no SSH connection attempted");
    assert.ok(events.length >= 1, "ssh_exec event logged");
    assert.ok(events[0]!.result.includes("DENIED"), events[0]!.result.slice(0, 120));
    assert.ok(events[0]!.result.includes("out of scope"));
  });

  it("in-scope ssh_exec executes and the audit lands in the event feed", async () => {
    const { res, events } = await run(false);
    assert.equal(res.status, "complete");
    assert.equal(sshCalls.length, 1);
    assert.equal(sshCalls[0], "uname -a");
    assert.ok(events.length >= 1);
    assert.ok(events[0]!.result.includes("ssh 10.9.0.12"), events[0]!.result.slice(0, 160));
    assert.ok(events[0]!.result.includes("Linux testhost"), "output snippet in event");
  });

  it("the agent's tool list includes all three host tools", async () => {
    let sawTools: string[] = [];
    const llm = async (role: AgentRole, messages: ChatMessage[], opts: { tools?: { name: string }[] }): Promise<ChatResult> => {
      if (opts.tools) sawTools = [...new Set([...sawTools, ...opts.tools.map((t) => t.name)])];
      if (role === "coordinator" && messages.some((m) => m.content.includes("Transition awaiting sign-off")))
        return textOnly("SIGN-OFF: approved.");
      return textOnly("idle");
    };
    const input: EngagementInput = {
      target: "10.9.0.12",
      mode: "red",
      objective: "tool-list check",
      roe: { scope: ["10.9.0.12"] },
    };
    await runEngagement(input, {
      mcpToken: "test",
      deepseekApiKey: "test",
      qwenApiKey: "test",
      engagementsDir: dir,
      deps: { verify: async () => true, completeForRole: llm as never },
    });
    for (const t of ["ssh_exec", "smb_exec", "winrm_exec"]) {
      assert.ok(sawTools.includes(t), `agent tool list includes ${t}`);
    }
    for (const t of ["winrm_probe", "rdp_auth", "rdp_shadow_prep", "smb_pth", "ad_enum", "krb_ptt", "ssh_agent_audit", "nfs_enum"]) {
      assert.ok(sawTools.includes(t), `agent tool list includes wave-2 tool ${t}`);
    }
  });
});
