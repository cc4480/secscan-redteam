/**
 * Red-team definition for the harness.
 *
 * Shape mirrors the proven dsh-agent-teams profile format
 * (NanmiCoder/dsh-agent-teams src/profiles.ts): named members with
 * {name, role, provider, model, reasoning_effort, executionPrompt} and seed
 * tasks with dependencies. The harness's team plugin consumes this to spawn
 * the coordinator + specialists as durable continuable subagents.
 *
 * v0.1 model policy (DeepSeek ONLY):
 *   - deepseek-flash — fast, cheap, strong tool use → recon loops,
 *     coordinator orchestration, reporter write-up.
 *   - deepseek-v4-pro   — premium reasoning → exploiter hypothesis formation,
 *     exploit-chain planning, pivot decisions.
 * The router (llm-router/) is provider-pluggable; adding Claude / ChatGPT /
 * Gemini / GLM / Qwen later means registering new provider adapters, not
 * rewriting these roles.
 */

export interface TeamMember {
  name: string;
  role: string;
  provider: string;
  model: string;
  reasoning_effort?: string;
  /** System-prompt file for this role (see ../../agents/). */
  promptFile: string;
  executionPrompt?: string;
}

export interface TeamTask {
  id: string;
  subject: string;
  description: string;
  assignee: string;
  dependencies?: string[];
}

export interface RedTeamProfile {
  description: string;
  protocol: string;
  members: TeamMember[];
  tasks: TeamTask[];
}

export const REDTEAM_PROFILE: RedTeamProfile = {
  description:
    "AI red-team for authorized web-app pentests. Coordinator runs the engagement; " +
    "recon maps the surface; exploiter reasons over findings and invents dynamic tests; " +
    "reporter writes the client-ready report. All active testing requires proven domain ownership.",

  protocol:
    "ReAct engagement protocol. Every specialist loops: REASON (form a hypothesis from " +
    "observations so far) → ACT (call exactly one tool) → OBSERVE (read the result, update the " +
    "hypothesis). No static checklists: if a result is surprising, the next action must chase the " +
    "surprise, not the plan. The coordinator owns phase transitions and may re-task any member. " +
    "The exploiter NEVER runs an active probe against a target whose ownership is unverified — " +
    "the auth gate denies it, and attempting to bypass the gate ends the engagement immediately.",

  members: [
    {
      name: "coordinator",
      role: "Engagement lead. Owns the plan, phases, scope discipline, and final assembly. Runs recon → exploitation → reporting in order, re-tasks on surprises.",
      provider: "deepseek",
      model: "deepseek-flash",
      promptFile: "agents/coordinator.md",
      executionPrompt:
        "You are the engagement lead. Keep phases tight, keep every action inside the authorized scope, " +
        "and never let a specialist freelance outside their task. Fast decisions; escalate reasoning to the exploiter.",
    },
    {
      name: "recon",
      role: "Surface mapper. Passive recon first (headers, TLS, DNS, exposed files, tech fingerprinting via seclayer_scan passive tier), then hands attack-surface notes to the exploiter.",
      provider: "deepseek",
      model: "deepseek-flash",
      promptFile: "agents/recon.md",
      executionPrompt:
        "Map first, touch lightly. Enumerate everything observable without active probing, then write " +
        "a crisp attack-surface brief: entry points, parameters, auth flows, tech stack guesses.",
    },
    {
      name: "exploiter",
      role: "Reasoning attacker. Takes recon + scan findings, forms hypotheses, crafts context-specific payloads, observes responses, and pivots. The dynamic-testing differentiator lives here.",
      provider: "deepseek",
      model: "deepseek-v4-pro",
      reasoning_effort: "high",
      promptFile: "agents/exploiter.md",
      executionPrompt:
        "Think like an attacker, act like a scientist. Every probe tests a specific hypothesis. " +
        "When a result contradicts your mental model, your next move investigates the contradiction — " +
        "that is where real vulnerabilities hide. Never repeat a failed payload verbatim; mutate with intent.",
    },
    {
      name: "reporter",
      role: "Client report author. Converts validated findings into a business-readable report: executive summary, per-finding impact + evidence + fix, retest checklist.",
      provider: "deepseek",
      model: "deepseek-flash",
      promptFile: "agents/reporter.md",
      executionPrompt:
        "Write for the client's CTO, not for hackers. Every finding needs: what it is, why it matters " +
        "in business terms, the evidence that proves it, and a concrete fix. No finding without evidence.",
    },
  ],

  tasks: [
    {
      id: "scope",
      subject: "Verify scope and authorization",
      description:
        "Confirm the engagement scope (target URLs, test window, auth credentials if any) and run " +
        "the auth gate: DNS TXT ownership proof at _seclayer-challenge.<domain> (or the well-known " +
        "file). If ownership is unverified, the engagement runs PASSIVE ONLY — no aggressive scans, " +
        "no crafted payloads. Record the authorization state for the report.",
      assignee: "coordinator",
    },
    {
      id: "recon",
      subject: "Passive reconnaissance and surface mapping",
      description:
        "Enumerate the attack surface without active probing: run seclayer_scan (standard tier) for " +
        "the baseline, review headers/TLS/DNS/exposed files, fingerprint the stack, list parameters " +
        "and auth flows. Deliver an attack-surface brief.",
      assignee: "recon",
      dependencies: ["scope"],
    },
    {
      id: "exploit",
      subject: "Dynamic exploitation",
      description:
        "Reason over the recon brief and scan findings. Form hypotheses, run aggressive-tier scans " +
        "where authorized, craft context-specific payloads, observe, and pivot. Validate every " +
        "candidate finding with a second, independent observation before reporting it.",
      assignee: "exploiter",
      dependencies: ["recon"],
    },
    {
      id: "report",
      subject: "Client report",
      description:
        "Assemble the client-ready report: executive summary, posture score, per-finding business " +
        "impact + evidence + fix, authorization statement, and retest checklist.",
      assignee: "reporter",
      dependencies: ["exploit"],
    },
  ],
};
