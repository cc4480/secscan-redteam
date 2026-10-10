/**
 * T16 regression: the agent loop must record TOOL CALLS in history.
 *
 * T11 proved two drops broke every real multi-turn tool conversation:
 * the DeepSeek provider's wire format couldn't carry assistant tool_calls,
 * and this loop recorded a tool-calling turn as bare text, discarding the
 * calls. The provider side is fixed (llm-router emits `tool_calls`); this
 * test pins the runner side — on turn 2, the outbound history must declare
 * the assistant's call AND the tool result answering the same call id, the
 * exact shape wire APIs require (an undeclared tool result is a 400).
 *
 * Fake completeForRole, zero network. Turn 1 returns a Tier-0 bookkeeping
 * call (update_target_map — touches shared state only); turn 2 captures
 * the history it is handed and answers text-only to end the loop.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { agentLoop } from "../src/agents.js";
import type { Ctx } from "../src/context.js";
import type { EngagementPhase } from "../src/types.js";
import type { ChatMessage } from "@secscan/redteam-llm-router";

describe("agent loop tool-call history (T16)", () => {
  it("turn 2 history declares the assistant tool call and its tool result", async () => {
    const seen: ChatMessage[][] = [];
    let turn = 0;
    const callId = "call_T16_history";
    const ctx = {
      actions: 0,
      consecutive5xx: 0,
      probesUsed: 0,
      deniedStreak: 0,
      redirects: 0,
      startedAt: Date.now(),
      config: { maxActions: 60, maxDurationMs: 45 * 60_000 },
      input: { roe: { blackoutWindows: [] }, fullBattery: false },
      deps: {
        completeForRole: async (_role: unknown, messages: ChatMessage[]) => {
          turn++;
          seen.push(messages.map((m) => ({ ...m })));
          if (turn === 1) {
            return {
              text: "mapping the surface first",
              toolCalls: [
                {
                  id: callId,
                  name: "update_target_map",
                  arguments: { entries: [{ area: "/login", method: "GET" }] },
                },
              ],
            };
          }
          return { text: "done", toolCalls: [] };
        },
      },
      events: { dir: "", append: () => {} },
      targetMap: [],
      liveFindings: [],
      killedLive: [],
      registryHits: [],
      coverage: new Set<string>(),
      opsecCooldown: new Set<string>(),
      plan: undefined,
      itemLedger: undefined,
      tier: { current: 2, chainSteps: new Map<string, number>() },
      hostKill: { aborted: false, controllers: new Set<AbortController>() },
      safety: {
        killSwitchAborts: 0,
        autoHalt: {
          isHalted: () => false,
          haltReason: () => undefined,
          recordOutcome: () => undefined,
        },
        limiter: { acquire: async () => {} },
      },
    } as unknown as Ctx;

    await agentLoop(ctx, "recon", "recon" as EngagementPhase, "sys", "user", [], 5, {
      onIdle: () => null,
    });

    assert.equal(seen.length, 2, "loop ran exactly two model turns");
    const outboundTurn2 = seen[1]!;
    const assistantWithCalls = outboundTurn2.find(
      (m) => m.role === "assistant" && m.toolCalls && m.toolCalls.length > 0,
    );
    assert.ok(
      assistantWithCalls,
      "turn-2 history must carry the assistant message WITH its tool calls",
    );
    assert.equal(assistantWithCalls.toolCalls![0]!.id, callId);
    assert.equal(assistantWithCalls.toolCalls![0]!.name, "update_target_map");

    const toolResult = outboundTurn2.find((m) => m.role === "tool");
    assert.ok(toolResult, "turn-2 history must carry the tool result");
    assert.equal(
      toolResult.toolCallId,
      callId,
      "tool result answers the call the assistant message declared",
    );
    // Order matters to wire APIs: the declaring assistant turn precedes the
    // tool result that answers it.
    assert.ok(
      outboundTurn2.indexOf(assistantWithCalls) < outboundTurn2.indexOf(toolResult),
      "assistant tool-call turn precedes its tool result",
    );
    // And the bookkeeping call really dispatched (shared state updated).
    assert.equal((ctx as unknown as { targetMap: unknown[] }).targetMap.length, 1);
  });
});
