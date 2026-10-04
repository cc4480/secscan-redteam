/**
 * How to add a provider later (Claude / ChatGPT / Gemini / GLM / Qwen):
 *
 *   1. Create src/providers/<id>.ts exporting a class that implements
 *      LlmProvider from ../types.js (see deepseek.ts for the reference).
 *   2. Read its key from a dedicated env var (e.g. ANTHROPIC_API_KEY) —
 *      never from a file, never hardcoded.
 *   3. Register it in src/router.ts via registerProvider(new MyProvider()).
 *   4. Optionally add role routes in src/policy.ts.
 *
 * Provider statuses:
 *   - deepseek : ACTIVE (v0.6) — all roles: coordinator/recon/reporter on
 *     deepseek-v4.1-flash, exploiter on deepseek-v4.1-pro (reasoning).
 *   - qwen (Alibaba) : REGISTERED, not routed (v0.5 had exploiter on
 *     qwen3.8-max; operator asked to run DeepSeek-only for now and bring
 *     Qwen back later — swap it back in via src/policy.ts).
 *   - anthropic (Claude), openai (ChatGPT), google (Gemini), zhipu (GLM),
 *     moonshot (Kimi — the runner-up for the next swap) : PLANNED —
 *     interface is ready, no implementation yet.
 */
export {};
