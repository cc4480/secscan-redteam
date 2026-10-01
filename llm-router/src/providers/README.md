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
 *   - deepseek : ACTIVE (v0.1)
 *   - anthropic (Claude), openai (ChatGPT), google (Gemini), zhipu (GLM),
 *     qwen (Alibaba) : PLANNED — interface is ready, no implementation yet.
 */
export {};
