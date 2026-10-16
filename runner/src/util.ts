/**
 * Shared tiny utilities (v0.19.0 refactor).
 *
 * sleep: black-mode jitter + blackout waits.
 * extractJsonBlock: pull a fenced (or bare) JSON block out of model output.
 * Both are pure, dependency-free, and used across dispatcher/agents/report.
 */
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Generate a fresh engagement id, or validate an operator-supplied one. */
export function safeEngagementId(candidate?: string): string {
  const id = candidate ?? `eng-${new Date().toISOString().slice(0, 10)}-${Math.random().toString(36).slice(2, 6)}`;
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,120}$/.test(id)) {
    throw new Error(`[runner] invalid engagement id: ${JSON.stringify(id)}`);
  }
  return id;
}

export function extractJsonBlock(text: string): unknown | null {
  const fenced = text.match(/```json\s*([\s\S]*?)```/i) ?? text.match(/```\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : text;
  try {
    return JSON.parse(candidate);
  } catch {
    const start = candidate.indexOf("{");
    const end = candidate.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(candidate.slice(start, end + 1));
      } catch {
        return null;
      }
    }
    return null;
  }
}
