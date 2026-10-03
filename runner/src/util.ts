/**
 * Shared tiny utilities (v0.19.0 refactor).
 *
 * sleep: black-mode jitter + blackout waits.
 * extractJsonBlock: pull a fenced (or bare) JSON block out of model output.
 * Both are pure, dependency-free, and used across dispatcher/agents/report.
 */
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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
