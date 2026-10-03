/**
 * Honest Nuclei counting for reports (v0.21.0).
 *
 * The anti-AI-washing posture, same as v0.20.0 variants: "418 attack
 * intents", "N variant executions", and "M nuclei template executions" are
 * reported as SEPARATE numbers — never merged into one inflated "attacks"
 * figure. A competitor-style single number is exactly what we refuse to
 * print.
 */

export interface NucleiCounts {
  templateExecutions: number;
  templatesRun: number;
  findings: number;
}

/** One-line honest summary for the battery coverage line. */
export function nucleiCountLine(c: NucleiCounts): string {
  if (c.templateExecutions === 0) return "";
  return (
    `Nuclei template executions: ${c.templateExecutions} runs (${c.templatesRun} template selections, ${c.findings} findings). ` +
    `Template executions are variant-level checks — counted separately from the 418 intents, never merged.`
  );
}
