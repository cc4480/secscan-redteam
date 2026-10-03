/**
 * Extract the reporter's OPERATION NARRATIVE (v0.19.0 refactor — extracted from report.ts).
 */
export function extractNarrative(md: string): string {
  const cut = md.search(/\n#{1,3}\s|\n\d+\.\s+\*\*/);
  const head = (cut > 0 ? md.slice(0, cut) : md).replace(/^.*OPERATION NARRATIVE.*$/gim, "").trim();
  return head.slice(0, 600);
}
