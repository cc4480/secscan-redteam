/**
 * High-quality HTML rendering for engagement reports.
 *
 * The runner already writes report.md, compliance-pack.md, attestation.md and
 * safety-manifest.md. Those stay — they are the diffable, greppable record and
 * the input to other tooling. This renders the same content as a self-contained
 * HTML document meant to be read by a person, opened in a browser, and printed.
 *
 * Deliberate properties:
 *
 *   - Self-contained. No CDN, no web fonts, no external images. A pentest report
 *     is read on client networks, in air-gapped review, and years after the
 *     engagement; a stylesheet that 404s turns a deliverable into a wall of
 *     unstyled text. Everything is inlined.
 *   - Safe. Body markdown goes through the same renderer the UI uses, which
 *     escapes all raw HTML and restricts links to http(s). Finding text embeds
 *     target-derived strings, so this is not a nicety.
 *   - Dark/light aware via prefers-color-scheme, with print rules that force
 *     light and drop interactive chrome, so "print to PDF" produces something
 *     worth sending without editing.
 *   - Severity colour-coded at the source. A reader scanning for the critical
 *     item should not have to read every line to find it.
 */

import { renderMarkdown } from "../ui/markdown.js";
import { type Ctx } from "../context.js";
import { type Finding } from "../types.js";
import { resolveOperatorName } from "../accountability/index.js";

export interface ReportMeta {
  engagementId: string;
  target: string;
  mode: string;
  environment: string;
  tier: number;
  operator?: string;
  client?: string;
  status: string;
  phase: string;
  verified: boolean;
  objective: string;
  startedAt: string;
  generatedAt: string;
  /** Counts shown in the summary strip. */
  findings?: { critical: number; high: number; medium: number; low: number; info: number };
  battery?: { total: number; confirmed: number; executedClean: number; killed: number; blocked: number; na: number; pending: number };
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

const STYLE = `
:root{
  --bg:#ffffff; --fg:#1a1d21; --muted:#5c6570; --line:#e3e6ea; --panel:#f7f8fa;
  --accent:#1f5fa9; --code-bg:#f2f4f7;
  --crit:#b3261e; --high:#c8500f; --med:#8a6d00; --low:#2f6f3e; --info:#4a5560;
  --ok:#2f6f3e; --warn:#8a6d00; --bad:#b3261e;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#14171a; --fg:#e6e9ec; --muted:#98a1ab; --line:#2a2f35; --panel:#1b1f24;
    --accent:#6aa9e9; --code-bg:#1e2329;
    --crit:#ff6b5e; --high:#ff9b4a; --med:#e3c14a; --low:#6fcf8b; --info:#9aa5b1;
    --ok:#6fcf8b; --warn:#e3c14a; --bad:#ff6b5e;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--bg); color:var(--fg);
  font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
.wrap{max-width:960px;margin:0 auto;padding:40px 28px 96px}
header.doc{border-bottom:2px solid var(--line);padding-bottom:22px;margin-bottom:30px}
.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:600}
h1{font-size:30px;line-height:1.2;margin:8px 0 4px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:15px;margin:0}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px 26px;margin:22px 0 0}
.meta div{font-size:14px}
.meta dt{color:var(--muted);font-size:12px;letter-spacing:.06em;text-transform:uppercase;font-weight:600}
.meta dd{margin:2px 0 0;font-weight:500;overflow-wrap:anywhere}
.strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(104px,1fr));gap:10px;margin:24px 0 0}
.cell{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:12px 14px}
.cell .n{font-size:23px;font-weight:700;line-height:1.1;font-variant-numeric:tabular-nums}
.cell .k{font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);margin-top:3px;font-weight:600}
.cell.crit .n{color:var(--crit)} .cell.high .n{color:var(--high)}
.cell.med .n{color:var(--med)}   .cell.low .n{color:var(--low)}
.cell.info .n{color:var(--info)} .cell.ok .n{color:var(--ok)}
.cell.warn .n{color:var(--warn)}
main{margin-top:34px}
main h2{font-size:21px;margin:38px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--line);letter-spacing:-.005em}
main h3{font-size:17px;margin:26px 0 8px}
main h4{font-size:15px;margin:20px 0 6px;color:var(--muted)}
main p,main li{overflow-wrap:anywhere}
main ul,main ol{padding-left:22px}
main li{margin:4px 0}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid color-mix(in srgb,var(--accent) 35%,transparent)}
a:hover{border-bottom-color:var(--accent)}
code{background:var(--code-bg);border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:13.5px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
pre{background:var(--code-bg);border:1px solid var(--line);border-radius:8px;padding:13px 15px;overflow-x:auto}
pre code{background:none;border:0;padding:0;font-size:13px}
blockquote{margin:16px 0;padding:10px 16px;border-left:3px solid var(--line);background:var(--panel);color:var(--muted);border-radius:0 8px 8px 0}
table{border-collapse:collapse;width:100%;margin:16px 0;font-size:14.5px;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:8px 11px;text-align:left;vertical-align:top}
th{background:var(--panel);font-weight:600;font-size:13px;letter-spacing:.02em}
hr{border:0;border-top:1px solid var(--line);margin:34px 0}
/* Severity chips: the report writes "[high]" / "severity: high" into prose, so
   colour the words rather than requiring the generator to emit markup. */
.sev{font-weight:700;letter-spacing:.03em;text-transform:uppercase;font-size:.86em;padding:1px 6px;border-radius:5px}
.sev-critical{color:var(--crit);background:color-mix(in srgb,var(--crit) 13%,transparent)}
.sev-high{color:var(--high);background:color-mix(in srgb,var(--high) 13%,transparent)}
.sev-medium{color:var(--med);background:color-mix(in srgb,var(--med) 15%,transparent)}
.sev-low{color:var(--low);background:color-mix(in srgb,var(--low) 13%,transparent)}
.sev-info{color:var(--info);background:color-mix(in srgb,var(--info) 13%,transparent)}
.pill{display:inline-block;font-size:12px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;
  padding:2px 9px;border-radius:999px;border:1px solid var(--line);background:var(--panel);color:var(--muted)}
.pill.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent)}
.pill.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,transparent)}
.pill.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 40%,transparent)}
footer.doc{margin-top:56px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
@media print{
  :root{--bg:#fff;--fg:#000;--muted:#444;--line:#bbb;--panel:#f4f4f4;--accent:#000}
  body{font-size:11.5pt}
  .wrap{max-width:none;padding:0}
  .cell,th,blockquote{background:#f4f4f4 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .sev{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  main h2{page-break-after:avoid} h1,h2,h3{page-break-after:avoid}
  table,pre,blockquote{page-break-inside:avoid}
  a{color:#000;border:0;text-decoration:underline}
  footer.doc{page-break-before:auto}
}
`;

/**
 * Colour the severity tags the report already writes, without emitting markup in
 * a way that can land inside an attribute or a code block.
 *
 * The match runs on the MARKDOWN source, against the one unambiguous form the
 * report uses — a bracketed `[critical]`/`[high]`/`[medium]`/`[low]`/`[info]`
 * tag — and produces a NUL sentinel that survives the renderer's HTML escaping
 * untouched. The `<span>` is substituted only AFTER rendering, so it can never
 * appear inside an href or a `<code>` the renderer built. Colouring over
 * finished HTML (a regex over the whole document) is what corrupted links and
 * code by matching the word "high" inside `…/high-risk` URLs.
 */
function decorateSeverity(markdown: string): { body: string; tokens: string[] } {
  const tokens: string[] = [];
  const body = markdown.replace(/\[(critical|high|medium|low|info)\]/gi, (_m, word: string) => {
    tokens.push(word);
    return `\u0000SEV${tokens.length - 1}\u0000`;
  });
  return { body, tokens };
}

export interface RenderHtmlOptions {
  /** Document title, shown as the page title and the H1. */
  title: string;
  /** Short line under the title. */
  subtitle?: string;
  meta: ReportMeta;
  /** The report body, as markdown. */
  markdown: string;
  /** Show the finding/battery summary strip. Off for attestation and manifests. */
  showStrip?: boolean;
}

/**
 * Build the metadata block shared by every HTML artifact, from the engagement
 * context. Severity counts are derived from the findings; battery figures are
 * passed in when the caller has them (the report does, the manifest does not).
 *
 * `ctx.events.state` is private; the snapshot getter is the supported read path
 * and copies findings so nothing here can mutate the live state.
 */
export function buildEngagementMeta(
  ctx: Ctx,
  findings: Finding[],
  battery?: ReportMeta["battery"],
): ReportMeta {
  const snap = ctx.events.snapshot;
  const counts: NonNullable<ReportMeta["findings"]> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    // Coerce and guard against prototype keys: a finding with severity "High"
    // must still count, and `"constructor" in counts` must not read a prototype.
    const sev = String(f.severity ?? "").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(counts, sev)) counts[sev as keyof typeof counts]++;
  }
  return {
    engagementId: ctx.events.engagementId,
    target: ctx.input.target,
    mode: ctx.input.mode,
    environment: ctx.input.environment ?? "staging",
    tier: ctx.tier.current,
    operator: resolveOperatorName(ctx.input.operatorName),
    client: ctx.input.client,
    status: snap.status,
    phase: snap.phase,
    verified: snap.verified,
    objective: ctx.input.objective,
    startedAt: snap.startedAt,
    generatedAt: new Date().toISOString(),
    findings: counts,
    battery,
  };
}

export function renderReportHtml(o: RenderHtmlOptions): string {
  const m = o.meta;
  const decorated = decorateSeverity(o.markdown);
  const body = renderMarkdown(decorated.body).replace(/\u0000SEV(\d+)\u0000/g, (_m, i: string) => {
    const word = decorated.tokens[Number(i)];
    return word ? `<span class="sev sev-${word.toLowerCase()}">${word}</span>` : "";
  });

  const cells: string[] = [];
  if (o.showStrip !== false) {
    const f = m.findings;
    if (f) {
      for (const [k, label, cls] of [
        ["critical", "Critical", "crit"], ["high", "High", "high"],
        ["medium", "Medium", "med"], ["low", "Low", "low"], ["info", "Info", "info"],
      ] as const) {
        cells.push(`<div class="cell ${cls}"><div class="n">${f[k]}</div><div class="k">${label}</div></div>`);
      }
    }
    const b = m.battery;
    if (b) {
      cells.push(`<div class="cell ok"><div class="n">${b.confirmed}</div><div class="k">Confirmed</div></div>`);
      cells.push(`<div class="cell"><div class="n">${b.executedClean}</div><div class="k">Clean</div></div>`);
      cells.push(`<div class="cell"><div class="n">${b.killed}</div><div class="k">Ruled out</div></div>`);
      cells.push(`<div class="cell warn"><div class="n">${b.pending}</div><div class="k">Pending</div></div>`);
    }
  }

  const statusPill =
    m.status === "complete" ? "ok" : m.status === "halted" || m.status === "blocked" ? "bad" : "warn";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="SecScan RedTeam">
<meta name="robots" content="noindex,nofollow">
<title>${esc(o.title)} — ${esc(m.target)}</title>
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
<header class="doc">
  <div class="eyebrow">SecScan RedTeam${m.client ? ` &middot; ${esc(m.client)}` : ""}</div>
  <h1>${esc(o.title)}</h1>
  ${o.subtitle ? `<p class="sub">${esc(o.subtitle)}</p>` : ""}
  <div class="meta">
    <div><dt>Target</dt><dd>${esc(m.target)}</dd></div>
    <div><dt>Engagement</dt><dd>${esc(m.engagementId)}</dd></div>
    <div><dt>Status</dt><dd><span class="pill ${statusPill}">${esc(m.status)}</span></dd></div>
    <div><dt>Mode</dt><dd>${esc(m.mode)} &middot; tier ${m.tier} &middot; ${esc(m.environment)}</dd></div>
    <div><dt>Authorisation</dt><dd>${m.verified ? '<span class="pill ok">ownership verified</span>' : '<span class="pill bad">not verified</span>'}</dd></div>
    ${m.operator ? `<div><dt>Operator</dt><dd>${esc(m.operator)}</dd></div>` : ""}
    <div><dt>Started</dt><dd>${esc(m.startedAt)}</dd></div>
    <div><dt>Generated</dt><dd>${esc(m.generatedAt)}</dd></div>
  </div>
  ${cells.length ? `<div class="strip">${cells.join("")}</div>` : ""}
</header>
<main>
<p><strong>Objective.</strong> ${esc(m.objective)}</p>
${body}
</main>
<footer class="doc">
  Generated by SecScan RedTeam from the engagement audit log. Machine-readable
  records — <code>state.json</code>, <code>item-verdicts.json</code>,
  <code>events.jsonl</code> — sit alongside this file and are the authoritative
  source for every figure above. Verify findings against them before acting.
</footer>
</div>
</body>
</html>`;
}
