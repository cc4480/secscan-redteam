/**
 * Minimal safe markdown → HTML renderer (v0.22.0).
 *
 * Report content comes from our own runner, but findings can embed
 * target-derived text — so ALL raw HTML is escaped first and only a safe
 * subset of markdown constructs is rendered. Links are restricted to
 * http(s); everything else renders as plain text.
 */

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function inline(s: string): string {
  // s is already HTML-escaped at this point.
  let out = s;
  // inline code (protect from further transforms)
  const codes: string[] = [];
  out = out.replace(/`([^`]+)`/g, (_, c: string) => {
    codes.push(c);
    return `\u0000${codes.length - 1}\u0000`;
  });
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/(^|[^*\w])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  out = out.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" rel="nofollow noopener" target="_blank">$1</a>');
  // Non-http(s) link targets (javascript:, data:, …) are stripped to their
  // text so they can never become clickable — or linger as bait.
  out = out.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1");
  out = out.replace(/\u0000(\d+)\u0000/g, (_, i: string) => `<code>${codes[Number(i)]}</code>`);
  return out;
}

function isTableRow(line: string): boolean {
  return /^\|.*\|\s*$/.test(line.trim());
}

function isTableSep(line: string): boolean {
  return /^\|?[\s:|-]+\|?[\s:|-]*$/.test(line.trim()) && line.includes("-");
}

function renderTable(lines: string[]): string {
  const rows = lines.map((l) =>
    l
      .trim()
      .replace(/^\||\|$/g, "")
      .split("|")
      .map((c) => inline(c.trim())),
  );
  const head = rows[0] ?? [];
  const body = rows.slice(1);
  return (
    "<table><thead><tr>" +
    head.map((c) => `<th>${c}</th>`).join("") +
    "</tr></thead><tbody>" +
    body.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") +
    "</tbody></table>"
  );
}

/** Render markdown to sanitized HTML. Never throws — falls back to <pre>. */
export function renderMarkdown(md: string): string {
  try {
    return renderMarkdownInner(md);
  } catch {
    return `<pre>${escapeHtml(md).slice(0, 200_000)}</pre>`;
  }
}

function renderMarkdownInner(md: string): string {
  const src = escapeHtml(md).slice(0, 500_000);
  // Extract fenced code blocks first (no transforms inside).
  const fences: string[] = [];
  let text = src.replace(/```(\w*)\n([\s\S]*?)```/g, (_, _lang: string, code: string) => {
    fences.push(code.replace(/^\n|\n$/g, ""));
    return `\u0001${fences.length - 1}\u0001`;
  });

  const lines = text.split("\n");
  const html: string[] = [];
  let i = 0;
  let listOpen = false;
  const closeList = () => {
    if (listOpen) {
      html.push("</ul>");
      listOpen = false;
    }
  };

  while (i < lines.length) {
    const line = lines[i]!;
    const fence = line.match(/^\u0001(\d+)\u0001$/);
    if (fence) {
      closeList();
      html.push(`<pre><code>${fences[Number(fence[1])]}</code></pre>`);
      i++;
      continue;
    }
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      closeList();
      const level = h[1]!.length;
      html.push(`<h${level}>${inline(h[2]!)}</h${level}>`);
      i++;
      continue;
    }
    if (/^\s*---+\s*$/.test(line)) {
      closeList();
      html.push("<hr>");
      i++;
      continue;
    }
    if (/^\s*>\s?/.test(line)) {
      closeList();
      const quote: string[] = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i]!)) {
        quote.push(lines[i]!.replace(/^\s*>\s?/, ""));
        i++;
      }
      html.push(`<blockquote>${quote.map((q) => `<p>${inline(q)}</p>`).join("")}</blockquote>`);
      continue;
    }
    if (isTableRow(line) && i + 1 < lines.length && isTableSep(lines[i + 1]!)) {
      closeList();
      const tbl: string[] = [line, lines[i + 1]!];
      i += 2;
      while (i < lines.length && isTableRow(lines[i]!)) {
        tbl.push(lines[i]!);
        i++;
      }
      // drop the separator row
      html.push(renderTable([tbl[0]!, ...tbl.slice(2)]));
      continue;
    }
    const li = line.match(/^\s*[-*]\s+(.*)$/);
    if (li) {
      if (!listOpen) {
        html.push("<ul>");
        listOpen = true;
      }
      html.push(`<li>${inline(li[1]!)}</li>`);
      i++;
      continue;
    }
    if (/^\s*$/.test(line)) {
      closeList();
      i++;
      continue;
    }
    closeList();
    html.push(`<p>${inline(line)}</p>`);
    i++;
  }
  closeList();
  return html.join("\n").replace(/\u0001(\d+)\u0001/g, (_, n: string) => `<pre><code>${fences[Number(n)]}</code></pre>`);
}
