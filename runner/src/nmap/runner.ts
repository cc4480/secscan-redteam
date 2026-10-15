/**
 * Nmap process runner + XML parser (v0.31.0).
 *
 * The spawn function is injected, exactly as in the nuclei bridge, so the
 * parser and the executor are testable without nmap installed and without a
 * network. Nothing here decides policy — it runs an argv it is handed and
 * reports what came back.
 *
 * Output is XML (-oX -) rather than greppable text: nmap's human format is for
 * humans, and a parser over it breaks the first time a service banner contains
 * a word that looks like a column.
 */

export interface NmapSpawnOpts {
  file: string;
  args: string[];
  timeoutMs: number;
  signal?: AbortSignal;
}

export interface NmapSpawnResult {
  stdout: string;
  stderr: string;
  /** Exit code, or null when killed by timeout/signal. */
  code: number | null;
  timedOut: boolean;
}

export type SpawnFn = (opts: NmapSpawnOpts) => Promise<NmapSpawnResult>;

export interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  product: string;
  version: string;
  /** NSE script id → output, when scripts ran. */
  scripts: Record<string, string>;
}

export interface NmapHostResult {
  address: string;
  hostnames: string[];
  state: string;
  ports: NmapPort[];
  osMatches: string[];
}

export interface NmapRunResult {
  hosts: NmapHostResult[];
  /** nmap's own summary line, echoed for the audit log. */
  summary: string;
  /** Hosts that were up but produced nothing, kept for honest counting. */
  upHostCount: number;
  elapsedS: number;
}

/**
 * Real spawn. Uses child_process directly with an argv array — never a shell —
 * so no argument can be reinterpreted as a command.
 */
export const realNmapSpawn: SpawnFn = async (opts) => {
  const { spawn } = await import("node:child_process");
  return new Promise<NmapSpawnResult>((resolve) => {
    const child = spawn(opts.file, opts.args, { windowsHide: true });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, opts.timeoutMs);
    const onAbort = (): void => {
      child.kill();
    };
    opts.signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString("utf8");
    });
    child.on("error", (err: Error) => {
      clearTimeout(timer);
      resolve({ stdout, stderr: `${stderr}\n${err.message}`, code: null, timedOut });
    });
    child.on("close", (code: number | null) => {
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      resolve({ stdout, stderr, code, timedOut });
    });
  });
};

/** Decode the five XML entities nmap emits. Deliberately not a full parser. */
function unescapeXml(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function attr(tag: string, name: string): string {
  const m = new RegExp(`${name}="([^"]*)"`).exec(tag);
  return m ? unescapeXml(m[1]!) : "";
}

/**
 * Parse nmap's XML.
 *
 * A hand-rolled scan rather than a DOM dependency: nmap's schema is small and
 * fixed, and pulling an XML library into the runner to read six attributes
 * would be a supply-chain cost for no gain. It is deliberately tolerant —
 * unparseable input yields no hosts rather than throwing, because a scan that
 * ran and produced odd output must still be recorded as having run.
 */
export function parseNmapXml(xml: string): NmapRunResult {
  const hosts: NmapHostResult[] = [];
  let upHostCount = 0;
  let elapsedS = 0;

  const elapsed = /elapsed="([\d.]+)"/.exec(xml);
  if (elapsed) elapsedS = Number(elapsed[1]) || 0;

  const hostBlocks = xml.match(/<host\b[\s\S]*?<\/host>/g) ?? [];
  for (const block of hostBlocks) {
    const stateTag = /<status\b[^>]*>/.exec(block)?.[0] ?? "";
    const state = attr(stateTag, "state") || "unknown";
    // A host nmap reports as down is not a result; counting it would inflate
    // every "hosts found" number in the report.
    if (state !== "up") continue;
    upHostCount++;

    const address = attr(/<address\b[^>]*>/.exec(block)?.[0] ?? "", "addr");
    const hostnames = (block.match(/<hostname\b[^>]*>/g) ?? [])
      .map((t) => unescapeXml(/name="([^"]*)"/.exec(t)?.[1] ?? ""))
      .filter(Boolean);

    const ports: NmapPort[] = [];
    for (const pTag of block.match(/<port\b[^>]*>[\s\S]*?<\/port>/g) ?? []) {
      const openTag = /<port\b[^>]*>/.exec(pTag)?.[0] ?? "";
      const stateM = /<state\b[^>]*>/.exec(pTag)?.[0] ?? "";
      const svcTag = /<service\b[^>]*>/.exec(pTag)?.[0] ?? "";
      const scripts: Record<string, string> = {};
      for (const sTag of pTag.match(/<script\b[^>]*>[\s\S]*?<\/script>/g) ?? []) {
        const id = attr(/<script\b[^>]*>/.exec(sTag)?.[0] ?? "", "id");
        const out = /<script\b[^>]*>([\s\S]*?)<\/script>/.exec(sTag)?.[1] ?? "";
        if (id) scripts[id] = unescapeXml(out).trim().slice(0, 500);
      }
      ports.push({
        port: Number(attr(openTag, "portid")) || 0,
        protocol: attr(openTag, "protocol") || "tcp",
        state: attr(stateM, "state") || "unknown",
        service: attr(svcTag, "name"),
        product: attr(svcTag, "product"),
        version: attr(svcTag, "version"),
        scripts,
      });
    }

    const osMatches = (block.match(/<osmatch\b[^>]*>/g) ?? [])
      .map((t) => unescapeXml(attr(t, "name")))
      .filter(Boolean)
      .slice(0, 5);

    hosts.push({ address, hostnames, state, ports, osMatches });
  }

  return { hosts, upHostCount, elapsedS, summary: summarise(hosts) };
}

/** One line for the audit log — what actually came back, not what was asked. */
function summarise(hosts: NmapHostResult[]): string {
  if (hosts.length === 0) return "no hosts up";
  const parts = hosts.map((h) => {
    const open = h.ports.filter((p) => p.state === "open");
    const label = h.hostnames[0] ? `${h.address} (${h.hostnames[0]})` : h.address;
    return `${label}: ${open.length} open${open.length ? ` [${open.map((p) => `${p.port}/${p.protocol}`).join(", ")}]` : ""}`;
  });
  return parts.join("; ");
}
