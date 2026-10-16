/**
 * External-tool resolver + executor (v0.32.0).
 *
 * Owns process spawning and the honest reading of results. Policy lives in
 * registry.ts and is pure; nothing here decides what may run — it runs an argv
 * it is handed and reports what came back.
 */

import { execFileSync } from "node:child_process";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { buildXToolArgv, type XRunOptions, type XToolSpec } from "./registry.js";

export interface XSpawnOpts {
  file: string;
  args: string[];
  cwd?: string;
  timeoutMs: number;
  signal?: AbortSignal;
  env?: NodeJS.ProcessEnv;
}

export interface XSpawnResult {
  stdout: string;
  stderr: string;
  code: number | null;
  timedOut: boolean;
}

export type XSpawnFn = (opts: XSpawnOpts) => Promise<XSpawnResult>;

export const realXSpawn: XSpawnFn = async (opts) =>
  new Promise<XSpawnResult>((resolve) => {
    const child = spawn(opts.file, opts.args, {
      cwd: opts.cwd,
      windowsHide: true,
      env: opts.env,
    });
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

/**
 * John ships CPU-specific binaries and no generic john.exe on Windows, so the
 * right one is chosen by asking the CPU rather than by guessing AVX2 and
 * failing on older hardware. An explicit env override always wins.
 */
const JOHN_VARIANTS = [
  "john-avx2-non-omp.exe",
  "john-avx-non-omp.exe",
  "john-sse41-non-omp.exe",
  "john-sse2-non-omp.exe",
  "john-xop-non-omp.exe",
];

export function resolveBinPath(spec: XToolSpec, env: NodeJS.ProcessEnv = process.env): string {
  const explicit = env[spec.envBin]?.trim();
  if (explicit) return explicit;
  const dir = spec.envDir ? env[spec.envDir]?.trim() : undefined;
  if (spec.id === "john") {
    const home = dir || "C:\\metasploit\\john";
    for (const v of JOHN_VARIANTS) {
      const p = join(home, "bin", v);
      if (existsSync(p)) return p;
    }
    return join(home, "bin", "john-avx-non-omp.exe");
  }
  // Neutral defaults, not a developer's home dir. The per-tool env vars
  // (REDTEAM_SQLMAP_DIR / REDTEAM_NIKTO_DIR) still override; this only stops
  // shipped code from silently pointing at C:\Users\<someone>\tools on a host
  // that is not that person's machine.
  if (spec.id === "sqlmap") return dir || "C:\\tools\\sqlmap";
  if (spec.id === "nikto") return dir || "C:\\tools\\nikto\\program";
  return spec.id;
}

export function binPresent(spec: XToolSpec, env: NodeJS.ProcessEnv = process.env): boolean {
  try {
    if (spec.id === "john") return existsSync(resolveBinPath(spec, env));
    if (spec.id === "sqlmap") return existsSync(join(resolveBinPath(spec, env), "sqlmap.py"));
    if (spec.id === "nikto") return existsSync(join(resolveBinPath(spec, env), "nikto.pl"));
    // ffuf / gobuster: an explicit env path must actually exist, otherwise the
    // binary is looked up on PATH. A set-but-nonexistent env var must not report
    // "present" and then fail with a confusing ENOENT at spawn time.
    const explicitBin = env[spec.envBin]?.trim();
    if (explicitBin) return existsSync(explicitBin);
    const cmd = process.platform === "win32" ? "where" : "which";
    execFileSync(cmd, [spec.id], { stdio: "ignore", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

export interface XExecResult {
  ok: boolean;
  tool: string;
  action: string;
  message: string;
  /** Structured findings when the tool's output is machine-readable. */
  findings?: XFinding[];
  binary?: string;
}

export interface XFinding {
  kind: string;
  target: string;
  detail: string;
}

/**
 * Pull ffuf's JSON records into findings. ffuf emits one JSON object per line
 * on stdout; anything that does not parse is skipped rather than throwing,
 * because a partial run must still report what it found.
 */
export function parseFfufJsonl(stdout: string, target: string): XFinding[] {
  const out: XFinding[] = [];
  for (const line of stdout.split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    try {
      const j = JSON.parse(t) as Record<string, unknown>;
      const status = typeof j["status"] === "number" ? j["status"] : 0;
      const url = typeof j["url"] === "string" ? j["url"] : target;
      const len = typeof j["length"] === "number" ? j["length"] : 0;
      out.push({ kind: "endpoint", target: url, detail: `HTTP ${status}, ${len} bytes` });
    } catch {
      /* a line that is not JSON is not a finding */
    }
  }
  return out;
}

/** gobuster's `-q` output is one path per line. */
export function parseGobusterText(stdout: string, target: string): XFinding[] {
  const out: XFinding[] = [];
  for (const line of stdout.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("=") || t.startsWith("[")) continue;
    out.push({ kind: "path", target, detail: t.slice(0, 200) });
  }
  return out;
}

export async function runXTool(
  spec: XToolSpec,
  opts: {
    action: "probe" | "run";
    target: string;
    profileId: string;
    wordlist?: string;
    rateLimit: number;
    timeoutS: number;
    signal?: AbortSignal;
    env?: NodeJS.ProcessEnv;
  },
  spawnFn: XSpawnFn = realXSpawn,
): Promise<XExecResult> {
  const env = opts.env ?? process.env;
  const bin = resolveBinPath(spec, env);

  if (opts.action === "probe") {
    return {
      ok: true,
      tool: spec.id,
      action: "probe",
      binary: bin,
      message:
        `${spec.id}: ${spec.purpose}\n` +
        `binary: ${bin}  (present: ${binPresent(spec, env)})\n` +
        `profiles:\n` +
        spec.profiles.map((p) => `  ${p.id.padEnd(12)} tier${p.minTier}+  ${p.description}`).join("\n"),
    };
  }

  // A target that begins with '-' can be read as a flag — for flag-style tools
  // (where it follows -u/-h) and for john's positional hash-file argument alike.
  // No legitimate URL, host, or hash-file path starts with '-', so refuse.
  if (opts.target.startsWith("-")) {
    return {
      ok: false,
      tool: spec.id,
      action: "run",
      binary: bin,
      message: `refused: target ${JSON.stringify(opts.target)} begins with '-' — a value must not be read as a flag.`,
    };
  }

  const cwd = spec.id === "sqlmap" || spec.id === "nikto" ? bin : undefined;
  const profile = spec.profiles.find((p) => p.id === opts.profileId) ?? spec.profiles[0]!;
  const argv = buildXToolArgv(spec, {
    bin,
    target: opts.target,
    profile,
    wordlist: opts.wordlist,
    timeoutS: opts.timeoutS,
  } as XRunOptions);

  // argv[0] of the built command is the interpreter for script tools (python,
  // perl) and the binary itself for the Go tools.
  const file = argv[0]!;
  const args = argv.slice(1);

  const r = await spawnFn({ file, args, cwd, timeoutMs: opts.timeoutS * 1000, signal: opts.signal, env });

  if (r.timedOut) {
    const partial = spec.jsonOutput ? parseFfufJsonl(r.stdout, opts.target) : [];
    return {
      ok: false,
      tool: spec.id,
      action: "run",
      binary: bin,
      findings: partial,
      message: `${spec.id} exceeded the ${opts.timeoutS}s ceiling and was killed. ${partial.length} finding(s) before the kill.`,
    };
  }
  // sqlmap and nikto exit non-zero on "nothing found", which is a RESULT, not a
  // failure — so the message distinguishes them rather than reporting an error.
  const findings =
    spec.id === "ffuf"
      ? parseFfufJsonl(r.stdout, opts.target)
      : spec.id === "gobuster"
        ? parseGobusterText(r.stdout, opts.target)
        : [];

  const head = r.stdout.trim().split("\n").slice(0, 40).join("\n");
  const tail = r.stderr.trim().split("\n").slice(0, 6).join("\n");
  // sqlmap exits 0 on "clean" and 1 on "injectable parameter found" — both are a
  // completed run whose result we report, never a failure. The other tools use 0
  // for success. Collapsing everything to `code === 0` inverted sqlmap's result.
  const ok = r.code === 0 || (spec.id === "sqlmap" && r.code === 1);
  return {
    ok,
    tool: spec.id,
    action: "run",
    binary: bin,
    findings,
    message:
      `${spec.id} ${profile.id} on ${opts.target} exited ${r.code}. ` +
      `${findings.length ? findings.length + " finding(s)." : ""}\n` +
      `Command: ${file} ${args.join(" ")}\n` +
      (head ? `Output:\n${head}\n` : "") +
      (tail ? `Stderr:\n${tail}` : ""),
  };
}
