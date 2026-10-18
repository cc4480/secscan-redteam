/**
 * Toolchain resolution (v0.37.0) - ONE place that decides where an external
 * binary comes from, so the precedence cannot drift between the nmap, nuclei
 * and xtool bridges.
 *
 * Order, most specific first:
 *   1. the tool's explicit env override (REDTEAM_NMAP_BIN, REDTEAM_FFUF_BIN, ...).
 *      The operator named a binary, so that value wins even when the path is
 *      missing; the resolver still reports `exists: false` so a caller says
 *      "missing" instead of silently running a binary the operator did not name.
 *   2. <REDTEAM_TOOLS_DIR>/<subdir>/<exe> - the payload the desktop app bundles
 *      (the first candidate that actually exists).
 *   3. the neutral default: the bare command name for PATH-resolved tools, or
 *      the tool's historical directory for the script tools (sqlmap/nikto) and
 *      John's Metasploit bundle.
 *
 * Pure and synchronous: it reads the environment and stats paths, never spawns
 * a process. That is what makes it unit-testable, and it lets readiness report
 * not just WHETHER something was found but WHERE it came from.
 *
 * This file owns no policy. Handing the resolved path to spawn, and deciding
 * whether an engagement may run without it, stay with the callers.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";

/** The environment variable the desktop supervisor exports for the payload. */
export const TOOLS_DIR_ENV = "REDTEAM_TOOLS_DIR";

export type ExternalToolId = "nmap" | "nuclei" | "ffuf" | "gobuster" | "john" | "sqlmap" | "nikto";

/** Where a resolved binary came from. */
export type ResolveSource = "explicit" | "tools-dir" | "path";

/**
 * John ships CPU-specific binaries and no generic john.exe on Windows, so the
 * most capable variant that exists wins. A machine without AVX2 must not
 * silently fail because the runner guessed AVX2 and the load error looked like
 * "the tool is broken".
 */
export const JOHN_VARIANTS = [
  "john-avx2-non-omp.exe",
  "john-avx-non-omp.exe",
  "john-sse41-non-omp.exe",
  "john-sse2-non-omp.exe",
  "john-xop-non-omp.exe",
];

export interface ResolveOptions {
  /** Environment to read; injected by tests and by callers with a captured env. */
  env?: NodeJS.ProcessEnv;
  /** Override the env var naming the binary (defaults to the tool table). */
  envBin?: string;
  /** Override the env var naming the tool directory (defaults to the tool table). */
  envDir?: string;
  /** Injectable existence check, so tests need no real files where practical. */
  exists?: (path: string) => boolean;
  /** Platform for the executable-suffix rule; injected by tests. */
  platform?: NodeJS.Platform;
}

export interface ResolvedBinary {
  /** Executable path, or the directory a script tool (sqlmap/nikto) runs from. */
  path: string;
  source: ResolveSource;
  /** The env var that supplied an explicit value, when source is "explicit". */
  envVar?: string;
  /** True when `path` is a directory the tool runs from rather than an executable. */
  directory: boolean;
  /** Whether `path` (or, for a directory, its known file) exists right now. */
  exists: boolean;
}

interface ToolEntry {
  envBin: string;
  envDir?: string;
  /** Subdirectory of envDir that holds the executable (John: "bin"). */
  envDirSubdir?: string;
  /** The resolved value is a directory the tool runs from. */
  directory: boolean;
  /** Location inside <REDTEAM_TOOLS_DIR>: executable directory, or tool directory. */
  bundled: string;
  /** Executable file names to try in order (file-shaped tools only). */
  exeNames: string[];
  /** Directory-shaped tools: the file that must exist inside the directory. */
  marker?: string;
  /** Neutral historical location used only when nothing above is configured. */
  legacy?: string;
  /** Subdirectory of the legacy location that holds the executable. */
  legacySubdir?: string;
}

/**
 * The tool table. `bundled` is relative to REDTEAM_TOOLS_DIR with forward
 * slashes (join() converts) and matches the payload layout in ZERO_INSTALL_PLAN:
 *   nmap/nmap.exe, nuclei/nuclei.exe, ffuf/ffuf.exe, gobuster/gobuster.exe,
 *   john/bin/john-*.exe, sqlmap/sqlmap.py, nikto/program/nikto.pl
 */
const TOOLS: Record<ExternalToolId, ToolEntry> = {
  nmap: { envBin: "REDTEAM_NMAP_BIN", directory: false, bundled: "nmap", exeNames: ["nmap"] },
  nuclei: { envBin: "REDTEAM_NUCLEI_BIN", directory: false, bundled: "nuclei", exeNames: ["nuclei"] },
  ffuf: { envBin: "REDTEAM_FFUF_BIN", directory: false, bundled: "ffuf", exeNames: ["ffuf"] },
  gobuster: { envBin: "REDTEAM_GOBUSTER_BIN", directory: false, bundled: "gobuster", exeNames: ["gobuster"] },
  john: {
    envBin: "REDTEAM_JOHN_BIN",
    envDir: "REDTEAM_JOHN_HOME",
    envDirSubdir: "bin",
    directory: false,
    bundled: "john/bin",
    exeNames: JOHN_VARIANTS,
    legacy: "C:\\metasploit\\john",
    legacySubdir: "bin",
  },
  sqlmap: {
    envBin: "REDTEAM_SQLMAP_BIN",
    envDir: "REDTEAM_SQLMAP_DIR",
    directory: true,
    bundled: "sqlmap",
    exeNames: [],
    marker: "sqlmap.py",
    legacy: "C:\\tools\\sqlmap",
  },
  nikto: {
    envBin: "REDTEAM_NIKTO_BIN",
    envDir: "REDTEAM_NIKTO_DIR",
    directory: true,
    bundled: "nikto/program",
    exeNames: [],
    marker: "nikto.pl",
    legacy: "C:\\tools\\nikto\\program",
  },
};

/** The env vars that name one tool's binary and (optionally) its directory. */
export function toolEnvNames(tool: ExternalToolId): { envBin: string; envDir?: string } {
  const entry = TOOLS[tool];
  return entry.envDir ? { envBin: entry.envBin, envDir: entry.envDir } : { envBin: entry.envBin };
}

/** The bundled tools directory, when the supervisor or operator provided one. */
export function toolsDir(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const raw = (env[TOOLS_DIR_ENV] ?? "").trim();
  return raw || undefined;
}

/** Human label for a resolved source, used by readiness and probe output. */
export function describeSource(resolved: ResolvedBinary): string {
  if (resolved.source === "explicit") return `explicit${resolved.envVar ? ` ${resolved.envVar}` : ""}`;
  if (resolved.source === "tools-dir") return `bundled tools directory (${TOOLS_DIR_ENV})`;
  return "system default / PATH";
}

/** Add or strip the Windows executable suffix for the platform being resolved. */
export function platformExe(name: string, platform: NodeJS.Platform = process.platform): string {
  const hasExe = /\.exe$/i.test(name);
  if (platform === "win32") return hasExe ? name : `${name}.exe`;
  return hasExe ? name.slice(0, -4) : name;
}

function markerPresent(dir: string, entry: ToolEntry, exists: (p: string) => boolean): boolean {
  return entry.marker ? exists(join(dir, entry.marker)) : exists(dir);
}

function firstExisting(
  dir: string,
  names: readonly string[],
  platform: NodeJS.Platform,
  exists: (p: string) => boolean,
): string | undefined {
  for (const name of names) {
    const candidate = join(dir, platformExe(name, platform));
    if (exists(candidate)) return candidate;
  }
  return undefined;
}

/**
 * Resolve one external tool. Never throws: a missing tool resolves to a path
 * with `exists: false` plus the source that produced it, which is exactly what
 * a readiness report needs to show the operator.
 */
export function resolveExternalBinary(tool: ExternalToolId, opts: ResolveOptions = {}): ResolvedBinary {
  const entry = TOOLS[tool];
  const env = opts.env ?? process.env;
  const exists = opts.exists ?? existsSync;
  const platform = opts.platform ?? process.platform;
  const envBinName = opts.envBin ?? entry.envBin;
  const envDirName = opts.envDir ?? entry.envDir;

  // 1. The operator's explicit value. It wins even when missing (see header):
  // a silently different binary would make the report lie about what ran.
  const explicitBin = (env[envBinName] ?? "").trim();
  if (explicitBin) {
    return {
      path: explicitBin,
      source: "explicit",
      envVar: envBinName,
      directory: entry.directory,
      exists: entry.directory ? markerPresent(explicitBin, entry, exists) : exists(explicitBin),
    };
  }
  const explicitDir = envDirName ? (env[envDirName] ?? "").trim() : "";
  if (explicitDir) {
    if (entry.directory) {
      return {
        path: explicitDir,
        source: "explicit",
        envVar: envDirName,
        directory: true,
        exists: markerPresent(explicitDir, entry, exists),
      };
    }
    const exeDir = entry.envDirSubdir ? join(explicitDir, entry.envDirSubdir) : explicitDir;
    const hit = firstExisting(exeDir, entry.exeNames, platform, exists);
    // John's historical default: name the most capable variant even when it is
    // absent, so the report points at the file the operator is expected to add.
    const path = hit ?? join(exeDir, platformExe(entry.exeNames[0]!, platform));
    return { path, source: "explicit", envVar: envDirName, directory: false, exists: Boolean(hit) };
  }

  // 2. The bundled payload. A candidate counts only when it exists: a partial
  // tools tree must fall through rather than hand spawn a path that is not there.
  const dir = toolsDir(env);
  if (dir) {
    const bundledDir = join(dir, ...entry.bundled.split("/"));
    if (entry.directory) {
      if (markerPresent(bundledDir, entry, exists)) {
        return { path: bundledDir, source: "tools-dir", directory: true, exists: true };
      }
    } else {
      const hit = firstExisting(bundledDir, entry.exeNames, platform, exists);
      if (hit) return { path: hit, source: "tools-dir", directory: false, exists: true };
    }
  }

  // 3. The neutral default. Directory-shaped tools keep their historical path (a
  // bare "sqlmap" would be handed to spawn as a cwd and fail confusingly);
  // everything else becomes the bare command name the OS resolves on PATH.
  if (entry.legacy) {
    const legacyDir = entry.legacySubdir ? join(entry.legacy, entry.legacySubdir) : entry.legacy;
    if (entry.directory) {
      return { path: legacyDir, source: "path", directory: true, exists: markerPresent(legacyDir, entry, exists) };
    }
    const hit = firstExisting(legacyDir, entry.exeNames, platform, exists);
    if (hit) return { path: hit, source: "path", directory: false, exists: true };
  }
  return { path: tool, source: "path", directory: false, exists: false };
}
