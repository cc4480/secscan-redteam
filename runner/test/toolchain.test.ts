/**
 * Toolchain resolver tests (v0.37.0, Phase A of the zero-install plan).
 *
 * What is pinned here is the ORDER and the HONESTY of binary resolution, because
 * every bridge (nmap, nuclei, ffuf, gobuster, john, sqlmap, nikto) now shares one
 * resolver and a drift there would show up as "the tool is broken" mid-engagement:
 *
 *   - explicit env > bundled REDTEAM_TOOLS_DIR payload > PATH, everywhere
 *   - a set-but-missing explicit value stays authoritative and is reported as
 *     not-found instead of silently running a different binary
 *   - a partial bundled tree falls through to PATH rather than handing spawn a
 *     path that is not there
 *   - john's CPU-specific variants are chosen most-capable-first
 *   - sqlmap/nikto are DIRECTORIES and only count when their known file is inside
 *   - the .exe suffix is a platform rule, not a hardcoded filename
 */
import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
  JOHN_VARIANTS,
  TOOLS_DIR_ENV,
  describeSource,
  platformExe,
  resolveExternalBinary,
  toolEnvNames,
  toolsDir,
  type ResolvedBinary,
} from "../src/toolchain.js";
import { XTOOLS, findXTool } from "../src/xtool/registry.js";
import { binPresent, resolveBinPath } from "../src/xtool/executor.js";
import { NMAP_ENV_BIN } from "../src/nmap/policy.js";
import { NUCLEI_ENV_BIN } from "../src/nuclei/policy.js";
import { resolveNmapCommand } from "../src/nmap/prereq.js";
import { resolveNucleiCommand } from "../src/nuclei/prereq.js";

/** The suffix a REAL payload is expected to have on this test host. */
const EXE = process.platform === "win32" ? ".exe" : "";
const roots: string[] = [];

/** Create a throwaway tools tree. Entries use forward slashes. */
function tree(files: readonly string[]): string {
  const root = mkdtempSync(join(tmpdir(), "rt-toolchain-"));
  roots.push(root);
  for (const rel of files) {
    const full = join(root, ...rel.split("/"));
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, "");
  }
  return root;
}

function pick(resolved: ResolvedBinary): { path: string; source: string } {
  return { path: resolved.path, source: resolved.source };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("toolchain resolver: precedence", () => {
  it("explicit env wins over the bundled payload", () => {
    const root = tree([`nmap/nmap${EXE}`, `custom/nmap${EXE}`]);
    const explicit = join(root, "custom", `nmap${EXE}`);
    const r = resolveExternalBinary("nmap", { env: { REDTEAM_TOOLS_DIR: root, REDTEAM_NMAP_BIN: explicit } });
    assert.equal(r.path, explicit);
    assert.equal(r.source, "explicit");
    assert.equal(r.envVar, "REDTEAM_NMAP_BIN");
    assert.equal(r.exists, true);
  });

  it("the bundled tools directory wins over PATH when no override is set", () => {
    const root = tree([`nmap/nmap${EXE}`]);
    const r = resolveExternalBinary("nmap", { env: { REDTEAM_TOOLS_DIR: root } });
    assert.equal(r.path, join(root, "nmap", `nmap${EXE}`));
    assert.equal(r.source, "tools-dir");
    assert.equal(r.exists, true);
    assert.equal(describeSource(r), `bundled tools directory (${TOOLS_DIR_ENV})`);
  });

  it("keeps a set-but-missing explicit value authoritative and reports it not-found", () => {
    const root = tree([`nmap/nmap${EXE}`]);
    const r = resolveExternalBinary("nmap", {
      env: { REDTEAM_TOOLS_DIR: root, REDTEAM_NMAP_BIN: join(root, "gone", `nmap${EXE}`) },
    });
    // Never silently swap in the bundled copy: the report must name what was
    // asked for and say it is missing, not claim a different binary ran.
    assert.equal(r.source, "explicit");
    assert.equal(r.exists, false);
  });

  it("falls back to the bare command name when the tools directory is empty or absent", () => {
    const empty = tree([]);
    assert.deepEqual(pick(resolveExternalBinary("nmap", { env: { REDTEAM_TOOLS_DIR: empty } })), {
      path: "nmap",
      source: "path",
    });
    assert.deepEqual(
      pick(resolveExternalBinary("ffuf", { env: { REDTEAM_TOOLS_DIR: "/no/such/tools/dir" }, exists: () => false })),
      { path: "ffuf", source: "path" },
    );
    // No REDTEAM_TOOLS_DIR at all: the pre-toolchain resolution, unchanged.
    assert.deepEqual(pick(resolveExternalBinary("nuclei", { env: {}, exists: () => false })), {
      path: "nuclei",
      source: "path",
    });
  });

  it("accepts an injected existence check, so tests need no real files", () => {
    const env = { REDTEAM_TOOLS_DIR: "/payloads" };
    const known = new Set([join("/payloads", "nuclei", platformExe("nuclei", "win32"))]);
    const win = resolveExternalBinary("nuclei", { env, platform: "win32", exists: (p) => known.has(p) });
    assert.equal(win.source, "tools-dir");
    assert.equal(win.path, join("/payloads", "nuclei", "nuclei.exe"));
    const linux = resolveExternalBinary("nuclei", { env, platform: "linux", exists: (p) => known.has(p) });
    assert.equal(linux.source, "path", "only the Windows payload exists, so POSIX falls through");
  });

  it("exposes the tools directory from the environment", () => {
    assert.equal(toolsDir({ REDTEAM_TOOLS_DIR: " /opt/tools " } as NodeJS.ProcessEnv), "/opt/tools");
    assert.equal(toolsDir({} as NodeJS.ProcessEnv), undefined);
    assert.equal(toolsDir({ REDTEAM_TOOLS_DIR: "   " } as NodeJS.ProcessEnv), undefined);
    assert.equal(TOOLS_DIR_ENV, "REDTEAM_TOOLS_DIR");
  });
});

describe("toolchain resolver: platform executable suffix", () => {
  it("looks for <exe>.exe on Windows and the bare name on POSIX", () => {
    const root = tree(["nmap/nmap.exe"]); // always create the Windows-shaped payload
    const win = resolveExternalBinary("nmap", { env: { REDTEAM_TOOLS_DIR: root }, platform: "win32" });
    assert.equal(win.source, "tools-dir");
    assert.equal(win.path, join(root, "nmap", "nmap.exe"));
    const posix = resolveExternalBinary("nmap", { env: { REDTEAM_TOOLS_DIR: root }, platform: "linux" });
    assert.equal(posix.source, "path");
    assert.equal(posix.path, "nmap");
    assert.equal(platformExe("john-avx2-non-omp.exe", "linux"), "john-avx2-non-omp");
    assert.equal(platformExe("nmap", "win32"), "nmap.exe");
  });
});

describe("toolchain resolver: john variants", () => {
  it("picks the most capable john variant that exists", () => {
    const root = tree([`john/bin/john-avx2-non-omp${EXE}`, `john/bin/john-sse2-non-omp${EXE}`]);
    const r = resolveExternalBinary("john", { env: { REDTEAM_TOOLS_DIR: root } });
    assert.equal(r.path, join(root, "john", "bin", `john-avx2-non-omp${EXE}`));
    assert.equal(r.source, "tools-dir");
    assert.equal(JOHN_VARIANTS[0], "john-avx2-non-omp.exe");
  });

  it("falls back to a slower john variant when the faster ones are absent", () => {
    const root = tree([`john/bin/john-sse2-non-omp${EXE}`]);
    const r = resolveExternalBinary("john", { env: { REDTEAM_TOOLS_DIR: root } });
    assert.equal(r.path, join(root, "john", "bin", `john-sse2-non-omp${EXE}`));
  });

  it("honours REDTEAM_JOHN_HOME, then falls back to the bare name", () => {
    const home = tree([`bin/john-avx-non-omp${EXE}`]);
    const explicit = resolveExternalBinary("john", { env: { REDTEAM_JOHN_HOME: home } });
    assert.equal(explicit.path, join(home, "bin", `john-avx-non-omp${EXE}`));
    assert.equal(explicit.source, "explicit");
    assert.equal(explicit.exists, true);
    const none = resolveExternalBinary("john", { env: {}, exists: () => false });
    assert.equal(none.path, "john");
    assert.equal(none.source, "path");
  });
});

describe("toolchain resolver: script tools are directories", () => {
  it("resolves sqlmap and nikto as their directories when the known file is inside", () => {
    const root = tree(["sqlmap/sqlmap.py", "nikto/program/nikto.pl"]);
    const env = { REDTEAM_TOOLS_DIR: root };
    const sql = resolveExternalBinary("sqlmap", { env });
    assert.equal(sql.path, join(root, "sqlmap"));
    assert.equal(sql.directory, true);
    assert.equal(sql.source, "tools-dir");
    assert.equal(sql.exists, true);
    const nik = resolveExternalBinary("nikto", { env });
    assert.equal(nik.path, join(root, "nikto", "program"));
    assert.equal(nik.directory, true);
    assert.equal(nik.source, "tools-dir");
  });

  it("requires the known file inside the directory", () => {
    const root = tree(["sqlmap/README.md"]);
    const miss = resolveExternalBinary("sqlmap", { env: { REDTEAM_TOOLS_DIR: root } });
    // A directory without sqlmap.py is not the tool: fall through to the
    // documented neutral default, which is also reported as not found.
    assert.equal(miss.source, "path");
    assert.equal(miss.exists, false);
    assert.equal(miss.path, "C:\\tools\\sqlmap");
    const explicit = resolveExternalBinary("nikto", { env: { REDTEAM_NIKTO_DIR: join(root, "sqlmap") } });
    assert.equal(explicit.source, "explicit");
    assert.equal(explicit.directory, true);
    assert.equal(explicit.exists, false, "a directory without nikto.pl is missing, not accepted");
  });
});

describe("toolchain resolver: every bridge uses the same order", () => {
  it("routes the xtool bridges through the shared resolver", () => {
    const root = tree([`ffuf/ffuf${EXE}`, `gobuster/gobuster${EXE}`]);
    const ffuf = findXTool("ffuf")!;
    const env = { REDTEAM_TOOLS_DIR: root };
    assert.equal(resolveBinPath(ffuf, env), join(root, "ffuf", `ffuf${EXE}`));
    assert.equal(binPresent(ffuf, env), true);
    // A stale explicit value wins for the path but must not claim presence.
    const stale = { REDTEAM_TOOLS_DIR: root, REDTEAM_FFUF_BIN: join(root, "gone", `ffuf${EXE}`) };
    assert.equal(resolveBinPath(ffuf, stale), join(root, "gone", `ffuf${EXE}`));
    assert.equal(binPresent(ffuf, stale), false);
  });

  it("makes the nmap and nuclei probes report the bundled source without spawning", () => {
    const root = tree([`nmap/nmap${EXE}`, `nuclei/nuclei${EXE}`]);
    const env = { REDTEAM_TOOLS_DIR: root };
    assert.equal(resolveNmapCommand(env).source, "tools-dir");
    assert.equal(resolveNucleiCommand(env).source, "tools-dir");
  });

  it("keeps the tool table's env names in sync with the bridge specs and policies", () => {
    for (const spec of XTOOLS) {
      const names = toolEnvNames(spec.id);
      assert.equal(names.envBin, spec.envBin, `${spec.id} envBin`);
      assert.equal(names.envDir, spec.envDir, `${spec.id} envDir`);
    }
    assert.equal(toolEnvNames("nmap").envBin, NMAP_ENV_BIN);
    assert.equal(toolEnvNames("nuclei").envBin, NUCLEI_ENV_BIN);
  });
});
