# DSH Desktop integration — build status and remaining work

Working notes for building a Windows desktop app that **is** secscan-redteam:
the DSH shell with the red-team plugin and SecScan MCP wiring mounted by default.

Last updated 2026-10-15. Everything below was measured on this machine, not inferred.

---

## Where it stands

| Stage | State |
|---|---|
| Plugin packaging (installable off-registry) | ✅ done — self-contained tarball, 29.9 KB |
| `@secscan/redteam-desktop-bundle` | ✅ done — mounts both rows as one layer |
| Conformance to the DSH build convention | ✅ done |
| Injection into the profile template | ✅ done — one line in `PROFILE_TEMPLATES.web` |
| Monorepo build | ✅ **passes** — `recorded 263 client artifact(s)`, exit 0 |
| Profile composition | ✅ **verified** — composed tree contains `mcp-secscan` + `secscan-redteam` |
| Desktop packaging (`--dir`) | ✅ **app produced** — `win-unpacked/`, 1,001.7 MB |
| Integration baked into the built app | ✅ **verified from the artifact** |
| NSIS installer `.exe` | ❌ blocked on MSVC (window-frame.dll) |

### The app is built, and the red team is in it

`pnpm --dir apps/desktop run package:win:x64:dir:unsigned` now produces:

```
unsigned-artifacts/win-unpacked/
  DeepSeek Harness.exe          233.1 MB
  resources/app.asar            103.2 MB
  resources/app.asar.unpacked/
  resources/runtime/
  (1,001.7 MB total)
```

Verified **from the built artifact**, not from source:

- `targets/win-x64/dsh/node_modules/@secscan/` contains all four packages
  (`redteam-auth-gate`, `redteam-llm-router`, `redteam-harness-plugin`,
  `redteam-desktop-bundle`).
- `resources/app.asar` contains the strings `redteam-desktop-bundle` and
  `redteam-harness-plugin`.
- The **built** `@deepseek-ai/dsh-app-boot/lib/index.js` still names the bundle at line 526 —
  the profile template survived packaging.
- Running the **shipped** composer end to end on an isolated `DSH_HOME`:

  ```
  node <targets>/win-x64/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js \
       --profile verify --from-default-profile web --dump-config
  -> exit 0, 46,326 bytes, containing:
       mcp-secscan            PRESENT
       secscan-redteam        PRESENT
       secscan.us/api/mcp     PRESENT
       redteam-harness-plugin PRESENT
  ```

  A profile created by the installed app therefore mounts the SecScan MCP client and the
  authorization gate with no manual setup — which is the objective.

### Known gap: product branding

`productName` in `electron-builder-config.mjs` is still `DeepSeek Harness`, so the built app
is named that and the exe is `DeepSeek Harness.exe`. `DSH_DESKTOP_APP_ID` was set to
`com.secscan.redteam` in `.env.windows`, but the display name was not changed. A real
secscan-redteam product needs `productName` (and the icon) changed too.

### Third local deviation: the packaged-runtime smoke test

Two failures seen in the packaging sequence are the **same known Office → PDF defect the
dsh-desktop release notes already document** for this build:

```
LibreOffice helper returned an invalid response (exit 3221225781)
```

`3221225781` is `0xC0000135`, `STATUS_DLL_NOT_FOUND` — the LibreOffice helper cannot load a
dependent DLL. It aborts `prepare:dsh` and then the post-build smoke.

- `DSH_LOCAL_DEFER_RUNTIME_SMOKE=1` passes `--defer-runtime-smoke` to `prepare:dsh`, an
  option upstream already uses for signed builds (`package-target.ts:488`).

The post-build `smoke-packaged-runtime.ts` still fails on the same defect. That is why the
run exits non-zero **after** `win-unpacked` has been written. Upstream's own note applies
here: *"the packaging run reports failure when the packaged-runtime smoke test fails, but
the installer is still produced"* — but electron-builder never reaches the NSIS step,
because this failure is raised as a hard error before it.

### The remaining fix for blocker 2

`package-target.ts` now packs the four vendored packages into `buildPaths.packedDsh`
immediately after the `release:pack --family dsh` step, because that step `rmSync`s its
destination and the family deliberately excludes private / non-`@deepseek-ai` manifests.
This is the change that unblocked `prepare:packages`.


---

## Blocker 1 — MSVC toolchain (environmental, needs Administrator)

`pnpm --dir apps/desktop run package:win:x64:unsigned` fails immediately:

```
vswhere: spawn %ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe ENOENT
```

`apps/desktop/scripts/desktop-toolchain-preflight.ts` requires Visual Studio with
`Microsoft.VisualStudio.Component.VC.Tools.x86.x64`, because
`apps/desktop/scripts/prepare-windows-installer.ps1` compiles `installer/window-frame.cpp`
into an x86 DWM helper (`window-frame.dll`) that the NSIS installer's custom window chrome
embeds. It links `dwmapi.lib`, `gdiplus.lib`, `comctl32.lib`, `user32.lib` — Windows SDK
libraries.

Checked, absent: `cl`, `clang`, `clang++`, `gcc`, `g++`, `clang-cl`, any Visual Studio
directory, `C:\Program Files (x86)\Windows Kits\10`, LLVM, MSYS2/MinGW.

The preflight runs **unconditionally** (`package-target.ts`, the `toolchain` step), so
`--dir` and `--unsigned` do not bypass it.

**Remedy:** install Visual Studio Build Tools 2022 with *Desktop development with C++*,
then re-run. This needs Administrator.

### Local deviation used to get past it

Two env-gated escapes were added so the rest of the pipeline could be exercised here.
**Both must be absent for a real installer build** — with them set, the installer would
ship without its window-frame helper.

- `DSH_LOCAL_SKIP_MSVC_PREFLIGHT=1` — `desktop-toolchain-preflight.ts` reports the
  failures and returns instead of throwing.
- `DSH_LOCAL_SKIP_INSTALLER_UI=1` — `electron-builder-config.mjs` `beforeBuild` returns
  before invoking `prepare-windows-installer.ps1`.

These are marked `LOCAL BUILD DEVIATION (not upstream)` in the code.

---

## Blocker 2 — the redteam packages are excluded from the packed set (real, fixable)

With the preflight escaped, the build proceeds much further: it downloads Electron, packs
the Landlock native package, runs `prepare:runtime` ("Office runtime versions and document
round trips passed"), then fails:

```
Error: desktop package set: @deepseek-ai/dsh requires unpacked package @secscan/redteam-desktop-bundle
    at visit (prepare-package-set.ts:75)
```

**Cause.** `prepare-package-set.ts` builds the desktop package closure by walking the
tarballs produced by `scripts/release/pack.ts`. That pack step takes its member list from
`scripts/release/families.ts` → `DshFamily`:

```ts
readonly patterns = ['packages/*/*/package.json', 'apps/*/package.json']
```

`packages/redteam/*` **does** match that glob — but two filters then drop the packages
(`families.ts:131`):

```ts
if (manifest.private === true) continue
...
if (!name.startsWith('@deepseek-ai/')) throw new Error(`${normalized} must name an @deepseek-ai package`)
```

The release family is **`@deepseek-ai`-only and public-only**, which is correct for an npm
publish set — but the desktop packaging reuses that same family, so anything not destined
for npm is invisible to it.

Measured: 320 tarballs packed, **zero** redteam.

Then `selectDesktopPackageClosure` walks `dependencies` + `peerDependencies` of each packed
package, and throws on any dependency that is a workspace package but not in the packed set.

### Fix, and why it is not a one-liner

The packages must reach the desktop package set **without** entering the npm publish set.
Options, in order of soundness:

1. **Add a desktop-scoped packing path.** Pack the redteam workspace packages into their
   own directory during `package-target.ts` and include that directory in
   `prepareDesktopPackageSet`'s `inputs` (its `defaultInputs` are
   `[packedDsh, packedVendor, packedLandlock]`; `--from` already allows extra sources).
   This keeps the publish family untouched.
2. **Add a dedicated non-publishing family** to `families.ts` whose patterns select
   `packages/redteam/*` and which skips the `@deepseek-ai` name assertion.
3. Renaming the packages under `@deepseek-ai/` and dropping `private: true` — **rejected**:
   it would put secscan packages into DeepSeek's public publish scope.

Option 1 is the smallest change that is also honest about intent.

### Why dropping tarballs into `packed/dsh` does not work

Tried it: packed the four redteam packages into
`apps/desktop/.desktop-build/targets/win-x64/packed/dsh/` (314 tarballs, up from 310,
`workspace:*` correctly rewritten to `0.2.0` by `pnpm pack`). The next run failed at the
**same** line, because `scripts/release/pack.ts` starts with:

```ts
rmSync(destination, { recursive: true, force: true })
mkdirSync(destination, { recursive: true })
```

The `release:pack` step therefore wipes `packed/dsh` and repacks only its family members,
discarding anything placed there beforehand. The redteam packages must be packed **after**
that step and **before** `prepare:packages`, or made members of the family that packs it.

Concretely, the fix belongs in `package-target.ts`, between the `release:pack` step and the
`prepare:packages` step: run `pnpm --dir packages/redteam/<pkg> pack --pack-destination
buildPaths.packedDsh` for each of the four packages, so they are present when
`selectDesktopPackageClosure` builds its map.


---

## What is proven to work

```
pnpm build
  -> exit 0, "recorded 263 client artifact(s) with 4 public value(s)"

node apps/cli/lib/bin.js --profile <x> --from-default-profile web --dump-config
  -> composed tree contains:
       - id: mcp-secscan      name: '@deepseek-ai/dsh-mcp-client'
                              serverName secscan, streamable-http,
                              https://secscan.us/api/mcp
       - id: secscan-redteam  name: '@secscan/redteam-harness-plugin'
```

That second command is the objective's core: a profile created from the shipped `web`
template — which is what `apps/desktop/src/project-manager.ts` uses, since
`const WEB_PROFILE = PROFILE_TEMPLATES.web` and the profile directory is named `desktop` —
mounts the red team with no manual setup.

**Existing profiles are unaffected.** The template applies when a profile is *initialised*;
a `desktop` profile that already exists keeps its own bundle list.

---

## Build prerequisites for whoever finishes this

- Windows x64
- **Visual Studio Build Tools 2022 + "Desktop development with C++"** (Administrator)
- Node `^22.19 || >=24`; this ran on `v26.7.0`
- pnpm `11.7.0` — the pinned commit's `packageManager`. The installed DSH bundles exactly
  this at `%LOCALAPPDATA%\..\DeepSeek Harness Windows\resources\runtime\pnpm\bin\pnpm.cjs`.
  A shim is needed because the bundled pnpm ships no `.cmd` wrapper, so the build's internal
  `pnpm --filter ... run <script>` calls fail with *"'pnpm' is not recognized"*:

  ```cmd
  @echo off
  node "C:\Users\Cho-zen\DeepSeek Harness Windows\resources\runtime\pnpm\bin\pnpm.cjs" %*
  ```

  Put it on PATH before building.
- Roughly: 2.2 GB for the checkout + node_modules, plus Electron and the prepared runtimes.

## Reproducing the build

```powershell
$env:PATH = "C:\Users\Cho-zen\dsh-pnpm-shim;$env:PATH"
cd C:\Users\Cho-zen\deepseek-harness-src

# one-time: apply the integration
git apply C:\Users\Cho-zen\secscan-redteam\dsh-desktop-integration.patch
# copy the packages into packages/redteam/ and the conformed configs from
# C:\Users\Cho-zen\secscan-redteam\dsh-desktop-package-configs\

pnpm install
pnpm build

# installer (requires the MSVC toolchain):
pnpm --dir apps/desktop run package:win:x64:unsigned
```

---

## Traps hit while doing this, recorded so they are not repeated

1. **`tsconfig.base.json` is JSONC and fragile.** A missing comma after the last generated
   path alias makes `extends` fail *silently for every package*, which surfaces as 267
   `TS6306 must have composite: true` errors that look unrelated to the edit. Verify with a
   parse after editing, and remember the last alias in a block needs no trailing comma.
2. **A broken base makes `tsc` emit into `src/`.** 420 `.js`/`.d.ts` files appeared beside
   sources across the repo. `.gitignore` covers `lib/` but not `src/**/*.js`, so they would
   be committed. Cleaning and rebuilding produced zero, confirming the cause.
3. **Vendored devDependencies can break the host's own build.** Carrying
   `@types/node ^26.6.3` into the workspace installed 26.6.5 beside the repo's `^22.20.0`
   and DSH's own scripts failed with `TS2339: Property 'on' does not exist on type
   'ChildProcess...'`. Drop them; the workspace provides the toolchain.
4. **Path aliases alone are not enough.** With `paths` mapping to source and no project
   `references`, TS inlines the imported project's files into the importing program and
   fails their `rootDir` / listing checks.
5. **Run the packaging through `pnpm run`, not `npx`.** `package-target.ts` reads
   `npm_execpath` and refuses otherwise; under `npx`, nested calls resolve to npm, which
   swallows `--family` / `--out` as its own config and the pack step dies with
   `ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL`.

---

## Round 4 findings

### The installer path now reaches NSIS, and fails on exactly one thing

With the three escapes and the cache fix below, the installer target runs to completion of
everything except the NSIS step:

```
Error: Command failed: powershell.exe ... prepare-windows-installer.ps1
  Windows installer preparation requires Visual Studio C++ Build Tools and a Windows SDK.
  At prepare-windows-installer.ps1:12
```

That is the **only** remaining obstacle. Confirmed here that no workaround exists: no
installer artifact is present on this machine to extract a prebuilt `window-frame.dll` from,
the DLL is not anywhere on disk, and 7-Zip is not installed to unpack one anyway.

### A corrupt download-cache entry, and how to spot it

`prepare:runtime` failed reproducibly with:

```
primary runtime download: checksum mismatch for .../openpyxl-3.1.5-py2.py3-none-any.whl
```

Not a network fault. The file downloads correctly and matches `lock.json` exactly:

```
lock.json expects   5282c12b107bffeef825f4617dc029afaf41d0ea60823bbb665ef3079dc79de2
a fresh download    5282c12b107bffeef825f4617dc029afaf41d0ea60823bbb665ef3079dc79de2
```

But the cache is content-addressed by expected hash, and one entry did not hash to its own
name:

```
apps/desktop/.desktop-build/downloads/5282c12b107b...   size 250,910 (correct)
    actual sha256  4abf2d1530473ff0ccb6b70096c17ffa9b62b97139789f692e06c930e420dc68
    name says      5282c12b107bffeef825f4617dc029afaf41d0ea60823bbb665ef3079dc79de2
```

Same length, valid ZIP header (`50 4B 03 04`), wrong content. It was the only one of 15
entries that failed to hash to its own filename. Deleting that single file fixed the build.

**To check the whole cache for this class of corruption:**

```powershell
Get-ChildItem "$src\apps\desktop\.desktop-build\downloads" -File | ForEach-Object {
  [pscustomobject]@{ Entry = $_.Name.Substring(0,12)
                     Valid = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() -eq $_.Name }
} | Where-Object { -not $_.Valid }
```

Note `prepare:runtime` begins with `rmSync(RUNTIME_ROOT)`, so it re-downloads every run and
re-hits a corrupt entry every time rather than failing once.

### Branding

`productName` changed from `DeepSeek Harness` to `SecScan RedTeam`
(`apps/desktop/scripts/electron-builder-config.mjs:113`), pairing with
`DSH_DESKTOP_APP_ID=com.secscan.redteam`. The window icon is still the upstream one
(`resources/icon-windows.png`) and has not been replaced.

### Conclusion

Everything that can be produced without an MSVC toolchain has been. The app builds, runs,
and carries the red team. The installer needs Visual Studio Build Tools 2022 with
*Desktop development with C++*, installed as Administrator.
