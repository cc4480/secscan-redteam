# `@secscan/redteam-harness-plugin`

DeepSeek Harness plugin for the SecScan red team. It does two things, and **only** two things:

1. **Installs the authorization gate** as a `tools/pre-execute` hook, so every tool
   call is checked against active testing scope *before* anything is sent.
2. **Registers a red-team engagement-protocol system-prompt section.**

It does **not** bridge the SecScan API. The SecScan MCP connection is the harness-native
`@deepseek-ai/dsh-mcp-client`, declared alongside this plugin in `cordis.patch.yml`.
Tools arrive namespaced as `mcp__secscan__scan_url`, `mcp__secscan__get_report`, …

---

## What is honest about this plugin today

Stated plainly, because the rest of this repo states things plainly:

- The plugin is **built and test-verified** (smoke tests for the pre-execute hook and the
  prompt section). It has **not** been exercised in a live engagement from inside a DSH
  session.
- `REDTEAM_PROFILE` in `redteam-profile.ts` **drives the injected section**: `index.ts` builds
  the specialist roster and the task DAG from it. It is still **not a spawner** — nothing in this
  repo starts those members as separate subagents; the section tells the session's Lead to do
  that with the Agent Teams tools.
- The gate **fails closed**. If `SECSCAN_MCP_TOKEN` is unset, the `mcp__secscan__*` tools
  simply do not appear — and the gate denies active work anyway.

---

## Packaging: why the plain tarball does not work

`npm pack` on this directory produces a tarball that **cannot be installed**. The compiled
plugin imports two sibling workspace packages at runtime:

```
dist/auth-gate.js        -> @secscan/redteam-auth-gate
dist/index.js            -> @secscan/redteam-llm-router
dist/redteam-profile.js  -> @secscan/redteam-llm-router
```

Those are pnpm workspace links, and every package in this repo is `private: true`, so they are
not on npm. Installing the plain tarball fails with:

```
npm error 404 Not Found - GET .../@secscan%2Fredteam-auth-gate
```

Both siblings have **zero runtime dependencies** of their own (devDependencies only), so
inlining them is cheap — `dist/` plus `package.json` each, no transitive tree to flatten.

### Build the self-contained tarball

```sh
npm run build                              # from the repo root; stamps every dist/
node scripts/pack-plugin.mjs               # or: npm -w @secscan/redteam-harness-plugin run pack:selfcontained
```

Output: `secscan-redteam-harness-plugin-<version>.tgz` (~30 KB), with `sha256` printed.

The script **refuses to pack a stale `dist/`**, using the same `dist-hash` gate the repo uses
everywhere else. A self-contained bundle of an old build is worse than no bundle: the consumer
has no signal that it is old.

`peerDependencies` are deliberately **not** bundled. `@deepseek-ai/cordis` and
`@deepseek-ai/dsh-tools` are supplied by the DSH host — that is what a peer dependency means.

---

## Path A — register the plugin in a DSH profile

For a developer machine that already has DSH Desktop (or a DSH CLI) installed.

> **Do not do this while the target DSH app is running.** The profile is read at startup.
> Close the app, apply, then reopen. The profile lives outside the install directory, so this
> survives reinstalling or upgrading DSH.

1. **Build the self-contained tarball** (above).

2. **Install it into the profile's `node_modules`.** The active profile here is `desktop`:

   ```powershell
   $profile = "$env:USERPROFILE\.dsh\profiles\desktop"
   cd $profile
   npm install <path-to>\secscan-redteam-harness-plugin-0.2.0.tgz
   ```

3. **Merge the loader entries.** Take both `insert` entries from this directory's
   `cordis.patch.yml` and append them to the profile's own `cordis.patch.yml`
   (`$profile\cordis.patch.yml`). That file is a top-level YAML **array** of patch entries and is
   applied after every bundle layer, so the two `insert` blocks append cleanly.

4. **Set the MCP token.** Create a token at <https://secscan.us/settings> — the settings page
   issues it for MCP clients and displays the Claude Code and Cursor configurations. The
   `ssk_`-prefixed API token works against the MCP endpoint; an earlier version of this file
   claimed a separate "MCP scope" existed, which was wrong and cost real debugging time.
   Then set `SECSCAN_MCP_TOKEN` in the environment DSH runs under. With it unset, DSH still
   starts; the `mcp__secscan__*` tools just do not appear.

5. **Reopen DSH** and confirm `mcp__secscan__*` tools are listed.

---

## Path B — bake the plugin into a DSH Desktop build

So a fresh install of the Windows app already carries the redteam tools, the way `office-docx`,
`office-pptx` and `office-xlsx` already ship "registered by default".

**The build pipeline is not in `cc4480/dsh-desktop`.** That repository holds only the installer,
`README.md`, `RELEASE-NOTES.md` and `SHA256SUMS.txt`. The build is performed against the
upstream source, per the dsh-desktop README:

```sh
git clone https://github.com/deepseek-ai/deepseek-harness.git
cd deepseek-harness
git checkout 46a7f68b0922371ce7144b668b90e377d8e799f4
pnpm install
pnpm --dir apps/desktop run package:win:x64:unsigned
```

So shipping this plugin by default means changing the **build stage**, in one of two places:

- **Default-profile seed** — whatever mechanism the build uses to seed a new
  `%USERPROFILE%\.dsh\profiles\desktop` on first run. Add the plugin package plus the two
  `cordis.patch.yml` entries there. This is the closest analogue to how the office skills are
  registered by default.
- **Bundled skills directory** — `resources/runtime/office-skills/<name>/SKILL.md` is where
  skills are baked into the runtime. Note this is a **skills** mechanism; this plugin is a
  **cordis plugin**, so the profile-seed route above is the correct one. Do not force it into
  `office-skills`.

Either way the self-contained tarball from `pack-plugin.mjs` is the artifact to ship, because
it removes the registry dependency at install time.

### Blockers to settle before Path B ships

- **`private: true` on all three packages.** Fine for bundling; it must be lifted if you ever
  want registry distribution instead.
- **The installer is unsigned**, per dsh-desktop's own README, so enterprise code-integrity
  policy may block it regardless of what it contains.
- **`dsh-desktop` currently builds from upstream commit `46a7f68b…`.** Baking the plugin in
  means either patching that checkout during the build or maintaining a fork — the dsh-desktop
  README already records that the packaging run flagged the source checkout as **dirty**, so the
  existing binary may not match that commit. Decide which it is before adding more.

---

## Verify an install

```powershell
# the tarball installs with no registry access
mkdir $env:TEMP\plugin-check; cd $env:TEMP\plugin-check
'{"name":"c","private":true,"type":"module"}' | Set-Content package.json
npm install --no-save <path-to>\secscan-redteam-harness-plugin-0.2.0.tgz
node -e "import('@secscan/redteam-harness-plugin').then(m=>console.log('OK',Object.keys(m)))"
# expected: OK [ 'apply', 'inject', 'name', 'plugin' ]
```

---

## Security

Keys come from the environment only. **Never put a key in `cordis.patch.yml`** — the token is
read with `process.env.SECSCAN_MCP_TOKEN` and nothing here logs, prints or persists it.

The authorization gate is non-negotiable and applies to the operator too. Active testing
requires proven domain ownership, re-checked before every aggressive action, and it fails closed
for everyone. There is no in-chat override.
