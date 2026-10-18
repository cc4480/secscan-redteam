# External toolchain — bundled vs operator-supplied

The runner spawns external tools for four families: **nmap** (port/service discovery),
**nuclei** (template checks), the **xtools** (ffuf, gobuster, john, sqlmap, nikto), and the
**content-discovery wordlist**. Every one of them resolves through a single precedence rule,
implemented once in `runner/src/toolchain.ts`, so the order cannot drift between bridges.

## Resolution order

For each tool, first match wins:

1. **Explicit environment variable** — `REDTEAM_NMAP_BIN`, `REDTEAM_NUCLEI_BIN`,
   `REDTEAM_FFUF_BIN`, `REDTEAM_GOBUSTER_BIN`, `REDTEAM_JOHN_BIN`/`REDTEAM_JOHN_HOME`,
   `REDTEAM_SQLMAP_DIR`, `REDTEAM_NIKTO_DIR`, `REDTEAM_WORDLIST`.
   A set-but-missing explicit value is **authoritative and reported as not found** — it never
   silently falls through to another copy, because "whatever happens to be on this machine"
   is exactly the ambiguity a readiness report must not introduce.
2. **Bundled tools directory** — `REDTEAM_TOOLS_DIR/<subdir>/<executable>`:
   `nmap/nmap.exe`, `nuclei/nuclei.exe`, `ffuf/ffuf.exe`, `gobuster/gobuster.exe`,
   `john/bin/john-{avx2,avx,sse41,sse2,xop}-non-omp.exe` (first present),
   `sqlmap/` (must contain `sqlmap.py`), `nikto/program/` (must contain `nikto.pl`),
   `wordlists/common.txt`.
3. **System default / PATH** — the bare command name (`nmap`, `ffuf`, …).

`redteam-runner doctor` prints, per tool, the resolved path **and which of the three sources it
came from**, plus a `bundled tools directory` row (optional, never blocks a run). That is the
mechanical answer to "is this installation actually able to run an engagement".

## Where the bundled directory comes from

The desktop application ships it: `node apps/desktop/scripts/vendor-tools.mjs` in the desktop
repository materializes `resources/tools` from a pinned `resources/tools-manifest.json`
(URL + SHA-256 + license per tool), electron-builder copies it to
`<install>/resources/tools`, and the desktop supervisor exports `REDTEAM_TOOLS_DIR` to the
runner child. Binaries are build output and are not committed; the manifest and the script are,
so every payload is reproducible and hash-verified.

An absent directory is not an error: the runner falls back to PATH and the readiness report
names the missing tools, which keep their `[needs: …]` battery markers.

## Tool tiers and licenses

| Tier | Tools | Notes |
|---|---|---|
| 1 | nmap 7.92 (win32 ZIP), ffuf 2.3.0, wordlist | The two tools a scan needs. nmap.org publishes a win32 ZIP only up to 7.92; Npcap is never bundled, so SYN scans stay an elevated opt-in and the connect-scan fallback maps ports unprivileged. App-local VC++ DLLs ship in the tree. |
| 2 | gobuster 3.8.2, nuclei | Optional content-discovery and template scanning; nuclei's template checkout stays an operator action. |
| 3 | sqlmap, john, nikto | Need a Python/Perl runtime; remain `[needs: …]` until provisioned. |

Licenses: nmap (NPSL/GPLv2-based), ffuf and nuclei (MIT), gobuster (Apache-2.0), sqlmap/john/nikto
(GPLv2). Each vendored tree carries a `.provenance.json` and the upstream license files; a build
including them must also carry the corresponding third-party notices.

## Verifying a provisioned install

```powershell
$env:REDTEAM_TOOLS_DIR = '<install>\resources\tools'
node <install>\resources\redteam-runner\dist\cli.js doctor
# expect: bundled tools directory OK, nmap/ffuf/gobuster "[from bundled tools directory]"
```

With `PATH` stripped and every explicit override removed, that command resolving nmap, ffuf,
gobuster and the wordlist is the zero-install contract in one line.
