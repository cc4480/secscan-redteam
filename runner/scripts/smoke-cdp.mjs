/**
 * On-host smoke: browser/CDP driver against a real browser (v0.34.0).
 *
 * The driver in `src/browser/cdp.ts` and the transport in `src/browser/cdp-transport.ts`
 * are ordinary code; this script is the proof that they work against an actual Chromium
 * browser, which a unit test cannot provide. It is deliberately not part of the test
 * suite: it launches a browser process and needs one installed.
 *
 * What it proves, in order:
 *   1. a headless browser can be started and its DevTools endpoint discovered
 *   2. `connectCdp` resolves a page target and completes the CDP handshake
 *   3. `createCdpDriver().navigate` drives the page to a local URL
 *   4. `snapshot` reads url/title/text from the live document
 *   5. `fillField` sets a labeled input through real DOM events
 *   6. `evalJs` reads state back out of the page
 *
 * Usage: node scripts/smoke-cdp.mjs [--browser <path>]
 * Exit code 0 means every step passed. Set REDTEAM_BROWSER_BIN to pick a browser.
 */

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCdpDriver } from "../dist/browser/cdp.js";
import { connectCdp } from "../dist/browser/cdp-transport.js";

const PAGE = `<!doctype html><html><head><title>smoke-page</title></head>
<body>
  <h1>CDP smoke</h1>
  <p id="marker">hello from the deterministic page</p>
  <label for="email">Email</label>
  <input id="email" type="text" />
  <button id="go">Go</button>
</body></html>`;

const candidates = [
  process.env.REDTEAM_BROWSER_BIN,
  process.env.ProgramFiles && join(process.env.ProgramFiles, "Google", "Chrome", "Application", "chrome.exe"),
  process.env["ProgramFiles(x86)"] && join(process.env["ProgramFiles(x86)"], "Microsoft", "Edge", "Application", "msedge.exe"),
  process.env.ProgramFiles && join(process.env.ProgramFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
];
const browserPath = candidates.find((candidate) => candidate && existsSync(candidate));

function fail(message) {
  process.stderr.write(`smoke-cdp: FAIL — ${message}\n`);
  process.exitCode = 1;
}

async function main() {
  if (!browserPath) {
    fail("no browser found; set REDTEAM_BROWSER_BIN to a Chrome/Edge executable");
    return;
  }
  process.stdout.write(`smoke-cdp: browser ${browserPath}\n`);

  const server = createServer((request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(PAGE);
  });
  const port = await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
  const pageUrl = `http://127.0.0.1:${String(port)}/`;
  const profile = mkdtempSync(join(tmpdir(), "cdp-smoke-"));
  const debugPort = 9500 + Math.floor(Math.random() * 400);

  const child = spawn(browserPath, [
    "--headless=new",
    `--remote-debugging-port=${String(debugPort)}`,
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-gpu",
    "about:blank",
  ], { stdio: "ignore", windowsHide: true });

  let connection;
  try {
    // Wait for the DevTools endpoint to answer.
    const endpoint = `http://127.0.0.1:${String(debugPort)}`;
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      try {
        const response = await fetch(`${endpoint}/json/version`);
        if (response.ok) { ready = true; break; }
      } catch { /* not listening yet */ }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    if (!ready) throw new Error(`DevTools endpoint ${endpoint} never became ready`);
    process.stdout.write("smoke-cdp: PASS endpoint discovered\n");

    connection = await connectCdp(endpoint);
    process.stdout.write("smoke-cdp: PASS CDP handshake (Runtime.enable + Page.enable)\n");

    const driver = createCdpDriver(connection);
    await driver.navigate(pageUrl);
    process.stdout.write("smoke-cdp: PASS navigate\n");

    // The page settles asynchronously after navigation; poll briefly for the marker.
    let snapshot = { url: "", title: "", text: "" };
    for (let attempt = 0; attempt < 40; attempt += 1) {
      snapshot = await driver.snapshot();
      if (snapshot.url.startsWith(pageUrl) && snapshot.text.includes("hello from the deterministic page")) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (!snapshot.url.startsWith(pageUrl)) throw new Error(`snapshot url ${JSON.stringify(snapshot.url)} != ${pageUrl}`);
    if (!snapshot.title.includes("smoke-page")) throw new Error(`snapshot title ${JSON.stringify(snapshot.title)}`);
    if (!snapshot.text.includes("hello from the deterministic page")) throw new Error("snapshot text is missing the page marker");
    process.stdout.write(`smoke-cdp: PASS snapshot (title=${JSON.stringify(snapshot.title)})\n`);

    await driver.fillField("Email", "operator@example.test");
    const value = await driver.evalJs("document.getElementById('email').value");
    if (value !== "operator@example.test") throw new Error(`fillField produced ${JSON.stringify(value)}`);
    process.stdout.write("smoke-cdp: PASS fillField + evalJs\n");

    const title = await driver.evalJs("document.title");
    if (title !== "smoke-page") throw new Error(`evalJs returned ${JSON.stringify(title)}`);
    process.stdout.write("smoke-cdp: PASS evalJs\n");

    // The driver must refuse anything that is not http(s).
    let refused = false;
    try { await driver.navigate("file:///etc/passwd"); } catch { refused = true; }
    if (!refused) throw new Error("navigate accepted a non-http(s) URL");
    process.stdout.write("smoke-cdp: PASS navigate rejects non-http(s) URLs\n");

    process.stdout.write("smoke-cdp: PASS all checks\n");
  } finally {
    connection?.close();
    child.kill("SIGKILL");
    server.close();
    await new Promise((resolve) => setTimeout(resolve, 300));
    rmSync(profile, { recursive: true, force: true, maxRetries: 5 });
  }
}

main().catch((error) => {
  fail(error instanceof Error ? error.message : String(error));
});
