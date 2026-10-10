/**
 * WebProber REAL network behavior (audit 2026-10-09, tests HIGH #3).
 *
 * Pre-flight validation had tests; the live fetch did not. These stand up
 * throwaway servers on 127.0.0.1 (ephemeral ports, the only traffic allowed)
 * and prove the documented transport contract end to end:
 *  - the timeout actually fires on a stalling target
 *  - an oversized body comes back as a 4KB snippet (result-level truncation)
 *  - redirects are never followed; a 302 into link-local (metadata) space
 *    refuses the probe instead of handing out the hop
 *  - garbage bytes / header bombs are rejected, never "recorded"
 * Fast + hermetic: injected short timeout, minDelayMs 0, no external net.
 *
 * Every socket is tracked and destroyed in after() — no reliance on
 * server.closeAllConnections (its typing/runtime presence varies across
 * Node type versions), so the file always terminates.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { createServer as createTcpServer, type Server as TcpServer, type Socket } from "node:net";
import type { AddressInfo } from "node:net";
import { WebProber } from "../src/prober.js";

const TWO_MB = 2 * 1024 * 1024;

/**
 * Fail loudly if a probe never settles (a stalled transport must become a
 * named test failure, never a parked suite).
 */
function settleWithin<T>(p: Promise<T>, ms = 4_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const guard = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`probe did not settle within ${ms}ms`)), ms);
    timer.unref();
  });
  return Promise.race([p, guard]).finally(() => clearTimeout(timer));
}

describe("WebProber real network behavior (loopback servers only)", () => {
  let server: Server;
  let garbage: TcpServer;
  let port = 0;
  let garbagePort = 0;
  let targetHits = 0;
  let okHits = 0;
  const sockets = new Set<Socket>();
  const track = (s: Socket) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
  };

  const loopbackProber = (timeoutMs: number) =>
    new WebProber({ scopeHosts: ["127.0.0.1"], allowPrivateHosts: true, minDelayMs: 0, timeoutMs });

  before(async () => {
    server = createServer((req, res) => {
      const path = req.url ?? "/";
      if (path === "/ok") {
        okHits++;
        res.end("hello");
        return;
      }
      if (path === "/big") {
        res.setHeader("content-type", "text/plain");
        res.end("A".repeat(TWO_MB));
        return;
      }
      if (path === "/drip") {
        // Writes a partial body, then stalls "forever" (a 10s tail-end the
        // client timeout must cut long before). Cleared on socket close.
        res.writeHead(200, { "content-type": "text/plain" });
        res.write("partial");
        const tail = setTimeout(() => res.end("late"), 10_000);
        tail.unref();
        res.on("close", () => clearTimeout(tail));
        return;
      }
      if (path === "/redir") {
        res.writeHead(302, { location: "/target" });
        res.end();
        return;
      }
      if (path === "/target") {
        targetHits++;
        res.end("you followed a redirect");
        return;
      }
      if (path === "/redir-meta") {
        res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
        res.end();
        return;
      }
      if (path === "/redir-self") {
        res.writeHead(302, { location: `http://127.0.0.1:${port}/ok` });
        res.end();
        return;
      }
      if (path === "/huge-header") {
        res.setHeader("x-bomb", "H".repeat(64 * 1024));
        res.end("ok");
        return;
      }
      res.writeHead(404);
      res.end("nope");
    });
    server.on("connection", track);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;

    garbage = createTcpServer((socket) => {
      socket.end("this is not http\r\n\r\n");
    });
    garbage.on("connection", track);
    await new Promise<void>((resolve) => garbage.listen(0, "127.0.0.1", resolve));
    garbagePort = (garbage.address() as AddressInfo).port;
  });

  after(async () => {
    for (const s of sockets) s.destroy();
    await Promise.all([
      new Promise<void>((r) => server.close(() => r())),
      new Promise<void>((r) => garbage.close(() => r())),
    ]);
  });

  it("default timeout is the documented 20s", () => {
    const p = new WebProber({ scopeHosts: ["127.0.0.1"], allowPrivateHosts: true, minDelayMs: 0 });
    assert.equal((p as unknown as { timeoutMs: number }).timeoutMs, 20_000);
  });

  it("the timeout actually fires on a stalling target", async () => {
    const prober = loopbackProber(300);
    const started = Date.now();
    await assert.rejects(settleWithin(prober.probe({ method: "GET", url: `http://127.0.0.1:${port}/drip` })), /abort/i);
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= 200, `aborted suspiciously early (${elapsed}ms) — not the timeout?`);
    assert.ok(elapsed < 3_000, `timeout took ${elapsed}ms — the 300ms cap did not fire`);
  });

  it("an oversized body is returned as a 4KB snippet (huge response, small evidence)", async () => {
    const prober = loopbackProber(5_000);
    const res = await settleWithin(prober.probe({ method: "GET", url: `http://127.0.0.1:${port}/big` }));
    assert.equal(res.status, 200);
    assert.equal(res.bodySnippet.length, 4096);
    assert.equal(res.bodySnippet, "A".repeat(4096));
  });

  it("redirects are never followed (302 returned as the result, target untouched)", async () => {
    const prober = loopbackProber(5_000);
    const beforeHits = targetHits;
    const res = await prober.probe({ method: "GET", url: `http://127.0.0.1:${port}/redir` });
    assert.equal(res.status, 302);
    assert.equal(targetHits, beforeHits, "the redirect target must not be fetched");
  });

  it("a 302 into link-local (metadata) space refuses the probe", async () => {
    const prober = loopbackProber(5_000);
    await assert.rejects(
      prober.probe({ method: "GET", url: `http://127.0.0.1:${port}/redir-meta` }),
      /redirect target 169\.254\.169\.254 rejected/,
    );
  });

  it("a 302 to an allowed loopback target is returned, not followed", async () => {
    const prober = loopbackProber(5_000);
    const beforeHits = okHits;
    const res = await prober.probe({ method: "GET", url: `http://127.0.0.1:${port}/redir-self` });
    assert.equal(res.status, 302);
    assert.equal(okHits, beforeHits, "even an allowed redirect is inspected, never followed");
  });

  it("non-HTTP garbage bytes reject instead of being recorded as a response", async () => {
    const prober = loopbackProber(5_000);
    await assert.rejects(settleWithin(prober.probe({ method: "GET", url: `http://127.0.0.1:${garbagePort}/` })));
  });

  it("a header bomb is rejected by the transport, not buffered into evidence", async () => {
    const prober = loopbackProber(5_000);
    await assert.rejects(settleWithin(prober.probe({ method: "GET", url: `http://127.0.0.1:${port}/huge-header` })));
  });
});
