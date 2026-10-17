/**
 * CDP transport tests (v0.34.0).
 *
 * The live browser smoke (`scripts/smoke-cdp.mjs`) proves the transport against a real
 * Chromium; these tests pin the parts a live run cannot exercise deterministically:
 * target resolution, the connect-before-send rule, command/response correlation,
 * error propagation and the timeout path.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { connectCdp, resolveCdpWebSocketUrl, type CdpFetchLike, type SocketLike } from "../src/browser/cdp-transport.js";

/** Fetch stub returning a target list (or an HTTP failure). */
function listFetch(targets: unknown, status = 200): CdpFetchLike {
  return async () => ({ ok: status < 400, status, json: async () => targets });
}

interface FakeSocket extends SocketLike {
  sent: Array<{ id: number; method: string; params: Record<string, unknown> }>;
}

/** Socket stub: opens when a handler is attached, and answers according to `reply`. */
function fakeSocket(options: { open?: boolean; reply?: (message: { id: number; method: string }) => unknown } = {}): FakeSocket {
  let openHandler: (() => void) | null = null;
  const socket: FakeSocket = {
    onopen: null,
    onclose: null,
    onmessage: null,
    onerror: null,
    sent: [],
    send(data: string) {
      const message = JSON.parse(data) as { id: number; method: string };
      socket.sent.push({ id: message.id, method: message.method, params: {} });
      const reply = options.reply?.(message);
      if (reply !== undefined && socket.onmessage) {
        queueMicrotask(() => socket.onmessage?.({ data: JSON.stringify(reply) }));
      }
    },
    close() { socket.onclose?.({}); },
  };
  // A real WebSocket opens after the listener is attached; mirror that ordering so a
  // handler assigned later still observes the open event.
  Object.defineProperty(socket, "onopen", {
    get: () => openHandler,
    set: (handler: (() => void) | null) => {
      openHandler = handler;
      if (handler && options.open !== false) queueMicrotask(() => handler());
    },
  });
  return socket;
}

describe("CDP target resolution", () => {
  it("uses an explicit ws:// endpoint as-is", async () => {
    const url = await resolveCdpWebSocketUrl("ws://127.0.0.1:9222/devtools/browser/abc", listFetch([]));
    assert.equal(url, "ws://127.0.0.1:9222/devtools/browser/abc");
  });

  it("picks the first page target from /json/list", async () => {
    const url = await resolveCdpWebSocketUrl("http://127.0.0.1:9222/", listFetch([
      { type: "browser", webSocketDebuggerUrl: "ws://browser" },
      { type: "page", webSocketDebuggerUrl: "ws://page" },
    ]));
    assert.equal(url, "ws://page");
  });

  it("fails when the endpoint refuses or lists no page", async () => {
    await assert.rejects(() => resolveCdpWebSocketUrl("http://127.0.0.1:9", listFetch({}, 500)), /cannot list targets/);
    await assert.rejects(() => resolveCdpWebSocketUrl("http://127.0.0.1:9", listFetch([{ type: "page" }])), /no debuggable page/);
  });
});

describe("CDP transport", () => {
  it("waits for the socket to open, then enables Runtime and Page", async () => {
    const socket = fakeSocket({ reply: (message) => ({ id: message.id, result: {} }) });
    const connection = await connectCdp("http://127.0.0.1:9222", {
      fetchImpl: listFetch([{ type: "page", webSocketDebuggerUrl: "ws://page" }]),
      socketFactory: () => socket,
      timeoutMs: 500,
    });
    assert.deepEqual(socket.sent.map((message) => message.method), ["Runtime.enable", "Page.enable"]);
    await connection.send("Page.navigate", { url: "http://example.test" });
    assert.equal(socket.sent[2]!.method, "Page.navigate");
    connection.close();
  });

  it("propagates a CDP error frame as a rejection", async () => {
    const socket = fakeSocket({
      reply: (message) => (message.method === "Page.enable"
        ? { id: message.id, error: { message: "not allowed" } }
        : { id: message.id, result: {} }),
    });
    await assert.rejects(() => connectCdp("http://127.0.0.1:9222", {
      fetchImpl: listFetch([{ type: "page", webSocketDebuggerUrl: "ws://page" }]),
      socketFactory: () => socket,
      timeoutMs: 500,
    }), /not allowed/);
  });

  it("fails closed when the socket never opens, and when a command times out", async () => {
    await assert.rejects(() => connectCdp("http://127.0.0.1:9222", {
      fetchImpl: listFetch([{ type: "page", webSocketDebuggerUrl: "ws://page" }]),
      socketFactory: () => fakeSocket({ open: false }),
      timeoutMs: 20,
    }), /did not open/);

    const silent = fakeSocket({ reply: (message) => (message.method === "Runtime.enable" || message.method === "Page.enable" ? { id: message.id, result: {} } : undefined) });
    const connection = await connectCdp("http://127.0.0.1:9222", {
      fetchImpl: listFetch([{ type: "page", webSocketDebuggerUrl: "ws://page" }]),
      socketFactory: () => silent,
      timeoutMs: 20,
    });
    await assert.rejects(() => connection.send("Page.navigate", {}), /timed out/);
    connection.close();
  });
});
