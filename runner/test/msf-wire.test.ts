/**
 * msfrpc wire-format regression tests.
 *
 * WHY THIS FILE EXISTS. msf.test.ts runs against a fake daemon that replies
 * with `encode(obj)` — genuine MessagePack, but with `str` keys, because the
 * encoder emits `str` for JavaScript strings. A real msfrpcd does NOT: Ruby's
 * `String#to_msgpack` emits `bin` for ASCII-8BIT strings, so both map keys and
 * values come back as binary.
 *
 * That difference made every call fail against a real daemon while the whole
 * suite stayed green:
 *
 *   1. @msgpack/msgpack v3 refuses a non-string map key — "The type of key must
 *      be string or number but object" — so msfCall threw
 *      MsfTransportError('undecodable data') before reading any result.
 *   2. Even with keys converted, values stayed Uint8Array, so
 *      `res['result'] === 'success'` could never be true and login always
 *      failed with MsfAuthError.
 *   3. msfCall also demanded a map, but module.search returns a bare ARRAY.
 *
 * The bytes below are captured verbatim from a live msfrpcd 6.5.3 (Metasploit
 * Framework on Windows) and are the ground truth this bridge must decode. Do
 * not "simplify" them through encode() — that is precisely the bug.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { msfCall } from "../src/msf/protocol.js";

const hex = (s: string): Uint8Array =>
  new Uint8Array((s.match(/../g) ?? []).map((b) => parseInt(b, 16)));

/** A transport that replays fixed bytes, whatever is sent. */
const replay = (bytes: Uint8Array) => async (): Promise<Uint8Array> => bytes;

/** 82 c406"result" c407"success" c405"token" c420"TEMP…"  — every key and value is bin8. */
const LOGIN_RESPONSE =
  "82c406726573756c74c40773756363657373c405746f6b656ec42054454d50525a51424a713557636474395a745a4d35644d4a77756d3669726b79";
const LOGIN_TOKEN = "TEMPRZQBJq5Wcdt9ZtZM5dMJwum6irky";

describe("msfrpc wire format (real daemon bytes)", () => {
  it("decodes bin8-encoded map KEYS to strings", async () => {
    const res = await msfCall(replay(hex(LOGIN_RESPONSE)), "auth.login", null, ["msf", "pw"]);
    assert.ok(!Array.isArray(res), "a map, not an array");
    assert.deepEqual(Object.keys(res as Record<string, unknown>).sort(), ["result", "token"]);
  });

  it("decodes bin8-encoded VALUES to strings (login can actually succeed)", async () => {
    const res = (await msfCall(replay(hex(LOGIN_RESPONSE)), "auth.login", null, ["msf", "pw"])) as Record<
      string,
      unknown
    >;
    // The exact comparison MsfClient.login makes. With raw Uint8Array values
    // this was always false, so login failed even though the daemon said success.
    assert.equal(res["result"], "success");
    assert.equal(res["token"], LOGIN_TOKEN);
    assert.equal(typeof res["token"], "string");
  });

  it("round-trips through the encoder would NOT have caught this", async () => {
    // Guards the guard: prove the fixture really is bin-encoded, so nobody
    // regenerates it with encode() and silently re-opens the bug.
    assert.equal(hex(LOGIN_RESPONSE)[1], 0xc4, "second byte must be bin8 (0xc4), not str8 (0xd9)");
    const { encode } = await import("@msgpack/msgpack");
    const encoded = encode({ result: "success" });
    assert.equal(encoded[1], 0xa6, "the encoder emits fixstr (0xa6) — which is why the fake daemon passed");
  });

  it("accepts an ARRAY response (module.search returns a bare array)", async () => {
    // 91 = fixarray(1) holding one map: {"fullname":"exploit/x"} — keys still bin8.
    const bytes = hex("91 81 c40866756c6c6e616d65 c4096578706c6f69742f78".replace(/ /g, ""));
    const res = await msfCall(replay(bytes), "module.search", "tok", ["apache"]);
    assert.ok(Array.isArray(res), "an array must not be rejected as a non-map response");
    assert.equal((res as unknown[]).length, 1);
    assert.deepEqual(res[0], { fullname: "exploit/x" });
  });

  it("still rejects a scalar response (fails closed)", async () => {
    await assert.rejects(
      () => msfCall(replay(hex("c3")), "core.version", "tok", []), // 0xc3 = true
      /neither a map nor an array/,
    );
  });

  it("still rejects genuinely corrupt bytes (fails closed)", async () => {
    await assert.rejects(
      () => msfCall(replay(hex("c1c1c1c1")), "core.version", "tok", []), // 0xc1 is never used
      /undecodable data/,
    );
  });
});
