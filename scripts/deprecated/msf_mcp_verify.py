#!/usr/bin/env python3
# DEPRECATED — do not use. This script performs a streamable-HTTP MCP
# handshake against POST /mcp, but the live gc-metasploit server speaks
# SSE (GET /sse) and 404s /mcp — a healthy server will "fail" this
# check. The working verifier is the SSE variant kept on the operator's
# PC (C:\Users\Cho-zen\msf_mcp_verify_sse.py). Kept for reference only.
"""Verify the gc-metasploit MCP server end-to-end (stdlib only).

Run ON Carlos's PC (where 127.0.0.1:8085 is the gc-metasploit server
backed by msfrpcd in the `msf-rpc` Docker container on port 55553).

Performs the real MCP streamable-HTTP handshake that direct POSTs skipped:
  1. initialize            (captures Mcp-Session-Id response header)
  2. notifications/initialized
  3. tools/list            (prints tool names; success = end-to-end verified)

Usage: python msf_mcp_verify.py [base_url]   (default http://127.0.0.1:8085)
Exit codes: 0 = tools/list OK, 1 = handshake/transport failure, 2 = bad usage.
Does NOT call any tool — read-only verification only. First scoped MSF
check (tools/call) is a separate, Carlos-approved step after this passes.
"""
import json
import sys
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8085"
ENDPOINT = BASE.rstrip("/") + "/mcp"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def post(payload, session_id=None, expect_response=True):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(ENDPOINT, data=data, method="POST")
    for k, v in HEADERS.items():
        req.add_header(k, v)
    if session_id:
        req.add_header("Mcp-Session-Id", session_id)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, resp.headers.get("Mcp-Session-Id"), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if e.fp else ""
        raise RuntimeError(f"HTTP {e.code} from {ENDPOINT}: {body[:400]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Cannot reach {ENDPOINT}: {e.reason}") from e


def parse_rpc(body):
    """Handle plain JSON or SSE-framed (data: ...) MCP responses."""
    body = body.strip()
    if not body:
        return {}
    if body.startswith("event:") or body.startswith("data:"):
        for line in body.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        return {}
    return json.loads(body)


def main():
    print(f"Target: {ENDPOINT}")
    # 1. initialize
    status, session_id, body = post({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "msf-mcp-verify", "version": "1.0"},
        },
    })
    rpc = parse_rpc(body)
    if "error" in rpc:
        print(f"FAIL: initialize returned error: {rpc['error']}")
        return 1
    server = rpc.get("result", {}).get("serverInfo", {})
    print(f"initialize OK (HTTP {status}) session={'yes' if session_id else 'none'} "
          f"server={server.get('name', '?')} {server.get('version', '')}".rstrip())

    # 2. notifications/initialized (no response expected)
    try:
        post({"jsonrpc": "2.0", "method": "notifications/initialized"},
             session_id=session_id)
    except RuntimeError as e:
        print(f"note: initialized notification: {e}")

    # 3. tools/list
    _, _, body = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                      session_id=session_id)
    rpc = parse_rpc(body)
    if "error" in rpc:
        print(f"FAIL: tools/list returned error: {rpc['error']}")
        return 1
    tools = rpc.get("result", {}).get("tools", [])
    if not tools:
        print("FAIL: tools/list returned zero tools")
        return 1
    print(f"tools/list OK — {len(tools)} tools:")
    for t in tools:
        print(f"  - {t.get('name')}")
    print("VERIFIED: MCP initialize -> initialized -> tools/list end-to-end.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        print(f"FAIL: {e}")
        sys.exit(1)
