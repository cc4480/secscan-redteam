#!/usr/bin/env python3
"""
Live-fire payload test runner for secscan-redteam variant libraries.

Usage:
    python3 test_runner.py --target http://localhost:5173 --category xss
    python3 test_runner.py --target http://localhost:5173 --category all --out results.json

For each payload in the category:
  1. Sends it as a query parameter (?q=<payload>) via GET
  2. Sends it as form data (q=<payload>) via POST
  3. Records status code, response time, and whether the payload
     (or a recognizable fragment) is reflected in the response body.

Classification (heuristic, human review required for final verdict):
  - "reflected"       — payload fragment appears verbatim in response
  - "error_reflected" — response is 500/400 with payload fragment present
  - "no_reflection"   — payload not found in response
  - "blocked"         — 403/429 or WAF-ish block page
  - "error"           — request failed (connection, timeout)

True/false positive determination REQUIRES manual review against ground
truth for the target. This runner only collects evidence; it does not
declare EXPLOITABLE.
"""

import argparse
import html
import json
import re
import sys
import time
import urllib.parse

try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

PAYLOADS_PATH = "payloads.json"
TIMEOUT = 10


def reflection_fragments(payload):
    """Return fragments of the payload worth searching for in a response."""
    frags = set()
    # verbatim (first 60 chars is usually enough to be distinctive)
    if len(payload) >= 8:
        frags.add(payload[:60])
    # URL-decoded form
    try:
        dec = urllib.parse.unquote(payload)
        if dec != payload and len(dec) >= 8:
            frags.add(dec[:60])
    except Exception:
        pass
    # HTML-entity-decoded form
    try:
        hed = html.unescape(payload)
        if hed != payload and len(hed) >= 8:
            frags.add(hed[:60])
    except Exception:
        pass
    # distinctive tokens (e.g. alert(1), 7*7, ../)
    for tok in re.findall(r"[A-Za-z0-9_]{3,}(?:\([^)]{0,20}\))?", payload):
        if len(tok) >= 6:
            frags.add(tok)
    return [f for f in frags if f]


def probe(session, method, url, params=None, data=None, headers_extra=None):
    """Send one probe, return evidence dict."""
    t0 = time.time()
    try:
        if method == "GET":
            r = session.get(url, params=params, timeout=TIMEOUT,
                            allow_redirects=False)
        else:
            r = session.post(url, data=data, timeout=TIMEOUT,
                             allow_redirects=False)
        dt = round(time.time() - t0, 3)
        body = r.text or ""
        return {
            "ok": True,
            "status": r.status_code,
            "time_s": dt,
            "len": len(body),
            "location": r.headers.get("Location", ""),
            "body": body[:20000],  # cap stored body
        }
    except Exception as e:  # noqa: BLE001 - evidence collection
        return {
            "ok": False,
            "status": 0,
            "time_s": round(time.time() - t0, 3),
            "len": 0,
            "location": "",
            "body": "",
            "error": f"{type(e).__name__}: {e}",
        }


def classify(payload, resp):
    """Heuristic classification based on reflection. Human review required."""
    if not resp["ok"]:
        return "error"
    body = resp["body"]
    status = resp["status"]
    if status in (403, 429):
        return "blocked"
    frags = reflection_fragments(payload)
    reflected = any(f in body for f in frags)
    if reflected:
        if status >= 500:
            return "error_reflected"
        return "reflected"
    return "no_reflection"


def run_category(session, target, category, items, param_names=("q", "search", "id")):
    results = []
    for i, item in enumerate(items):
        payload = item["payload"]
        entry = {
            "category": category,
            "index": i,
            "payload": payload,
            "tests": item.get("tests", ""),
            "probes": [],
        }
        # GET with each param name
        for pname in param_names:
            resp = probe(session, "GET", target, params={pname: payload})
            cls = classify(payload, resp)
            entry["probes"].append({
                "method": "GET",
                "param": pname,
                "classification": cls,
                "status": resp["status"],
                "time_s": resp["time_s"],
                "resp_len": resp["len"],
                "location": resp["location"],
            })
        # POST form with first param name
        resp = probe(session, "POST", target, data={param_names[0]: payload})
        cls = classify(payload, resp)
        entry["probes"].append({
            "method": "POST",
            "param": param_names[0],
            "classification": cls,
            "status": resp["status"],
            "time_s": resp["time_s"],
            "resp_len": resp["len"],
            "location": resp["location"],
        })
        # header-based probes for header/auth categories
        if category in ("headers", "auth") and ":" in payload:
            name, _, value = payload.partition(":")
            name, value = name.strip(), value.strip()
            if name and value and len(name) < 60:
                try:
                    t0 = time.time()
                    r = session.get(target, headers={name: value},
                                    timeout=TIMEOUT, allow_redirects=False)
                    dt = round(time.time() - t0, 3)
                    cls = classify(payload, {
                        "ok": True, "status": r.status_code,
                        "body": r.text or ""})
                    entry["probes"].append({
                        "method": "GET-HEADER",
                        "param": name,
                        "classification": cls,
                        "status": r.status_code,
                        "time_s": dt,
                        "resp_len": len(r.text or ""),
                        "location": r.headers.get("Location", ""),
                    })
                except Exception as e:  # noqa: BLE001
                    entry["probes"].append({
                        "method": "GET-HEADER",
                        "param": name,
                        "classification": "error",
                        "status": 0,
                        "time_s": 0,
                        "resp_len": 0,
                        "location": "",
                        "error": f"{type(e).__name__}",
                    })
        results.append(entry)
        if (i + 1) % 10 == 0:
            print(f"  [{category}] {i + 1}/{len(items)} done", flush=True)
    return results


def summarize(results):
    counts = {}
    for entry in results:
        for p in entry["probes"]:
            c = p["classification"]
            counts[c] = counts.get(c, 0) + 1
    reflected_items = sum(
        1 for e in results
        if any(p["classification"] in ("reflected", "error_reflected")
               for p in e["probes"]))
    return {
        "probe_classifications": counts,
        "payloads_with_any_reflection": reflected_items,
        "payloads_total": len(results),
    }


def main():
    ap = argparse.ArgumentParser(description="Live-fire payload test runner")
    ap.add_argument("--target", required=True,
                    help="Base target URL, e.g. http://localhost:5173/")
    ap.add_argument("--category", required=True,
                    help="Payload category or 'all' (sqli,xss,cmdi,ssti,xxe,traversal,ssrf,redirect,auth,headers)")
    ap.add_argument("--out", default="results.json", help="Output JSON path")
    ap.add_argument("--params", default="q,search,id",
                    help="Comma-separated param names to inject into")
    ap.add_argument("--payloads", default=PAYLOADS_PATH,
                    help="Path to payloads.json")
    args = ap.parse_args()

    with open(args.payloads, encoding="utf-8") as f:
        all_payloads = json.load(f)

    if args.category == "all":
        categories = sorted(all_payloads.keys())
    else:
        if args.category not in all_payloads:
            sys.exit(f"unknown category: {args.category} "
                     f"(have: {sorted(all_payloads.keys())})")
        categories = [args.category]

    param_names = [p.strip() for p in args.params.split(",") if p.strip()]
    session = requests.Session()
    session.headers.update({"User-Agent": "secscan-redteam-livefire/1.0"})

    output = {
        "target": args.target,
        "param_names": param_names,
        "categories": {},
        "note": ("Heuristic reflection evidence only. True/false positive "
                 "verdicts require manual review against target ground truth."),
    }
    for cat in categories:
        print(f"Running category: {cat} "
              f"({len(all_payloads[cat])} payloads)", flush=True)
        results = run_category(session, args.target, cat,
                               all_payloads[cat], param_names)
        output["categories"][cat] = {
            "results": results,
            "summary": summarize(results),
        }
        s = output["categories"][cat]["summary"]
        print(f"  -> {cat}: {s['payloads_with_any_reflection']}/"
              f"{s['payloads_total']} payloads reflected somewhere; "
              f"probes: {s['probe_classifications']}", flush=True)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=1)
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
