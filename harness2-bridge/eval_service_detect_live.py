"""Live evaluation for service_detect Cycle 2 — v0-baseline-probe vs v1-robust-syn.

Live-logic mode (same caveat as Cycle 1): the layers' decision logic runs
for real against real sockets; no LLM is in the loop. Ground truth is
localhost-only per the Cycle 2 constraint lock:

  OPEN     127.0.0.1 listener sockets started by this script (3 ports)
  CLOSED   127.0.0.1 high ports verified unbound (3 ports) -> RST/refused
  FILTERED 10.255.255.1 (non-routable blackhole) (3 ports) -> timeout
           The script first MEASURES the blackhole: if connects fail fast
           instead of timing out, the fixture is invalid and the run aborts
           rather than fabricating a filtered state.

Layer logic per the 2026-10-19 design lock:
  v0-baseline-probe  tcp_connect 2000ms; on timeout retries aggressively
                     (eval cap 5 retries — the production flaw is unbounded;
                     the cap keeps the batch finite while measuring the waste)
  v1-robust-syn      probe 800ms (non-blocking tcp_connect as SYN surrogate,
                     Windows-feasible per the tuner's resolution);
                     refused -> closed immediately, no retry;
                     timeout -> ONE fallback tcp_connect 2500ms -> decide

Every (target x layer) run is logged via harness_logger.log_trajectory with
mode=live in the trace. Token cost is a labeled proxy: attempts x 100.
"""
import json
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from harness_logger import log_trajectory  # noqa: E402

OPEN_PORTS = [18711, 18712, 18713]
CLOSED_PORTS = [18721, 18722, 18723]
BLACKHOLE_IP = "10.255.255.1"
FILTERED_PORTS = [65001, 65002, 65003]


def tcp_probe(host: str, port: int, timeout_ms: int) -> tuple[str, int]:
    """Returns (outcome, elapsed_ms); outcome in open|closed|timeout|error:*"""
    started = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_ms / 1000.0)
    try:
        s.connect((host, port))
        return "open", int((time.time() - started) * 1000)
    except ConnectionRefusedError:
        return "closed", int((time.time() - started) * 1000)
    except (socket.timeout, TimeoutError):
        return "timeout", int((time.time() - started) * 1000)
    except OSError as err:
        return f"error:{err.errno}", int((time.time() - started) * 1000)
    finally:
        s.close()


def v0_baseline_probe(host: str, port: int) -> tuple[str, list]:
    attempts = []
    for _ in range(6):  # 1 primary + 5 retries (eval cap on 'unbounded')
        outcome, ms = tcp_probe(host, port, 2000)
        attempts.append({"probe": "tcp_connect", "timeout_ms": 2000, "outcome": outcome, "ms": ms})
        if outcome == "open":
            return "open", attempts
        if outcome == "closed":
            return "closed", attempts
        # timeout/error -> aggressive retry, the v0 flaw
    return "filtered", attempts


def v1_robust_syn(host: str, port: int) -> tuple[str, list]:
    attempts = []
    outcome, ms = tcp_probe(host, port, 800)
    attempts.append({"probe": "fast_probe", "timeout_ms": 800, "outcome": outcome, "ms": ms})
    if outcome == "open":
        return "open", attempts
    if outcome == "closed":
        return "closed", attempts  # RST fail-fast: no retry, no escalation
    outcome2, ms2 = tcp_probe(host, port, 2500)
    attempts.append({"probe": "fallback_connect", "timeout_ms": 2500, "outcome": outcome2, "ms": ms2})
    if outcome2 == "open":
        return "open", attempts
    if outcome2 == "closed":
        return "closed", attempts
    return "filtered", attempts


LAYERS = {"v0-baseline-probe": v0_baseline_probe, "v1-robust-syn": v1_robust_syn}


def start_listeners(ports: list[int]) -> list[socket.socket]:
    listeners = []
    for p in ports:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", p))
        srv.listen(8)
        listeners.append(srv)

        def accept_loop(s=srv):
            while True:
                try:
                    conn, _ = s.accept()
                    conn.close()
                except OSError:
                    return

        threading.Thread(target=accept_loop, daemon=True).start()
    return listeners


def port_is_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main() -> int:
    # Fixture validation first — never fabricate a ground truth.
    for p in CLOSED_PORTS:
        if not port_is_free(p):
            print(f"ABORT: closed-fixture port {p} is bound")
            return 1
    probe_outcome, probe_ms = tcp_probe(BLACKHOLE_IP, FILTERED_PORTS[0], 3000)
    print(f"blackhole check: outcome={probe_outcome} ms={probe_ms}")
    if probe_outcome != "timeout":
        print("ABORT: blackhole fixture does not time out on this host — filtered state not reproducible this way")
        return 1

    listeners = start_listeners(OPEN_PORTS)
    targets = (
        [("127.0.0.1", p, "open") for p in OPEN_PORTS]
        + [("127.0.0.1", p, "closed") for p in CLOSED_PORTS]
        + [(BLACKHOLE_IP, p, "filtered") for p in FILTERED_PORTS]
    )
    results = {layer: {"correct": 0, "total": 0, "confusion": {}} for layer in LAYERS}
    try:
        for host, port, truth in targets:
            for layer_id, logic in LAYERS.items():
                started = time.time()
                decision, attempts = logic(host, port)
                latency = int((time.time() - started) * 1000)
                correct = decision == truth
                run_id = log_trajectory(
                    target_class="service_detect",
                    layer_id=layer_id,
                    passed=correct,
                    score=1.0 if correct else 0.0,
                    tokens_used=len(attempts) * 100,
                    latency_ms=latency,
                    prompt_text=f"[live] Classify port state: {host}:{port}",
                    trace=[{
                        "mode": "live",
                        "fixture": truth,
                        "target": f"{host}:{port}",
                        "decision": decision,
                        "attempts": attempts,
                        "token_proxy": "attempts*100",
                    }],
                    verifier_output=f"LIVE: decision={decision} ground_truth={truth} — {'CORRECT' if correct else 'WRONG'}",
                )
                r = results[layer_id]
                r["total"] += 1
                r["correct"] += int(correct)
                key = f"{truth}->{decision}"
                r["confusion"][key] = r["confusion"].get(key, 0) + 1
                print(f"{layer_id} {host}:{port} truth={truth} decision={decision} {'OK' if correct else 'WRONG'} latency={latency}ms run={run_id}")
    finally:
        for s in listeners:
            s.close()
    print("\n==== SUMMARY ====")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
