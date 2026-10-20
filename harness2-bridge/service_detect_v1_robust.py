"""
Layer ID: v1-robust-syn
Target Class: service_detect
Parent Layer: v0-baseline-probe
Status: PROPOSED 2026-10-20 (editor verdict: recommend adopt, live 9/9 x2 batches; awaiting Carlos)
Rationale: Fast probe first with an 800ms budget. A refusal means closed, immediately,
           with no retry. On timeout, escalate exactly once to a longer 2500ms connect
           before declaring filtered. Never repeat a probe at the same timeout: on this
           fleet's Windows stack a closed localhost port answers RST at ~2.0-2.1s, so a
           2000ms probe retries the same losing race forever (v0: 0/6 on closed, 12s
           per target) while one longer fallback crosses the threshold (v1: 6/6).
"""

PROMPT_LAYER_CONFIG = {
    "layer_id": "v1-robust-syn",
    "target_class": "service_detect",
    "system_instructions": (
        "ROBUST PORT-STATE PROTOCOL:\n"
        "1. PRIMARY PROBE: Execute `tcp_probe` once with an 800ms timeout "
        "(non-blocking tcp_connect; on Windows this is the SYN surrogate).\n"
        "2. OPEN: If the probe connects, the port is OPEN. Stop.\n"
        "3. FAIL-FAST CLOSED: If the probe is refused (RST / ICMP unreachable), "
        "the port is CLOSED. Stop. Never retry a refusal.\n"
        "4. SINGLE ESCALATION: If the probe times out, execute exactly one "
        "fallback `tcp_probe` with a 2500ms timeout. Its outcome decides: "
        "connect = OPEN, refusal = CLOSED, timeout = FILTERED.\n"
        "5. NO SAME-BUDGET RETRIES: Never repeat a timed-out probe at the same "
        "or a shorter timeout. Escalate once, then decide."
    ),
    "allowed_tools": ["tcp_probe"],
    "max_steps": 2,
    "temperature": 0.0
}
