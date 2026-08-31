"""
Live, non-LLM-guessed cross-identity IDOR proof for PixelMart's TP3
(profile IDOR) and TP4 (order IDOR) -- see ANSWER_KEY.md #3/#4.

Every prior scoring pass (phase_real_run_v5.py and friends) fed each
captured exchange through orchestrator.analyze() independently, so a
"CONFIRMED" IDOR was never more than an LLM's guess from a single
exchange -- even though capture_exchanges.py already logs in as two real,
distinct identities (Alice, Bob) specifically to test this. This script
throws nothing away: it performs the actual four-probe comparison
(source/candidate/attempt/anon) IdentityCompareLogic.java's proven design
calls for, using real HTTP against a real, running PixelMart -- no
Ollama, no Burp, no harness server required.

Self-contained by design (see the implementation plan's Part C rationale):
does not read capture_exchanges.py's output or register anything through
harness/server.py's /identities or /sessions endpoints (those exist only
to label a human's picker in ValidationExecutor.java, and reading stale
tokens from a JSON file would risk expired-token false negatives). Every
probe here is a fresh, live request, mirroring exactly what
ValidationExecutor.identityCompare() does on the Burp side.

PRECONDITION: run this against a FRESHLY RESTARTED `python app.py`, before
any other script has created an order -- TP4 relies on the orders table
starting empty so the two orders this script creates land at known ids
(matches ANSWER_KEY.md's own grading precondition, step 1).

Usage:
    # terminal 1
    cd testing/test-target && python app.py
    # terminal 2, immediately after
    cd testing/test-target && python cross_identity_probe.py
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "harness"))
import identity_compare  # noqa: E402

BASE = "http://127.0.0.1:5001"
RESULTS_PATH = Path("C:/tmp/pixelmart_cross_identity_results.json")


def login(username: str, password: str) -> str:
    resp = requests.post(f"{BASE}/api/login", json={"username": username, "password": password}, timeout=10)
    resp.raise_for_status()
    return resp.json()["token"]


def get(path: str, token: str | None) -> identity_compare.Probe:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = requests.get(f"{BASE}{path}", headers=headers, timeout=10)
    return identity_compare.Probe(resp.status_code, resp.text)


def create_order(token: str, product_id: int, quantity: int) -> None:
    resp = requests.post(f"{BASE}/api/orders", headers={"Authorization": f"Bearer {token}"},
                          json={"product_id": product_id, "quantity": quantity}, timeout=10)
    resp.raise_for_status()


def probe_case(name: str, source: identity_compare.Probe, candidate: identity_compare.Probe,
               attempt: identity_compare.Probe, anon: identity_compare.Probe,
               identifier_changed: bool) -> dict:
    ev = identity_compare.evaluate("cross_identity_compare", identifier_changed,
                                    source, candidate, attempt, anon)
    status = "confirmed" if ev.confirmed else ev.verdict.value.lower()
    report = {
        "validator": "cross_identity_probe",
        "finding_class": "idor",
        "status": status,
        "confidence": ev.confidence,
        "confirmed": ev.confirmed,
        "summary": ev.summary,
        "evidence": ev.detail,
    }
    print(f"[{name}] {ev.verdict.value} (confidence={ev.confidence}) -- {ev.summary}")
    return report


def main() -> None:
    alice_token = login("alice", "alicepw123")
    bob_token = login("bob", "bobpw456")

    results = []

    # --- TP3: profile IDOR (ANSWER_KEY.md #3) ---
    # alice=user id 1, bob=user id 2 -- stable across any fresh restart,
    # init_db() always inserts them in this fixed order (see app.py).
    tp3_source = get("/api/users/1/profile", alice_token)      # alice's own profile
    tp3_candidate = get("/api/users/2/profile", bob_token)     # bob's own profile
    tp3_attempt = get("/api/users/2/profile", alice_token)     # the attack: alice's token on bob's profile
    tp3_anon = get("/api/users/2/profile", None)
    results.append(probe_case("TP3 profile IDOR", tp3_source, tp3_candidate, tp3_attempt, tp3_anon,
                               identifier_changed=True))

    # --- TP4: order IDOR (ANSWER_KEY.md #4) ---
    # Orders table starts empty -- create both orders ourselves, bob
    # first, so order id 1 = bob's and order id 2 = alice's.
    create_order(bob_token, product_id=1, quantity=1)
    create_order(alice_token, product_id=2, quantity=1)
    tp4_source = get("/api/orders/2", alice_token)      # alice's own order
    tp4_candidate = get("/api/orders/1", bob_token)     # bob's own order
    tp4_attempt = get("/api/orders/1", alice_token)     # the attack: alice's token on bob's order
    tp4_anon = get("/api/orders/1", None)
    results.append(probe_case("TP4 order IDOR", tp4_source, tp4_candidate, tp4_attempt, tp4_anon,
                               identifier_changed=True))

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {len(results)} results to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
