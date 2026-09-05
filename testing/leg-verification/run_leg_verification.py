"""
Operator-run live leg-verification (Phase 2.2 / 2.3).

Stands up vuln_fixture on localhost and runs the confirmation legs against its
true-positive endpoints, printing CONFIRMED / not for each. Use this on a machine
with the extra infra the hermetic test_leg_live_verification can't assume:

  - path_traversal: needs a real canonical system file (C:\\Windows\\win.ini on
    Windows, /etc/passwd on POSIX) reachable by traversal from the fixture dir.
  - browser_xss: needs a real Chromium/Playwright (or a CDP endpoint).

SSTI and open_redirect are already covered portably by the hermetic test; they
are included here too as a sanity check. The OOB legs (xxe / ssrf /
command_injection) are NOT covered: the fixture has no OOB endpoints yet and they
need a live collaborator -- adding those endpoints is the next fixture step.

Run:  python testing/leg-verification/run_leg_verification.py
(from the repo root, with harness/ importable -- e.g. PYTHONPATH=harness).
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time
import urllib.request
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO / "harness"))

from werkzeug.serving import make_server  # noqa: E402
import global_throttle  # noqa: E402
import safety_gate  # noqa: E402
from models import Finding, HttpExchange  # noqa: E402
from vuln_fixture import make_app  # noqa: E402 (same dir)


def _finding(vc):
    return Finding(vulnerability_class=vc, confidence=0.5, severity="high",
                   summary=f"{vc} hypothesis", evidence="", suggested_test="", basis="derived")


async def _run_all(base: str):
    from validators.ssti_validator import SstiValidator
    from validators.open_redirect_validator import OpenRedirectValidator
    from validators.path_traversal_validator import PathTraversalValidator
    from validators.browser_xss_validator import BrowserXssValidator

    hosts = ["127.0.0.1"]
    cases = [
        ("ssti",           SstiValidator(allowed_hosts=hosts),          "/ssti/render?q=seed"),
        ("open_redirect",  OpenRedirectValidator(allowed_hosts=hosts),  "/redirect/open?url=/seed"),
        ("path_traversal", PathTraversalValidator(allowed_hosts=hosts), "/files/read?file=seed.txt"),
        ("browser_xss",    BrowserXssValidator(allowed_hosts=hosts),    "/xss/reflect?q=seed"),
    ]
    for name, validator, path in cases:
        ex = HttpExchange(url=f"{base}{path}", method="GET", request_headers={}, request_body="")
        try:
            res = await validator.validate(_finding(name), ex)
            mark = "CONFIRMED" if res.confirmed else res.status.upper()
            print(f"  {name:16s} {mark:14s} {res.summary}")
        except Exception as e:  # noqa: BLE001
            print(f"  {name:16s} ERROR          {e!r}")


def main():
    global_throttle.configure(0)
    safety_gate.reset_default_gate()
    safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})
    app = make_app()
    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{base}/health", timeout=0.5).read()
            break
        except OSError:
            time.sleep(0.05)
    print(f"leg-verification fixture on {base}")
    try:
        asyncio.run(_run_all(base))
    finally:
        server.shutdown()
        t.join(timeout=5.0)


if __name__ == "__main__":
    main()
