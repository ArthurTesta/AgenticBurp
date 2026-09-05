"""
Live leg-verification (Phase 2) -- REAL, not stubbed.

Stands up the disposable vulnerable fixture on a real localhost socket and runs
the in-band confirmation legs against it with genuine HTTP (real httpx inside the
leg, a real Flask app answering). Unlike the per-leg smoke tests -- which stub the
network at httpx and assert only the decision logic -- this proves the whole leg
path bites on a real true-positive and stays silent on a matched negative control.

Scope: the legs that need no external OOB collaborator or browser -- SSTI and
open redirect (both portable). Path traversal, XXE/SSRF/command-injection (OOB
collaborator) and browser_xss (a real browser) need external infra and are driven
by testing/leg-verification/run_leg_verification.py, run live by the operator.

Hermetic and self-contained: the only "network" is loopback to a server this test
owns; it is torn down in tearDown.
"""
import asyncio
import importlib.util
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from werkzeug.serving import make_server

import global_throttle
import safety_gate
from models import Finding, HttpExchange
from validators.ssti_validator import SstiValidator
from validators.open_redirect_validator import OpenRedirectValidator

_FIXTURE = (Path(__file__).resolve().parent.parent
            / "testing" / "leg-verification" / "vuln_fixture.py")


def _load_make_app():
    spec = importlib.util.spec_from_file_location("vuln_fixture", _FIXTURE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_app


def _finding(vc):
    return Finding(vulnerability_class=vc, confidence=0.5, severity="high",
                   summary=f"{vc} hypothesis", evidence="", suggested_test="", basis="derived")


class LiveLegVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)  # quiet per-request logs
        global_throttle.configure(0)
        app = _load_make_app()()
        cls._server = make_server("127.0.0.1", 0, app, threaded=True)
        cls._port = cls._server.server_address[1]
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()
        cls._base = f"http://127.0.0.1:{cls._port}"
        # Wait until the server actually answers before running any leg.
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"{cls._base}/health", timeout=0.5).read()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("leg-verification fixture did not come up")
        safety_gate.reset_default_gate()
        safety_gate.get_default_gate({"active_enabled": True, "allow_mutating_replay": True})

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        cls._thread.join(timeout=5.0)
        safety_gate.reset_default_gate()

    def _run(self, validator, path):
        ex = HttpExchange(url=f"{self._base}{path}", method="GET",
                          request_headers={}, request_body="")
        fc = next(iter(validator.finding_classes))
        return asyncio.run(validator.validate(_finding(fc), ex))

    # --- SSTI -----------------------------------------------------------------
    def test_ssti_confirms_on_real_template_render(self):
        v = SstiValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/ssti/render?q=seed")
        self.assertEqual(res.status, "confirmed",
                         f"SSTI leg did not confirm against a real Jinja render endpoint: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_ssti_silent_on_escaped_echo_control(self):
        v = SstiValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/ssti/echo?q=seed")
        self.assertNotEqual(res.status, "confirmed")

    # --- Open redirect --------------------------------------------------------
    def test_open_redirect_confirms_on_blind_redirect(self):
        v = OpenRedirectValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/redirect/open?url=/seed")
        self.assertEqual(res.status, "confirmed",
                         f"open-redirect leg did not confirm against a real blind redirect: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_open_redirect_silent_on_fixed_target_control(self):
        v = OpenRedirectValidator(allowed_hosts=["127.0.0.1"])
        res = self._run(v, "/redirect/safe?url=/seed")
        self.assertNotEqual(res.status, "confirmed")


if __name__ == "__main__":
    unittest.main()
