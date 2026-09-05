"""
Live leg-verification (Phase 2) -- REAL, not stubbed.

Stands up the disposable vulnerable fixture on a real localhost socket and runs
the in-band confirmation legs against it with genuine HTTP (real httpx inside the
leg, a real Flask app answering). Unlike the per-leg smoke tests -- which stub the
network at httpx and assert only the decision logic -- this proves the whole leg
path bites on a real true-positive and stays silent on a matched negative control.

Scope: SSTI, open redirect, SSRF and mass-assignment (the sequence leg) are all
verified here -- the OOB legs (SSRF, command-injection) reach the real in-process
collaborator, which is itself just a loopback listener. command-injection needs
`curl` on this host to run the injected fetch, so it is skipped when curl is
absent. Path traversal (needs a real system file) and browser_xss (needs a real
browser) stay in testing/leg-verification/run_leg_verification.py, run live by the
operator.

Hermetic and self-contained: the only "network" is loopback -- the fixture server
this test owns, plus the collaborator's loopback listener; the server is torn down
in tearDownClass.
"""
import asyncio
import importlib.util
import shutil
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
from validators.ssrf_validator import SsrfValidator
from validators.sequence_validator import SequenceValidator
from validators.command_injection_validator import CommandInjectionValidator

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

    def _run_ex(self, validator, exchange, fc):
        return asyncio.run(validator.validate(_finding(fc), exchange))

    def _reset_profiles(self):
        urllib.request.urlopen(urllib.request.Request(
            f"{self._base}/account/reset", method="POST"), timeout=2).read()

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

    # --- SSRF (OOB via the real in-process collaborator) ----------------------
    def test_ssrf_confirms_on_real_server_side_fetch(self):
        v = SsrfValidator(allowed_hosts=["127.0.0.1"], timeout=1.0)
        res = self._run(v, "/ssrf/fetch?url=http://example.invalid/x")
        self.assertEqual(res.status, "confirmed",
                         f"SSRF leg did not confirm against a real server-side fetch: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_ssrf_silent_on_no_fetch_control(self):
        v = SsrfValidator(allowed_hosts=["127.0.0.1"], timeout=1.0)
        res = self._run(v, "/ssrf/safe?url=http://example.invalid/x")
        self.assertNotEqual(res.status, "confirmed")

    # --- Sequence / mass assignment (write -> re-read differential) -----------
    def _profile_exchange(self, path):
        return HttpExchange(url=f"{self._base}{path}", method="PATCH",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"name": "alice"}')

    def test_sequence_confirms_on_mass_assignable_write(self):
        self._reset_profiles()
        v = SequenceValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._profile_exchange("/account/profile"), "mass_assignment")
        self.assertEqual(res.status, "confirmed",
                         f"sequence leg did not confirm a real mass-assignable write: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_sequence_silent_on_allowlisted_control(self):
        self._reset_profiles()
        v = SequenceValidator(allowed_hosts=["127.0.0.1"])
        res = self._run_ex(v, self._profile_exchange("/account/profile-safe"), "mass_assignment")
        self.assertNotEqual(res.status, "confirmed")

    # --- Command injection (OOB shell fetch; needs curl on the target) --------
    @unittest.skipIf(shutil.which("curl") is None, "curl not available to exercise the shell payload")
    def test_command_injection_confirms_via_shell(self):
        v = CommandInjectionValidator(allowed_hosts=["127.0.0.1"], timeout=1.0)
        res = self._run(v, "/cmdi/ping?host=seed")
        self.assertEqual(res.status, "confirmed",
                         f"command-injection leg did not confirm against a real shell endpoint: {res.summary}")
        self.assertTrue(res.confirmed)

    def test_command_injection_silent_on_no_shell_control(self):
        v = CommandInjectionValidator(allowed_hosts=["127.0.0.1"], timeout=1.0)
        res = self._run(v, "/cmdi/safe?host=seed")
        self.assertNotEqual(res.status, "confirmed")


if __name__ == "__main__":
    unittest.main()
