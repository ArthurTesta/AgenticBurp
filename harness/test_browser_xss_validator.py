"""Tests for the browser-driven XSS validator (A2), using a fake driver."""
import asyncio
import re
import unittest

import global_throttle
import browser_driver
from browser_driver import ExecutionObservation
from models import Finding, HttpExchange
from validators.browser_xss_validator import BrowserXssValidator

_NONCE = re.compile(r"HARNESSXSS[0-9a-f]+")


class _VulnDriver:
    """Simulates a page that EXECUTES a reflected payload: whatever nonce shows
    up in the URL's payload is echoed into the console (as real execution would).
    `sink` picks which execution channel carries it."""
    def __init__(self, sink="console"):
        self.sink = sink
        self.visited = []

    async def visit(self, url, *, wait_ms=1500):
        self.visited.append(url)
        obs = ExecutionObservation(url=url)
        m = _NONCE.search(url)
        if m:
            getattr(obs, self.sink).append(f"fired {m.group(0)}")
        return obs


class _SafeDriver:
    """Simulates a page that reflects nothing executable -- empty sinks."""
    def __init__(self):
        self.visited = []

    async def visit(self, url, *, wait_ms=1500):
        self.visited.append(url)
        return ExecutionObservation(url=url)


class _BrokenDriver:
    async def visit(self, url, *, wait_ms=1500):
        return ExecutionObservation(url=url, load_error="Timeout")


def _finding():
    return Finding(vulnerability_class="xss", confidence=0.6, summary="reflected xss on q",
                   evidence="e", suggested_test="t", basis="derived")


def _exchange(url="https://shop.test/search?q=hello&lang=en"):
    return HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                        response_status=200, response_headers={}, response_body="")


class BrowserXssValidatorTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def _validate(self, driver, exchange=None, **kw):
        v = BrowserXssValidator(allowed_hosts=["shop.test"], driver=driver, **kw)
        return asyncio.run(v.validate(_finding(), exchange or _exchange()))

    def test_confirms_on_console_execution(self):
        r = self._validate(_VulnDriver("console"))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertIn("console", r.evidence)

    def test_confirms_on_dialog_execution(self):
        r = self._validate(_VulnDriver("dialogs"))
        self.assertEqual(r.status, "confirmed")
        self.assertIn("dialog", r.evidence)

    def test_not_confirmed_when_nothing_executes(self):
        r = self._validate(_SafeDriver())
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)

    def test_nonce_prevents_false_positive(self):
        # A page that echoes a DIFFERENT nonce-shaped string must not confirm.
        class _WrongNonce:
            async def visit(self, url, *, wait_ms=1500):
                return ExecutionObservation(url=url, console=["HARNESSXSSdeadbeefdeadbeef"])
        r = self._validate(_WrongNonce())
        self.assertEqual(r.status, "not_confirmed")

    def test_out_of_scope_skips(self):
        r = self._validate(_VulnDriver(), exchange=_exchange("https://evil.test/x?q=1"))
        self.assertEqual(r.status, "skipped")
        self.assertIn("scope", r.summary)

    def test_no_driver_available_skips(self):
        # Force default_driver() to return None (no engine installed).
        orig = browser_driver.default_driver
        browser_driver.default_driver = lambda: None
        try:
            v = BrowserXssValidator(allowed_hosts=["shop.test"], driver=None)
            r = asyncio.run(v.validate(_finding(), _exchange()))
        finally:
            browser_driver.default_driver = orig
        self.assertEqual(r.status, "skipped")
        self.assertIn("install", r.evidence)

    def test_all_visits_error_is_error_status(self):
        r = self._validate(_BrokenDriver())
        self.assertEqual(r.status, "error")

    def test_visits_are_bounded_by_max_visits(self):
        driver = _SafeDriver()
        self._validate(driver, max_visits=3)
        self.assertLessEqual(len(driver.visited), 3)

    def test_no_query_params_uses_synthetic_q(self):
        driver = _VulnDriver()
        r = self._validate(driver, exchange=_exchange("https://shop.test/page"))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(all("q=" in u for u in driver.visited))

    def test_applies_to_xss_finding(self):
        v = BrowserXssValidator()
        self.assertTrue(v.applies(_finding(), _exchange()))


class BrowserDriverAvailabilityTests(unittest.TestCase):
    def test_available_reports_reason(self):
        ok, reason = browser_driver.available()
        self.assertIsInstance(ok, bool)
        self.assertTrue(reason)
        if not ok:
            self.assertIn("install", reason)


if __name__ == "__main__":
    unittest.main()
