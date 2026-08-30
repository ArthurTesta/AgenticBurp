import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from models import Finding, HttpExchange
from validators.sqlmap import SqlmapValidator
from validators.registry import ValidatorRegistry


class FakeProc:
    returncode = 0
    stdout = "[INFO] parameter 'id' appears to be injectable\n[CRITICAL] GET parameter 'id' is vulnerable"
    stderr = ""


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.exchange = HttpExchange(
            url="https://example.test/item?id=7",
            method="GET",
            request_headers={"User-Agent": "test"},
            response_status=200,
            response_body="item",
        )
        self.finding = Finding(
            vulnerability_class="sqli", confidence=0.8, severity="high",
            summary="possible SQL injection in id", evidence="id parameter",
            suggested_test="test id", basis="derived",
        )

    def test_raw_request_uses_captured_exchange_not_model_input(self):
        raw = SqlmapValidator._raw_request(self.exchange)
        self.assertIn("GET /item?id=7 HTTP/1.1", raw)
        self.assertIn("Host: example.test", raw)
        self.assertNotIn("sqlmap", raw)

    def test_registry_keeps_active_validators_off_by_default(self):
        reg = ValidatorRegistry({"validators": {"enabled": True, "active_enabled": False}})
        self.assertEqual(reg.for_finding(self.finding, self.exchange), [])

    def test_sqlmap_confirmation_promotes_only_on_explicit_tool_result(self):
        validator = SqlmapValidator()
        with patch("subprocess.run", return_value=FakeProc()):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertTrue(result.confirmed)
        self.assertEqual(result.status, "confirmed")

    def test_sqlmap_failure_is_not_confirmation(self):
        class NoHit:
            returncode = 0
            stdout = "[INFO] testing parameter id"
            stderr = ""
        validator = SqlmapValidator()
        with patch("subprocess.run", return_value=NoHit()):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertFalse(result.confirmed)
        self.assertEqual(result.status, "not_confirmed")

    def test_timeout_with_bytes_partial_output_does_not_crash(self):
        """
        Regression test for a real bug found live: subprocess.run's
        TimeoutExpired can carry .stdout/.stderr as bytes even when the
        call passed text=True -- confirmed by triggering a genuine
        sqlmap timeout against a real target (a slower, more thorough
        scan legitimately exceeded the configured timeout). The old
        code did `(exc.stdout or "") + "\\n" + (exc.stderr or "")`,
        which crashes with TypeError the moment either side is bytes --
        turning a normal "sqlmap took too long" outcome into an
        unhandled crash instead of the intended graceful error result.
        No prior test exercised this path at all.
        """
        import subprocess
        validator = SqlmapValidator()
        timeout_exc = subprocess.TimeoutExpired(
            cmd=["sqlmap"], timeout=90,
            output=b"[INFO] testing parameter id\npartial output",
            stderr=b"some stderr bytes",
        )
        with patch("subprocess.run", side_effect=timeout_exc):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertEqual(result.status, "error")
        self.assertIn("timed out", result.summary)
        self.assertIn("partial output", result.evidence)
        self.assertIn("some stderr bytes", result.evidence)

    def test_timeout_with_str_partial_output_still_works(self):
        """Companion to the bytes case above -- confirms the fix handles
        the str form too (e.g. a different Python/OS combination that
        does decode consistently), not just bytes."""
        import subprocess
        validator = SqlmapValidator()
        timeout_exc = subprocess.TimeoutExpired(
            cmd=["sqlmap"], timeout=90,
            output="already a str", stderr="also already a str",
        )
        with patch("subprocess.run", side_effect=timeout_exc):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertEqual(result.status, "error")
        self.assertIn("already a str", result.evidence)

    def test_timeout_with_no_partial_output_does_not_crash(self):
        """Edge case: a timeout with no captured output at all (both
        None) must still produce a clean error result, not crash on the
        concatenation."""
        import subprocess
        validator = SqlmapValidator()
        timeout_exc = subprocess.TimeoutExpired(cmd=["sqlmap"], timeout=90)
        with patch("subprocess.run", side_effect=timeout_exc):
            result = asyncio.run(validator.validate(self.finding, self.exchange))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.evidence, "\n")


if __name__ == "__main__":
    unittest.main()
