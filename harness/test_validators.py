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


if __name__ == "__main__":
    unittest.main()
