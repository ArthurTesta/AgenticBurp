"""Tests for the TOCTOU privilege-escalation race leg (V19), with mocked GET
reads and a mocked concurrent burst. The distinguishing oracle: a privileged
field flips ONLY under concurrency (>=2 clean successes) + an independent re-read."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch, MagicMock

from models import Finding, HttpExchange
from safety_gate import get_default_gate, reset_default_gate
from validators.toctou_validator import ToctouValidator


def _finding(vc="toctou"):
    return Finding(vulnerability_class=vc, severity="high", confidence=0.6,
                   summary="t", evidence="t", suggested_test="t", basis="derived")


def _ex(url="http://target.test/api/account/role", method="POST",
        body='{"name":"alice"}', headers=None):
    return HttpExchange(url=url, method=method, request_body=body,
                        request_headers=headers or {"Content-Type": "application/json"},
                        response_status=200, response_body="")


def _resp(status=200, text="ok"):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


class ToctouTests(unittest.TestCase):
    def setUp(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True,
                          "max_burst_size": 12})

    def tearDown(self):
        reset_default_gate()

    def test_skip_on_get(self):
        v = ToctouValidator(allowed_hosts=["target.test"])
        self.assertFalse(v.applies(_finding(), _ex(method="GET")))

    def test_skip_out_of_scope(self):
        v = ToctouValidator(allowed_hosts=["target.test"])
        r = asyncio.run(v.validate(_finding(), _ex(url="http://evil.test/x")))
        self.assertEqual(r.status, "skipped")

    def test_skip_when_burst_ceiling_below_two(self):
        reset_default_gate()
        get_default_gate({"active_enabled": True, "allow_mutating_replay": True, "max_burst_size": 1})
        v = ToctouValidator(allowed_hosts=["target.test"])
        # baseline read must return JSON with a non-privileged authority field
        with patch.object(v, "_get_json", new=AsyncMock(return_value=(200, {"role": "user"}))):
            r = asyncio.run(v.validate(_finding(), _ex()))
        self.assertEqual(r.status, "skipped")
        self.assertIn("max_burst_size", r.summary)

    @patch("validators.toctou_validator.httpx.AsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_confirms_when_field_flips_under_concurrency(self, _t, mock_cls):
        v = ToctouValidator(allowed_hosts=["target.test"], burst_size=4)
        reads = iter([(200, {"role": "user"}),      # baseline: not privileged
                      (200, {"role": "admin"})])    # verify: flipped
        # burst client: every concurrent request returns a clean 200
        client = AsyncMock()
        client.request = AsyncMock(return_value=_resp(200, "ok"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        with patch.object(v, "_get_json", new=AsyncMock(side_effect=lambda *a, **k: next(reads))):
            r = asyncio.run(v.validate(_finding(), _ex()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertIn("role", r.summary)

    @patch("validators.toctou_validator.httpx.AsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_single_success_is_mass_assign_not_race(self, _t, mock_cls):
        # field flips, but only ONE concurrent request succeeds cleanly (rest
        # rejected) -> that's mass-assignment (sequence's case), not a race.
        v = ToctouValidator(allowed_hosts=["target.test"], burst_size=4)
        reads = iter([(200, {"role": "user"}), (200, {"role": "admin"})])
        calls = {"n": 0}

        async def _req(*a, **k):
            calls["n"] += 1
            return _resp(200, "ok") if calls["n"] == 1 else _resp(409, "already applied")
        client = AsyncMock()
        client.request = _req
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        with patch.object(v, "_get_json", new=AsyncMock(side_effect=lambda *a, **k: next(reads))):
            r = asyncio.run(v.validate(_finding(), _ex()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertIn("mass-assignment", r.summary)

    @patch("validators.toctou_validator.httpx.AsyncClient")
    @patch("global_throttle.acquire", new_callable=AsyncMock)
    def test_not_confirmed_when_no_flip(self, _t, mock_cls):
        v = ToctouValidator(allowed_hosts=["target.test"], burst_size=4)
        reads = iter([(200, {"role": "user"}), (200, {"role": "user"})])  # never flips
        client = AsyncMock()
        client.request = AsyncMock(return_value=_resp(200, "ok"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock()
        mock_cls.return_value = client
        with patch.object(v, "_get_json", new=AsyncMock(side_effect=lambda *a, **k: next(reads))):
            r = asyncio.run(v.validate(_finding(), _ex()))
        self.assertEqual(r.status, "not_confirmed")

    def test_registered_and_active(self):
        from validators.registry import ValidatorRegistry
        reg = ValidatorRegistry({"validators": {"active_enabled": True}})
        self.assertIn("toctou", reg.validators)
        self.assertTrue(reg.validators["toctou"].active)


if __name__ == "__main__":
    unittest.main()
