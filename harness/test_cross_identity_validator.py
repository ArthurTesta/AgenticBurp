"""
Unit tests for the cross-identity (Autorize-style) access-control validator.

No live target: the _probe seam is replaced with a canned responder that returns
a (status, body) per request headers, so the identity_compare decision logic is
exercised end-to-end deterministically.
"""
import asyncio
import unittest

import identity_headers
import identity_compare
from validators.cross_identity_validator import CrossIdentityValidator
from models import Finding, HttpExchange


def _finding(cls="insecure_direct_object_reference"):
    return Finding(vulnerability_class=cls, confidence=0.9, summary="s", evidence="e",
                   suggested_test="t", basis="derived", severity="high")


def _exchange(method="GET", url="http://localhost/api/tickets/1", status=200, body="OWNER-SECRET-DATA-12345"):
    return HttpExchange(url=url, method=method, request_headers={}, request_body="",
                        response_status=status, response_headers={}, response_body=body)


class _StubbedValidator(CrossIdentityValidator):
    """Replaces the live probe with a canned responder(headers) -> (status, body)."""
    def __init__(self, responder, **kw):
        super().__init__(**kw)
        self._responder = responder

    async def _probe(self, url, headers):
        status, body = self._responder(headers)
        return identity_compare.Probe(status, body)


class CrossIdentityValidatorTest(unittest.TestCase):
    def setUp(self):
        identity_headers.clear()

    def tearDown(self):
        identity_headers.clear()

    def test_confirms_real_idor(self):
        # bob (another identity) reaches the owner's protected data; anon is denied.
        identity_headers.set_identity("localhost", "bob", {"Authorization": "Bearer bob"})

        def responder(headers):
            if headers.get("Authorization") == "Bearer bob":
                return (200, "OWNER-SECRET-DATA-12345")   # bob sees the owner's data
            return (403, "Forbidden")                     # anon denied

        v = _StubbedValidator(responder, allowed_hosts=["localhost"])
        r = asyncio.run(v.validate(_finding(), _exchange()))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertIn("bob", r.summary)

    def test_rejects_secure_endpoint(self):
        # Every other identity AND anon are denied -> the control held.
        identity_headers.set_identity("localhost", "bob", {"Authorization": "Bearer bob"})

        def responder(headers):
            return (403, "Forbidden")

        v = _StubbedValidator(responder, allowed_hosts=["localhost"])
        r = asyncio.run(v.validate(_finding(), _exchange()))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)

    def test_skips_without_identities(self):
        v = _StubbedValidator(lambda h: (200, "x"), allowed_hosts=["localhost"])
        r = asyncio.run(v.validate(_finding(), _exchange()))
        self.assertEqual(r.status, "skipped")

    def test_skips_non_get(self):
        identity_headers.set_identity("localhost", "bob", {"Authorization": "Bearer bob"})
        v = _StubbedValidator(lambda h: (200, "x"), allowed_hosts=["localhost"])
        r = asyncio.run(v.validate(_finding(), _exchange(method="POST")))
        self.assertEqual(r.status, "skipped")

    def test_skips_out_of_scope(self):
        identity_headers.set_identity("evil.example", "bob", {"Authorization": "Bearer bob"})
        v = _StubbedValidator(lambda h: (200, "x"), allowed_hosts=["localhost"])
        r = asyncio.run(v.validate(_finding(), _exchange(url="http://evil.example/api/tickets/1")))
        self.assertEqual(r.status, "skipped")

    def test_only_applies_to_access_control_classes(self):
        v = _StubbedValidator(lambda h: (200, "x"), allowed_hosts=["localhost"])
        self.assertTrue(v.applies(_finding("insecure_direct_object_reference"), _exchange()))
        self.assertTrue(v.applies(_finding("Broken Access Control"), _exchange()))
        self.assertFalse(v.applies(_finding("sql_injection"), _exchange()))


if __name__ == "__main__":
    unittest.main()
