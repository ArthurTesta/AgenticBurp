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

    def test_skips_token_relative_endpoint(self):
        # /api/users/me has no object identifier to swap -> not an IDOR candidate
        # (the TN3 shared-self-profile false positive). Must skip even though an
        # identity is configured, it's GET, and it's in scope.
        identity_headers.set_identity("localhost", "bob", {"Authorization": "Bearer bob"})
        v = _StubbedValidator(lambda h: (200, "x"), allowed_hosts=["localhost"])
        r = asyncio.run(v.validate(_finding(), _exchange(url="http://localhost/api/users/me")))
        self.assertEqual(r.status, "skipped")
        self.assertIn("object identifier", r.summary)

    def test_has_object_identifier(self):
        from validators.cross_identity_validator import has_object_identifier
        self.assertTrue(has_object_identifier("http://h/api/users/2/profile"))
        self.assertTrue(has_object_identifier("http://h/api/orders/1"))
        self.assertTrue(has_object_identifier("http://h/api/tickets/a1b2c3d4e5f6"))
        self.assertTrue(has_object_identifier("http://h/api/thing?id=5"))
        self.assertFalse(has_object_identifier("http://h/api/users/me"))
        self.assertFalse(has_object_identifier("http://h/api/products"))
        self.assertFalse(has_object_identifier("http://h/dashboard"))

    def test_named_slug_object_identifier(self):
        # Named (non-numeric) object ids after a collection noun: the /users/alice
        # case _ID_SEGMENT can't catch. These ARE swappable objects -> cross-identity
        # should fire.
        from validators.cross_identity_validator import has_object_identifier
        self.assertTrue(has_object_identifier("http://h/users/alice"))
        self.assertTrue(has_object_identifier("http://h/api/v1/tickets/support-42"))
        self.assertTrue(has_object_identifier("http://h/api/users/alice/orders"))
        self.assertTrue(has_object_identifier("http://h/documents/annual-report"))

    def test_named_slug_does_not_reopen_self_profile_fp(self):
        # The conservative guards: a slug after a collection noun is NOT an object
        # id when it's a self-reference, a route verb, or a nested sub-collection.
        # Each of these must stay False or the TN3 (/users/me) false positive class
        # comes back.
        from validators.cross_identity_validator import has_object_identifier
        for url in [
            "http://h/api/users/me",          # self-reference
            "http://h/users/self",            # self-reference
            "http://h/users/search",          # route verb
            "http://h/orders/export",         # route verb
            "http://h/users/new",             # create form
            "http://h/products/reviews",      # nested sub-collection, not an object
            "http://h/api/products",          # bare collection
            "http://h/api/health",            # not a collection at all
            "http://h/settings/profile",      # non-collection prefix + reserved slug
        ]:
            self.assertFalse(has_object_identifier(url), url)

    def test_only_applies_to_access_control_classes(self):
        v = _StubbedValidator(lambda h: (200, "x"), allowed_hosts=["localhost"])
        self.assertTrue(v.applies(_finding("insecure_direct_object_reference"), _exchange()))
        self.assertTrue(v.applies(_finding("Broken Access Control"), _exchange()))
        self.assertFalse(v.applies(_finding("sql_injection"), _exchange()))

    # --- V13: function-level authorization (BFLA) on an admin-namespaced route ---

    def test_confirms_bfla_nonadmin_reaches_admin_function(self):
        # /api/admin/users has NO object id -> the BOLA path skips it; the BFLA
        # branch confirms because a non-admin identity reaches an admin-namespaced
        # function while anon is denied.
        identity_headers.set_identity("localhost", "carol", {"Authorization": "Bearer carol"}, role="user")

        def responder(headers):
            if headers.get("Authorization") == "Bearer carol":
                return (200, "ADMIN USER LIST: alice, bob, carol, dave ...")
            return (401, "Unauthorized")  # anon denied

        v = _StubbedValidator(responder, allowed_hosts=["localhost"])
        ex = _exchange(url="http://localhost/api/admin/users", body="")
        r = asyncio.run(v.validate(_finding("broken_access_control"), ex))
        self.assertEqual(r.status, "confirmed")
        self.assertTrue(r.confirmed)
        self.assertIn("function-level", r.summary.lower())

    def test_bfla_not_confirmed_when_control_holds(self):
        identity_headers.set_identity("localhost", "carol", {"Authorization": "Bearer carol"}, role="user")

        def responder(headers):
            return (403, "Forbidden")  # everyone denied, incl. carol + anon

        v = _StubbedValidator(responder, allowed_hosts=["localhost"])
        ex = _exchange(url="http://localhost/api/admin/users", body="")
        r = asyncio.run(v.validate(_finding("broken_access_control"), ex))
        self.assertEqual(r.status, "not_confirmed")
        self.assertFalse(r.confirmed)

    def test_bfla_skips_when_only_admin_identity(self):
        # an admin reaching an admin function is expected -> can't prove a bypass.
        identity_headers.set_identity("localhost", "root", {"Authorization": "Bearer root"}, role="admin")

        def responder(headers):
            if headers.get("Authorization") == "Bearer root":
                return (200, "ADMIN USER LIST: alice, bob ...")
            return (401, "Unauthorized")

        v = _StubbedValidator(responder, allowed_hosts=["localhost"])
        ex = _exchange(url="http://localhost/api/admin/users", body="")
        r = asyncio.run(v.validate(_finding("broken_access_control"), ex))
        self.assertEqual(r.status, "skipped")

    def test_bfla_anon_reachable_is_missing_auth_not_bfla(self):
        identity_headers.set_identity("localhost", "carol", {"Authorization": "Bearer carol"}, role="user")

        def responder(headers):
            return (200, "ADMIN USER LIST served to everyone including anon ...")

        v = _StubbedValidator(responder, allowed_hosts=["localhost"])
        ex = _exchange(url="http://localhost/api/admin/panel", body="")
        r = asyncio.run(v.validate(_finding("broken_access_control"), ex))
        self.assertEqual(r.status, "skipped")
        self.assertIn("anon", r.summary.lower())


if __name__ == "__main__":
    unittest.main()
