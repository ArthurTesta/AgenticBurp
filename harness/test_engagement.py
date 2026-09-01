"""Tests for the engagement spine (shared surface model + fused rating)."""
import unittest

import engagement
from engagement import EngagementState, SurfaceEndpoint, normalize_path


class NormalizeTests(unittest.TestCase):
    def test_aligns_concrete_and_templated(self):
        self.assertEqual(normalize_path("https://t.test/api/orders/42?x=1"), "/api/orders/{id}")
        self.assertEqual(normalize_path("/api/orders/{id}"), "/api/orders/{id}")

    def test_strips_host_and_query(self):
        self.assertEqual(normalize_path("http://t.test/a/b?c=d#e"), "/a/b")

    def test_long_hex_collapsed(self):
        self.assertEqual(normalize_path("/reset/a1b2c3d4e5f6a7b8"), "/reset/{id}")


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.st = EngagementState(host="shop.test")

    def test_ingest_endpoints(self):
        self.st.ingest_endpoints(["/api/a", "/api/b"])
        self.assertEqual(len(self.st.endpoints), 2)

    def test_ingest_findings_sets_status(self):
        self.st.ingest_findings("http://shop.test/api/x", "GET",
                                [{"vulnerability_class": "xss", "severity": "high", "confidence": 0.7, "confirmed": False}])
        ep = self.st.endpoints["GET /api/x"]
        self.assertEqual(ep.status, "analyzed")
        self.st.ingest_findings("http://shop.test/api/x", "GET",
                                [{"vulnerability_class": "xss", "severity": "high", "confidence": 0.9, "confirmed": True}])
        self.assertEqual(self.st.endpoints["GET /api/x"].status, "validated")

    def test_add_finding_dedup_supersede(self):
        ep = SurfaceEndpoint("GET", "/x")
        ep.add_finding({"vulnerability_class": "sqli", "severity": "high", "confidence": 0.5, "confirmed": False})
        ep.add_finding({"vulnerability_class": "sqli", "severity": "high", "confidence": 0.9, "confirmed": True})
        self.assertEqual(len(ep.findings), 1)
        self.assertTrue(ep.findings[0]["confirmed"])

    def test_ingest_role_crawl_matrix_and_idor(self):
        result = {
            "endpoints": [{"method": "GET", "path": "/api/orders/{id}", "by_role": {"user": 200},
                           "reachable_roles": ["user"], "object_scoped": True}],
            "idor_findings": [{"vulnerability_class": "idor", "severity": "high", "confidence": 0.65,
                               "confirmed": False, "validation_hints": ["cross_identity_compare:/api/orders/{id}"]}],
        }
        self.st.ingest_role_crawl(result)
        ep = self.st.endpoints["GET /api/orders/{id}"]
        self.assertTrue(ep.object_scoped)
        self.assertIn("user", ep.reachable_roles)
        self.assertTrue(any(f["vulnerability_class"] == "idor" for f in ep.findings))

    def test_ingest_prioritization(self):
        self.st.ingest_endpoints(["/api/x"])
        self.st.ingest_prioritization([{"method": "GET", "url": "http://shop.test/api/x",
                                        "ai_priority": "high", "ai_score": 0.8}])
        self.assertEqual(self.st.endpoints["GET /api/x"].llm_score, 0.8)


class FusionTests(unittest.TestCase):
    def test_anonymous_reaching_admin_ranks_high(self):
        st = EngagementState(host="shop.test")
        st.ingest_role_crawl({"endpoints": [
            {"method": "GET", "path": "/rest/admin/config", "by_role": {"anonymous": 200},
             "reachable_roles": ["anonymous"], "object_scoped": False},
            {"method": "GET", "path": "/api/public", "by_role": {"anonymous": 200},
             "reachable_roles": ["anonymous"], "object_scoped": False}]})
        wl = st.worklist()
        self.assertEqual(wl[0]["path"], "/rest/admin/config")
        self.assertTrue(any("privileged" in r for r in wl[0]["reasons"]))

    def test_confirmed_finding_outranks_bare_endpoint(self):
        st = EngagementState(host="shop.test")
        st.ingest_endpoints(["/api/plain"])
        st.ingest_findings("http://shop.test/api/hit", "GET",
                           [{"vulnerability_class": "sqli", "severity": "critical", "confidence": 0.9, "confirmed": True}])
        wl = st.worklist()
        self.assertEqual(wl[0]["path"], "/api/hit")

    def test_validated_is_deprioritized(self):
        st = EngagementState(host="shop.test")
        # two identical-severity findings; one validated, one still a hypothesis
        st.ingest_findings("http://shop.test/api/done", "GET",
                           [{"vulnerability_class": "xss", "severity": "high", "confidence": 0.9, "confirmed": True}])
        st.ingest_findings("http://shop.test/api/open", "GET",
                           [{"vulnerability_class": "xss", "severity": "high", "confidence": 0.9, "confirmed": False}])
        scores = {e["path"]: e["score"] for e in st.worklist()}
        self.assertLess(scores["/api/done"], scores["/api/open"])

    def test_llm_score_contributes(self):
        st = EngagementState(host="shop.test")
        st.ingest_endpoints(["/api/rated", "/api/unrated"])
        st.ingest_prioritization([{"method": "GET", "url": "http://shop.test/api/rated",
                                   "ai_priority": "critical", "ai_score": 0.95}])
        wl = st.worklist()
        self.assertEqual(wl[0]["path"], "/api/rated")

    def test_roundtrip(self):
        st = EngagementState(host="shop.test")
        st.ingest_endpoints(["/a"])
        st.ingest_findings("http://shop.test/a", "GET",
                           [{"vulnerability_class": "idor", "severity": "high", "confidence": 0.6, "confirmed": False}])
        st.ingest_identity("admin", "admin", source="seed")
        st2 = EngagementState.from_dict(st.to_dict())
        self.assertEqual(len(st2.endpoints), 1)
        self.assertEqual(st2.identities, st.identities)
        self.assertEqual(st2.endpoints["GET /a"].findings, st.endpoints["GET /a"].findings)


class CapabilityTests(unittest.TestCase):
    def test_extract_jwt_from_body(self):
        cred = engagement._extract_credential({}, 'x eyJhbGciOiJI.eyJzdWIiOiIx.sigABC1234567 y')
        self.assertEqual(cred["kind"], "bearer")
        self.assertIn("Authorization", cred["headers"])

    def test_extract_session_cookie(self):
        cred = engagement._extract_credential({"Set-Cookie": "session=abc123def; Path=/"}, "")
        self.assertEqual(cred["kind"], "cookie")
        self.assertIn("session=abc123def", cred["headers"]["Cookie"])

    def test_extract_json_token(self):
        cred = engagement._extract_credential({}, '{"access_token":"longtokenvalue12345"}')
        self.assertEqual(cred["kind"], "bearer")

    def test_no_credential(self):
        self.assertIsNone(engagement._extract_credential({}, '{"status":"ok"}'))

    def test_credential_capability_from_auth_finding(self):
        f = {"vulnerability_class": "auth", "confidence": 0.8, "confirmed": True}
        caps = engagement.detect_capabilities(f, {"Set-Cookie": "sid=abc123def"}, "", "http://t/login")
        self.assertTrue(any(c["type"] == "credential" for c in caps))

    def test_reachable_area_from_idor(self):
        f = {"vulnerability_class": "idor", "confidence": 0.7, "confirmed": True}
        caps = engagement.detect_capabilities(f, {}, "", "http://t/api/orders/1")
        self.assertTrue(any(c["type"] == "reachable_area" for c in caps))

    def test_apply_credential_registers_identity_and_queues_no_secret(self):
        st = EngagementState(host="t")
        caps = [{"type": "credential", "kind": "bearer",
                 "headers": {"Authorization": "Bearer SECRET"}, "source_url": "http://t/login",
                 "reason": "learned"}]
        cred_caps = st.apply_capabilities(caps, "http://t/login")
        self.assertEqual(len(cred_caps), 1)  # returned for in-process use
        self.assertTrue(any(i["source"] == "finding" for i in st.identities))
        # the queued action + persisted state must NOT contain the secret
        blob = str(st.to_dict())
        self.assertNotIn("SECRET", blob)
        self.assertTrue(any(a["kind"] == "recrawl_as_derived" for a in st.pending()))

    def test_apply_reachable_area_queues_action(self):
        st = EngagementState(host="t")
        caps = [{"type": "reachable_area", "area": "/rest/admin", "source_url": "http://t/rest/admin",
                 "reason": "broken access"}]
        st.apply_capabilities(caps, "http://t/rest/admin")
        self.assertTrue(any(a["kind"] == "recrawl_area" and a["target"] == "/rest/admin"
                            for a in st.pending()))

    def test_enqueue_dedups(self):
        st = EngagementState(host="t")
        st.enqueue_action("recrawl_area", "/x", "r1")
        st.enqueue_action("recrawl_area", "/x", "r2")
        self.assertEqual(len(st.pending()), 1)

    def test_resolve_action(self):
        st = EngagementState(host="t")
        st.enqueue_action("recrawl_area", "/x", "r")
        st.resolve_action("recrawl_area", "/x")
        self.assertEqual(st.pending(), [])

    def test_pending_actions_roundtrip(self):
        st = EngagementState(host="t")
        st.enqueue_action("recrawl_area", "/x", "r")
        st2 = EngagementState.from_dict(st.to_dict())
        self.assertEqual(len(st2.pending()), 1)


class StoreAndEndpointTests(unittest.TestCase):
    def setUp(self):
        import tempfile, store
        from pathlib import Path
        self.tmp = tempfile.TemporaryDirectory()
        self.orig = store._DB_PATH
        store._DB_PATH = Path(self.tmp.name) / "t.db"
        self.store = store

    def tearDown(self):
        self.store._DB_PATH = self.orig
        self.tmp.cleanup()

    def test_save_load_roundtrip(self):
        st = EngagementState(host="shop.test")
        st.ingest_endpoints(["/a", "/b"])
        self.store.save_engagement("shop.test", st.to_dict())
        loaded = self.store.load_engagement("shop.test")
        self.assertEqual(len(loaded["endpoints"]), 2)

    def test_load_missing_is_none(self):
        self.assertIsNone(self.store.load_engagement("nope.test"))

    def test_engagement_endpoint(self):
        import server as server_module
        from fastapi.testclient import TestClient
        client = TestClient(server_module.app)
        st = EngagementState(host="shop.test")
        st.ingest_role_crawl({"endpoints": [
            {"method": "GET", "path": "/rest/admin", "by_role": {"anonymous": 200},
             "reachable_roles": ["anonymous"], "object_scoped": False}]})
        self.store.save_engagement("shop.test", st.to_dict())
        resp = client.get("/engagement/shop.test")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["worklist"])
        self.assertEqual(body["worklist"][0]["path"], "/rest/admin")


if __name__ == "__main__":
    unittest.main()
