"""Tests for role-aware crawl -> access matrix (mocked network)."""
import asyncio
import unittest
from unittest.mock import patch

import global_throttle
import role_crawl
from role_crawl import RoleSession


class _Resp:
    def __init__(self, status, text):
        self.status_code, self.text = status, text


def _auth_of(headers):
    return (headers or {}).get("Authorization", "")


def _fake_crawl(endpoints):
    async def fake(base_url, headers=None, allowed_hosts=None, max_pages=40, max_depth=2, timeout=15.0):
        from crawler import CrawlResult
        r = CrawlResult(base_url=base_url)
        r.endpoints = set(endpoints)
        return r
    return fake


def _fake_probe(matrix):
    """matrix: (path) -> function(authHeader) -> (status, body)."""
    async def fake_request(self, method, url, headers=None):
        # recover the path key from the url
        from urllib.parse import urlsplit
        path = urlsplit(url).path
        # map concrete id back to {id} for lookup convenience
        key = path
        fn = matrix.get(key)
        if fn is None:
            return _Resp(404, "")
        status, body = fn(_auth_of(headers))
        return _Resp(status, body)
    return fake_request


class RoleCrawlTests(unittest.TestCase):
    def setUp(self):
        global_throttle.configure(0)

    def _run(self, endpoints, matrix, roles, **kw):
        kw.setdefault("allowed_hosts", ["shop.test"])
        with patch("crawler.crawl", _fake_crawl(endpoints)), \
             patch("httpx.AsyncClient.request", _fake_probe(matrix)):
            return asyncio.run(role_crawl.crawl_roles("http://shop.test/", roles, **kw))

    def test_auth_bypass_when_anonymous_reaches(self):
        roles = [RoleSession("anonymous", {}), RoleSession("admin", {"Authorization": "Bearer admintok"})]
        # /api/report returns data to everyone incl. anonymous
        matrix = {"/api/report": lambda auth: (200, '{"secret":1}')}
        r = self._run(["/api/report"], matrix, roles)
        self.assertTrue(any(c["class"] == "missing_authentication" for c in r.auth_bypass_candidates))
        access = r.endpoints[0]
        self.assertIn("anonymous", access.reachable_roles)
        self.assertIn("admin", access.reachable_roles)

    def test_no_bypass_when_anonymous_blocked(self):
        roles = [RoleSession("anonymous", {}), RoleSession("admin", {"Authorization": "Bearer admintok"})]
        matrix = {"/api/report": lambda auth: (200, '{"secret":1}') if auth else (401, "no")}
        r = self._run(["/api/report"], matrix, roles)
        self.assertFalse(any(c["class"] == "missing_authentication" for c in r.auth_bypass_candidates))
        self.assertEqual(r.endpoints[0].reachable_roles, ["admin"])

    def test_idor_candidate_for_object_scoped(self):
        roles = [RoleSession("user", {"Authorization": "Bearer u"}),
                 RoleSession("admin", {"Authorization": "Bearer a"})]
        # /api/orders/{id} -> concrete /api/orders/1, reachable by authed roles
        matrix = {"/api/orders/1": lambda auth: (200, '{"order":1}') if auth else (401, "")}
        r = self._run(["/api/orders/{id}"], matrix, roles)
        self.assertTrue(any(c["class"] == "idor" for c in r.idor_candidates))
        self.assertEqual(r.idor_candidates[0]["path"], "/api/orders/{id}")

    def test_no_idor_for_non_object_scoped(self):
        roles = [RoleSession("user", {"Authorization": "Bearer u"})]
        matrix = {"/api/profile": lambda auth: (200, '{"me":1}')}
        r = self._run(["/api/profile"], matrix, roles)
        self.assertEqual(r.idor_candidates, [])

    def test_authz_inverted_privilege_direction(self):
        # user reaches /admin/panel but admin does not (inverted) -> authz candidate.
        roles = [RoleSession("user", {"Authorization": "Bearer u"}),
                 RoleSession("admin", {"Authorization": "Bearer a"})]
        matrix = {"/admin/panel": lambda auth: (200, "panel") if auth == "Bearer u" else (403, "no")}
        r = self._run(["/admin/panel"], matrix, roles)
        self.assertTrue(any(c["class"] == "authz" for c in r.auth_bypass_candidates))

    def test_access_matrix_records_all_roles(self):
        roles = [RoleSession("anonymous", {}), RoleSession("user", {"Authorization": "Bearer u"})]
        matrix = {"/x": lambda auth: (200, "d") if auth else (401, "")}
        r = self._run(["/x"], matrix, roles)
        by = r.endpoints[0].by_role
        self.assertEqual(by["anonymous"], 401)
        self.assertEqual(by["user"], 200)

    def test_empty_roles_errors(self):
        with patch("crawler.crawl", _fake_crawl([])):
            r = asyncio.run(role_crawl.crawl_roles("http://shop.test/", [], allowed_hosts=["shop.test"]))
        self.assertTrue(any("no roles" in e for e in r.errors))

    def test_max_endpoints_bounds_probing(self):
        roles = [RoleSession("user", {"Authorization": "Bearer u"})]
        endpoints = [f"/api/e{i}" for i in range(20)]
        matrix = {f"/api/e{i}": (lambda auth: (200, "d")) for i in range(20)}
        r = self._run(endpoints, matrix, roles, max_endpoints=5)
        self.assertLessEqual(len(r.endpoints), 5)
        self.assertTrue(any("truncated" in e for e in r.errors))


class RoleCrawlEndpointTests(unittest.TestCase):
    def setUp(self):
        import server as server_module
        self.server_module = server_module
        server_module.orchestrator.allowed_hosts = ["shop.test"]
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def test_endpoint_runs(self):
        with patch("crawler.crawl", _fake_crawl(["/api/report"])), \
             patch("httpx.AsyncClient.request", _fake_probe({"/api/report": lambda a: (200, '{"x":1}')})):
            resp = self.client.post("/crawl-roles", json={
                "base_url": "http://shop.test/",
                "roles": [{"role": "anonymous", "headers": {}},
                          {"role": "admin", "headers": {"Authorization": "Bearer a"}}]})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["endpoint_count"], 1)
        self.assertTrue(body["auth_bypass_candidates"])

    def test_empty_roles_is_400(self):
        resp = self.client.post("/crawl-roles", json={"base_url": "http://shop.test/", "roles": []})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
