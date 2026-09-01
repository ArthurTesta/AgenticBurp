"""
HTTP-level tests for server.py's finding-suppression endpoints, using
FastAPI's TestClient for a real request/response cycle rather than
calling store.py functions directly (those are covered separately in
test_store.py::TestFindingSuppression). No test file previously
exercised server.py's endpoints via TestClient at all -- this is the
first one, scoped to the new suppression endpoints since those are what
this session added; it isn't a full endpoint audit of server.py.
"""
import tempfile
import unittest
from pathlib import Path

import store
from models import HttpExchange, Finding


class SuppressionEndpointTests(unittest.TestCase):
    def setUp(self):
        # Isolated temp DB, same pattern as test_store.py and
        # test_report_generator.py -- never touch the real
        # harness_state.db from a test run.
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        # Imported after the DB path is patched and inside setUp (not at
        # module level) so server.py's own module-level Orchestrator
        # construction doesn't happen until the test DB is already in
        # place, and so re-importing per test doesn't accumulate state
        # across tests via Python's module cache.
        import importlib
        import server as server_module
        importlib.reload(server_module)
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _persist_and_get_fingerprint(self, url="https://example.com/x") -> str:
        exchange = HttpExchange(url=url, method="GET", request_headers={}, request_body="",
                                 response_status=200, response_headers={}, response_body="")
        finding = Finding(vulnerability_class="sqli", confidence=0.8, summary="s",
                           evidence="e", suggested_test="t", basis="derived")
        store.persist_findings(exchange, "test_agent", [finding])
        results = store.all_host_findings(url, include_suppressed=True)
        return results[0]["fingerprint"]

    def test_suppress_finding_via_post(self):
        fp = self._persist_and_get_fingerprint()
        response = self.client.post("/findings/suppress", json={"fingerprint": fp, "reason": "false positive"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["suppressed"])
        self.assertTrue(store.is_suppressed(fp))

    def test_suppressed_finding_excluded_from_subsequent_all_host_findings(self):
        fp = self._persist_and_get_fingerprint()
        self.client.post("/findings/suppress", json={"fingerprint": fp, "reason": "fp"})
        results = store.all_host_findings("https://example.com/x")
        self.assertEqual(len(results), 0)

    def test_list_suppressions_via_get(self):
        fp = self._persist_and_get_fingerprint()
        self.client.post("/findings/suppress", json={"fingerprint": fp, "reason": "noise"})
        response = self.client.get("/findings/suppressions")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["fingerprint"], fp)
        self.assertEqual(body[0]["reason"], "noise")

    def test_unsuppress_via_delete(self):
        fp = self._persist_and_get_fingerprint()
        self.client.post("/findings/suppress", json={"fingerprint": fp})
        response = self.client.delete(f"/findings/suppress/{fp}")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(store.is_suppressed(fp))

    def test_unsuppress_unknown_fingerprint_is_404(self):
        response = self.client.delete("/findings/suppress/not-a-real-fingerprint")
        self.assertEqual(response.status_code, 404)

    def test_suppress_missing_fingerprint_field_is_422(self):
        # Pydantic request validation -- confirms the endpoint actually
        # requires the field rather than silently accepting a partial body.
        response = self.client.post("/findings/suppress", json={"reason": "no fingerprint given"})
        self.assertEqual(response.status_code, 422)


class PrioritizeEndpointTests(unittest.TestCase):
    """HTTP-level coverage for POST /prioritize -- the wiring/chunking
    logic itself (surface_prioritizer.prioritize is mocked out here; its
    own batching/index-matching logic is covered by
    test_surface_prioritizer.py)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        import importlib
        import server as server_module
        importlib.reload(server_module)
        self.server_module = server_module
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def test_empty_items_returns_empty_results_without_calling_prioritizer(self):
        from unittest.mock import AsyncMock, patch
        with patch.object(self.server_module, "surface_prioritizer") as mock_mod:
            mock_mod.prioritize = AsyncMock()
            response = self.client.post("/prioritize", json={"items": []})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"results": []})
        mock_mod.prioritize.assert_not_called()

    def test_items_are_chunked_by_max_items_per_call(self):
        from unittest.mock import AsyncMock, patch

        self.server_module.config["surface_prioritization"] = {
            "enabled": True, "max_items_per_call": 2, "model": "m", "temperature": 0.1,
        }
        items = [{"method": "GET", "url": f"https://x.test/{i}", "param_names": []} for i in range(5)]

        async def side_effect(chunk, ollama, model, temperature):
            return [self.server_module.PrioritizeResultItem(
                method=it.method, url=it.url, ai_priority="medium", ai_score=0.5, reasoning="r",
            ) for it in chunk]

        with patch.object(self.server_module, "surface_prioritizer") as mock_mod:
            mock_mod.prioritize = AsyncMock(side_effect=side_effect)
            response = self.client.post("/prioritize", json={"items": items})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body["results"]), 5)
        # 5 items, max_items_per_call=2 -> 3 chunks (2, 2, 1)
        self.assertEqual(mock_mod.prioritize.await_count, 3)

    def test_disabled_returns_403(self):
        self.server_module.config["surface_prioritization"] = {"enabled": False}
        response = self.client.post("/prioritize", json={"items": [
            {"method": "GET", "url": "https://x.test/a", "param_names": []}
        ]})
        self.assertEqual(response.status_code, 403)


class MissingAuthProbeEndpointTests(unittest.TestCase):
    """HTTP-level tests for POST /probe-missing-auth (mocked network)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_harness_state.db"

        import importlib
        import global_throttle
        import server as server_module
        importlib.reload(server_module)
        self.server_module = server_module
        # Scope the probe to a test host; the module-level orchestrator's
        # allowed_hosts is what the endpoint hands the probe.
        server_module.orchestrator.allowed_hosts = ["t.test"]
        global_throttle.configure(0)
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app)

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()

    def _fake(self, mapping):
        class _Resp:
            def __init__(self, status, text):
                self.status_code, self.text = status, text

        async def fake_request(_self, method, url, headers=None):
            entry = mapping.get((method.upper(), url))
            if entry is None:
                return _Resp(404, "")
            has_auth = bool(headers) and any(k.lower() == "authorization" for k in headers)
            return _Resp(*entry.get("garbage" if has_auth else "unauth", entry["unauth"]))
        return fake_request

    def test_probes_call_shapes_and_returns_finding(self):
        from unittest.mock import patch
        m = {("GET", "http://t.test/api/report"): {"unauth": (200, '{"salary": 90000}')},
             ("GET", "http://t.test/api/tickets"): {"unauth": (401, "no")}}
        with patch("httpx.AsyncClient.request", self._fake(m)):
            resp = self.client.post("/probe-missing-auth", json={
                "base_url": "http://t.test",
                "call_shapes": [{"method": "GET", "path": "/api/report"},
                                {"method": "GET", "path": "/api/tickets"}],
                "send_garbage_token": False,
            })
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["probed"], 2)
        self.assertEqual(body["findings_count"], 1)
        self.assertEqual(body["findings"][0]["vulnerability_class"], "missing_authentication")

    def test_bare_paths_probed_as_get(self):
        from unittest.mock import patch
        m = {("GET", "http://t.test/secret"): {"unauth": (200, "leaked internal data")}}
        with patch("httpx.AsyncClient.request", self._fake(m)):
            resp = self.client.post("/probe-missing-auth", json={
                "base_url": "http://t.test", "paths": ["/secret"], "send_garbage_token": False})
        self.assertEqual(resp.json()["findings_count"], 1)

    def test_no_targets_is_400(self):
        resp = self.client.post("/probe-missing-auth", json={"base_url": "http://t.test"})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
