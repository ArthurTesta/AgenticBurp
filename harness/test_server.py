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


if __name__ == "__main__":
    unittest.main()
