"""Tests for the Milestone-B worklist investigator: derive -> drive the iterative
agent per prioritised node -> fold findings back into the graph (no re-test).
The probe (iterative agent + network) is stubbed; the driver logic is under test."""
import asyncio
import unittest

import engagement
import worklist_investigator as wi
from role_crawl import RoleSession


ROLES = [RoleSession("anonymous", {}),
         RoleSession("user", {"Authorization": "Bearer u"}),
         RoleSession("admin", {"Authorization": "Bearer a"})]


def _state_with(endpoints, idor_findings=None):
    st = engagement.EngagementState(host="t")
    st.ingest_role_crawl({"endpoints": endpoints, "idor_findings": idor_findings or []})
    for r in ROLES:
        st.ingest_identity(r.role, r.role, source="seed")
    return st


OBJ = {"method": "GET", "path": "/api/tickets/{id}", "by_role": {"user": 200, "admin": 200, "anonymous": 401},
       "reachable_roles": ["user", "admin"], "object_scoped": True}
ADMIN = {"method": "GET", "path": "/api/admin/users", "by_role": {"user": 200, "admin": 200, "anonymous": 401},
         "reachable_roles": ["user", "admin"], "object_scoped": False}
BENIGN = {"method": "GET", "path": "/api/health", "by_role": {"anonymous": 200, "user": 200},
          "reachable_roles": ["anonymous", "user"], "object_scoped": False}


def _found_idor():
    return {"iterative_result": {"stop_reason": "found", "findings": [
        {"vulnerability_class": "idor", "confidence": 0.8, "severity": "high", "confirmed": True,
         "summary": "IDOR", "evidence": "other id", "suggested_test": "x", "basis": "derived"}]},
        "integration": {}}


def _nothing():
    return {"iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}}


class DeriveTests(unittest.TestCase):
    def test_object_scoped_node_derives_idor(self):
        self.assertEqual(wi._derive_probe(OBJ)[0], "idor")

    def test_privileged_low_trust_node_derives_auth(self):
        st = _state_with([ADMIN])
        node = next(w for w in st.worklist(10) if w["path"] == "/api/admin/users")
        self.assertEqual(wi._derive_probe(node)[0], "auth")

    def test_benign_node_skipped(self):
        st = _state_with([BENIGN])
        node = next(w for w in st.worklist(10) if w["path"] == "/api/health")
        self.assertIsNone(wi._derive_probe(node))


class InvestigateTests(unittest.IsolatedAsyncioTestCase):
    async def test_drives_probe_and_folds_findings_back(self):
        st = _state_with([OBJ, ADMIN, BENIGN])
        calls = []
        async def probe(exchange, hypothesis, specialty, step_budget):
            calls.append({"url": exchange.url, "specialty": specialty,
                          "auth": exchange.request_headers.get("Authorization")})
            return _found_idor() if specialty == "idor" else _nothing()

        outcomes = await wi.investigate_worklist(probe, st, "http://t", ROLES, max_nodes=8)

        specialties = {c["specialty"] for c in calls}
        self.assertIn("idor", specialties)
        self.assertIn("auth", specialties)
        # benign /api/health has no actionable signal -> never probed
        self.assertNotIn("/api/health", [o["path"] for o in outcomes])
        # probed the object endpoint from the LOWEST-trust reachable role (user)
        idor_call = next(c for c in calls if c["specialty"] == "idor")
        self.assertEqual(idor_call["auth"], "Bearer u")
        self.assertIn("/api/tickets/1", idor_call["url"])   # {id} filled
        # the confirmed finding folded back -> node is now 'validated'
        ep = next(w for w in st.worklist(10) if w["path"] == "/api/tickets/{id}")
        self.assertEqual(ep["status"], "validated")

    async def test_validated_node_is_not_retested(self):
        st = _state_with([OBJ])
        # first pass confirms it
        await wi.investigate_worklist(lambda *a, **k: _async(_found_idor()), st, "http://t", ROLES)
        # second pass must skip the now-validated node
        second = []
        async def probe(exchange, hypothesis, specialty, step_budget):
            second.append(exchange.url)
            return _nothing()
        out = await wi.investigate_worklist(probe, st, "http://t", ROLES)
        self.assertEqual(second, [])   # nothing re-tested
        self.assertEqual(out, [])

    async def test_one_node_failure_does_not_sink_the_sweep(self):
        st = _state_with([OBJ, ADMIN])
        async def probe(exchange, hypothesis, specialty, step_budget):
            if specialty == "idor":
                raise RuntimeError("probe blew up")
            return _nothing()
        out = await wi.investigate_worklist(probe, st, "http://t", ROLES)
        self.assertEqual(len(out), 2)
        self.assertTrue(any("error" in o for o in out))


def _async(value):
    async def _c(*a, **k):
        return value
    return _c()


if __name__ == "__main__":
    unittest.main()
