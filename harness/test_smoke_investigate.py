"""
End-to-end smoke test for the graph-driven investigation path and its PROACTIVE,
precondition-driven confirmation legs (HANDOVER_6 §4).

Companion to test_smoke_detection.py (which covers analyze()). That one never
exercised investigate_engagement, and NOTHING did -- the exact "green tests, dead
pipeline" shape this project has been bitten by three times. This runs the REAL
investigate_engagement pipeline (build_engagement -> worklist_investigator ->
_precondition -> shape_precondition_legs -> _confirm -> the real jwt-forge
validator) and asserts that a JWT-carrying endpoint an agent NEVER labelled "jwt"
still gets its alg:none forgery run and CONFIRMED -- the precise failure §3
documented (jwt_forge never fired where it could confirm).

Hermetic: no GPU, no model, no live target. Discovery is replaced with a canned
one-endpoint surface; the socket layer (httpx.AsyncClient.get, the only network
the jwt leg uses here) is stubbed with a vulnerable/secure responder. The
negative control (a server that actually verifies signatures) proves the test
guards CONFIRMATION, not merely that the leg ran.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

import httpx
import yaml

_HARNESS = Path(__file__).resolve().parent

import store
import cache
import engagement
from orchestrator import Orchestrator
from role_crawl import RoleSession
from validators.jwt_forge_validator import _b64url_encode, _b64url_decode
import json


def _jwt(payload: dict) -> str:
    h = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}.originalsig0123456789"


ORIGINAL_TOKEN = _jwt({"user_id": 4, "role": "user"})
GARBAGE_SIG = _b64url_encode(b"not-a-valid-signature-xxxx")
BASE_URL = "http://localhost"
JWT_PATH = "/api/tickets/mine"

# The single canned endpoint: JWT-carrying, NOT object-scoped, and NOT labelled
# with any finding -- so the agent probe derives nothing and only the shape-driven
# jwt leg can fire. This is the §3 case: the endpoint where alg:none is confirmable
# but no agent ever hypothesised "jwt".
_ENDPOINT = {"method": "GET", "path": JWT_PATH, "by_role": {"user": 200, "anonymous": 401},
             "reachable_roles": ["user"], "object_scoped": False}

ROLES = [RoleSession("anonymous", {}),
         RoleSession("user", {"Authorization": f"Bearer {ORIGINAL_TOKEN}"})]


def _auth_of(headers) -> str:
    for k, v in (headers or {}).items():
        if k.lower() in ("authorization", "cookie"):
            return v or ""
    return ""


def _responder(vulnerable: bool):
    """Stub for httpx.AsyncClient.get. A patched class method is called WITHOUT
    self, so the signature is (url, headers=..., **kw)."""
    async def _get(url, headers=None, **kw):
        req = httpx.Request("GET", str(url))
        if JWT_PATH not in str(url):
            return httpx.Response(404, content=b"", request=req)
        auth = _auth_of(headers)
        if GARBAGE_SIG in auth:
            return httpx.Response(401, content=b"forbidden", request=req)   # control: rejected
        if vulnerable:
            # Broken verifier: ANY JWT (forged alg:none included) is accepted.
            if "eyJ" in auth:
                return httpx.Response(200, content=b'{"tickets":["mine"]}', request=req)
            return httpx.Response(401, content=b"forbidden", request=req)
        # Secure verifier: only the exact, legitimately-signed token is accepted.
        if ORIGINAL_TOKEN in auth:
            return httpx.Response(200, content=b'{"tickets":["mine"]}', request=req)
        return httpx.Response(401, content=b"forbidden", request=req)
    return _get


def _test_config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    validators = cfg.setdefault("validators", {})
    validators["active_enabled"] = True          # the legs send live (here: stubbed) requests
    validators["allow_mutating_replay"] = False
    cfg.setdefault("autonomous_discovery", {})["enabled"] = False
    cfg.setdefault("github_advisories", {})["enabled"] = False
    cfg.setdefault("kev_check", {})["enabled"] = False
    cfg.setdefault("package_registry_checks", {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["localhost", "127.0.0.1"]
    return cfg


def _canned_engagement(base_url, roles, **kw):
    """Stand-in for engagement_builder.build_engagement: a real EngagementState
    holding the one canned endpoint, plus a role-crawl result with no findings."""
    state = engagement.EngagementState(host="localhost")
    state.ingest_role_crawl({"endpoints": [dict(_ENDPOINT)], "idor_findings": []})
    for r in roles:
        state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
    rc = SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[], idor_findings=[])
    return state, rc


class InvestigateProactiveJwtSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="smoke_investigate_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _run(self, vulnerable: bool):
        orch = Orchestrator(_test_config())
        # No agent probe should be needed (the node derives no specialty), but stub
        # it so a stray derivation can't reach for a real model.
        orch.run_active_probe = AsyncMock(return_value={
            "iterative_result": {"stop_reason": "gave_up", "findings": []}, "integration": {}})
        with patch("engagement_builder.build_engagement", side_effect=_canned_engagement), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_responder(vulnerable)):
            return asyncio.run(orch.investigate_engagement(
                BASE_URL, ROLES, max_nodes=4, step_budget=4, max_chain_rounds=0))

    def _confirmed_jwt(self, result):
        return [f for o in result.get("outcomes", []) for f in o.get("findings_detail", [])
                if f.get("confirmed") and "jwt" in (f.get("vulnerability_class") or "").lower()]

    def test_proactive_jwt_forge_confirms_on_unlabelled_endpoint(self):
        result = self._run(vulnerable=True)
        confirmed = self._confirmed_jwt(result)
        self.assertTrue(
            confirmed,
            "PROACTIVE CONFIRMATION IS DEAD: a JWT-carrying endpoint with a broken "
            "alg:none verifier was investigated, but the shape-driven jwt-forge leg "
            "never produced a confirmed finding -- the §4 routing is not reaching the "
            "validator end-to-end through investigate_engagement.")
        # It was proven from the low-trust 'user' identity, and it's a real confirm.
        self.assertTrue(any(f.get("confidence", 0) >= 0.9 for f in confirmed))

    def test_coverage_matrix_is_filled_end_to_end(self):
        # The coverage cell-filler must actually run inside investigate_engagement
        # (I1/I2/I5): a real run produces a matrix with the JWT check confirmed and
        # an auditable "not tested + reason" list -- not an empty stub.
        result = self._run(vulnerable=True)
        cov = result.get("coverage") or {}
        self.assertTrue(cov, "coverage matrix was not built by investigate_engagement")
        self.assertGreater(cov.get("total_cells", 0), 0)
        self.assertGreaterEqual(cov.get("confirmed", 0), 1,
                                "the confirmed JWT forge did not fill a CONFIRMED coverage cell")
        # WSTG-CRYP-04 is the JWT check; it must show a confirmed cell.
        jwt_check = cov.get("by_check", {}).get("WSTG-CRYP-04", {})
        self.assertGreaterEqual(jwt_check.get("confirmed", 0), 1)
        # every not-tested cell carries a reason (the audit guarantee)
        self.assertTrue(all(nt.get("reason") for nt in cov.get("not_tested", [])))

    def test_negative_control_secure_server_yields_no_confirmation(self):
        # A server that actually verifies signatures must NOT be confirmed -- proving
        # the test guards CONFIRMATION, not merely that the leg executed.
        result = self._run(vulnerable=False)
        self.assertEqual(
            self._confirmed_jwt(result), [],
            "Smoke test is not testing confirmation: a secure (signature-verifying) "
            "server was still reported as a confirmed JWT forgery.")


if __name__ == "__main__":
    unittest.main()
