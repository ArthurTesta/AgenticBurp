from __future__ import annotations
import logging
import os
import secrets
import yaml
import store
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from models import (AnalysisRequest, AnalysisResponse, ValidationSubmission, EstimateRequest, EffortStatus,
                     IdentityCreateRequest, SessionCreateRequest, SuppressFindingRequest)
import identity as identity_mod
from orchestrator import Orchestrator

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("harness.server")

CONFIG_PATH = Path(__file__).parent / "config.yaml"


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


config = load_config()
orchestrator = Orchestrator(config)
app = FastAPI(title="Burp LLM Harness", version="0.1.0")


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


_BEARER_TOKEN = config.get("server", {}).get("auth_token") or os.environ.get("HARNESS_BEARER_TOKEN")
_SERVER_HOST = config.get("server", {}).get("host", "127.0.0.1")
if not _is_loopback(_SERVER_HOST) and not _BEARER_TOKEN:
    raise RuntimeError(
        "Refusing non-loopback harness.server.host without authentication. "
        "Set server.auth_token or HARNESS_BEARER_TOKEN, or bind to 127.0.0.1."
    )


def _require_auth(authorization: str | None) -> None:
    # Loopback remains convenient for the Burp extension by default. Any
    # remotely reachable deployment must prove possession of a bearer token.
    if _is_loopback(_SERVER_HOST) and not _BEARER_TOKEN:
        return
    expected = f"Bearer {_BEARER_TOKEN}"
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="missing or invalid bearer token")


@app.get("/health")
async def health():
    return {"status": "ok", "coordinator_model": orchestrator.coordinator_model,
             "agents": list(orchestrator.agent_manager.get_enabled_agents())}


@app.get("/test-plans/{plan_id}")
async def test_plan(plan_id: str, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    plan = await __import__("asyncio").to_thread(store.get_test_plan, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="unknown test plan")
    return plan


@app.post("/validation-results")
async def validation_result(submission: ValidationSubmission, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    # The execution plane (normally Burp) posts only the observed result.
    # It cannot change a plan's target or turn a model assertion into a
    # confirmation; the server accepts the result as evidence for the plan.
    accepted, reason = await __import__("asyncio").to_thread(store.persist_validation_submission, submission)
    if not accepted:
        raise HTTPException(status_code=400 if reason == "binding_mismatch" else 404, detail=reason)
    log.info("Validation result received plan=%s status=%s confirmed=%s",
             submission.plan_id, submission.status, submission.confirmed)
    return {"accepted": True, "plan_id": submission.plan_id}


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(req: AnalysisRequest, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    try:
        return await orchestrator.analyze(req.exchange, req.force_agents, req.attempt_rediscovery)
    except Exception as e:
        log.exception("Unhandled error during analysis")
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/estimate")
async def estimate(req: EstimateRequest, authorization: str | None = Header(default=None)):
    """
    Projects total token cost for running the full assessment across the
    given URLs. Intended to be called once the analyst has spidered the
    target in Burp and sent at least one real exchange through /analyze
    (so the projection is calibrated against real per-call-kind token
    averages -- see `calibrated_from_real_calls` in the response; before
    that it still works, using the unmeasured priors in effort.py, and
    says so). Each URL can optionally carry a risk_score (e.g. Burp's
    PathScorer tier, normalized to 0-1) if the analyst's first walkthrough
    has already scored it -- unscored URLs are still counted, just at the
    lower "rest" retry-round assumption rather than "high risk".
    """
    _require_auth(authorization)
    if not req.urls:
        raise HTTPException(status_code=400, detail="urls must be non-empty")
    return orchestrator.estimate_for_urls(req.urls)


@app.get("/effort", response_model=EffortStatus)
async def effort_status(authorization: str | None = Header(default=None)):
    """Current cumulative spend against the configured budget (see
    config.yaml's effort_budget section) -- real numbers, not a projection."""
    _require_auth(authorization)
    return orchestrator.effort_status()


@app.post("/effort/confirm-overspend")
async def confirm_overspend(authorization: str | None = Header(default=None)):
    """
    Soft-mode only in practice: unblocks further dispatch after the budget
    is spent. Has no effect in hard mode -- see effort.EffortBudget.allow,
    which never checks this flag when mode is hard, by design (hard mode
    cannot be talked past by this endpoint or anything else).
    """
    _require_auth(authorization)
    orchestrator.effort_budget.confirm_overspend()
    return orchestrator.effort_status()


@app.post("/identities")
async def create_identity(req: IdentityCreateRequest, authorization: str | None = Header(default=None)):
    """Registers a named test identity (see identity.py) -- replaces
    picking a captured exchange out of an unlabeled list at
    cross-identity-compare time with a persistent, named identity."""
    _require_auth(authorization)
    try:
        role = identity_mod.IdentityRole(req.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"unknown role {req.role!r}")
    ident = identity_mod.Identity(name=req.name, role=role, notes=req.notes)
    await __import__("asyncio").to_thread(store.save_identity, ident)
    return {"id": ident.id, "name": ident.name, "role": ident.role.value, "notes": ident.notes}


@app.get("/identities")
async def get_identities(authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    return await __import__("asyncio").to_thread(store.list_identities)


@app.post("/sessions")
async def create_session(req: SessionCreateRequest, authorization: str | None = Header(default=None)):
    """Links an identity to a captured exchange's fingerprint (never the
    credential itself -- see identity.Session's docstring)."""
    _require_auth(authorization)
    if not await __import__("asyncio").to_thread(store.get_identity, req.identity_id):
        raise HTTPException(status_code=404, detail="unknown identity_id")
    sess = identity_mod.Session(identity_id=req.identity_id, host=req.host,
                                 exchange_hash=req.exchange_hash, label=req.label)
    await __import__("asyncio").to_thread(store.save_session, sess)
    return {"id": sess.id, "identity_id": sess.identity_id, "host": sess.host,
            "exchange_hash": sess.exchange_hash, "label": sess.label}


@app.get("/hosts/{host}/sessions")
async def sessions_for_host(host: str, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    return await __import__("asyncio").to_thread(store.sessions_for_host, host)


@app.post("/findings/suppress")
async def suppress_finding(req: SuppressFindingRequest, authorization: str | None = Header(default=None)):
    """
    Marks a finding fingerprint as suppressed so it doesn't resurface on
    a future scan of the same host -- see store.suppress_finding's
    docstring for the workflow gap this closes and its known limitation
    (fingerprint includes summary text, so a re-run with a differently-
    worded summary for the same underlying issue won't match).
    """
    _require_auth(authorization)
    await __import__("asyncio").to_thread(store.suppress_finding, req.fingerprint, req.reason)
    return {"fingerprint": req.fingerprint, "reason": req.reason, "suppressed": True}


@app.delete("/findings/suppress/{fingerprint}")
async def unsuppress_finding(fingerprint: str, authorization: str | None = Header(default=None)):
    """Reverses a suppression. 404s if the fingerprint wasn't suppressed,
    so a caller can tell "nothing happened" from "it worked"."""
    _require_auth(authorization)
    removed = await __import__("asyncio").to_thread(store.unsuppress_finding, fingerprint)
    if not removed:
        raise HTTPException(status_code=404, detail="fingerprint was not suppressed")
    return {"fingerprint": fingerprint, "suppressed": False}


@app.get("/findings/suppressions")
async def list_suppressions(authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    return await __import__("asyncio").to_thread(store.list_suppressions)




@app.get("/cache/stats")
async def cache_stats(authorization: str | None = Header(default=None)):
    """Get cache statistics (hits, misses, hit rate, etc.)."""
    _require_auth(authorization)
    import cache
    stats = cache.get_cache().stats()
    return {
        "cache_enabled": cache.get_cache().is_enabled(),
        "size": cache.get_cache().size(),
        "stats": stats.to_dict(),
    }


@app.post("/cache/clear")
async def cache_clear(authorization: str | None = Header(default=None)):
    """Clear all cached analysis results."""
    _require_auth(authorization)
    import cache
    cache.get_cache().clear()
    return {"status": "ok", "message": "Cache cleared"}


@app.post("/cache/enable")
async def cache_enable(authorization: str | None = Header(default=None)):
    """Enable caching."""
    _require_auth(authorization)
    import cache
    cache.get_cache().set_enabled(True)
    return {"status": "ok", "cache_enabled": True}


@app.post("/cache/disable")
async def cache_disable(authorization: str | None = Header(default=None)):
    """Disable caching."""
    _require_auth(authorization)
    import cache
    cache.get_cache().set_enabled(False)
    return {"status": "ok", "cache_enabled": False}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host=config["server"]["host"],
        port=config["server"]["port"],
        reload=False,
    )
