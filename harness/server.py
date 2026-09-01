from __future__ import annotations
import asyncio
import logging
import os
import secrets
import yaml
import store
import active_verification
import surface_prioritizer
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

from models import (AnalysisRequest, AnalysisResponse, ValidationSubmission, EstimateRequest, EffortStatus,
                     IdentityCreateRequest, SessionCreateRequest, SuppressFindingRequest,
                     PrioritizeRequest, PrioritizeResponse, PrioritizeResultItem)
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


@app.get("/report")
async def report(url: str, authorization: str | None = Header(default=None)):
    """
    Analyst-facing Markdown writeup of everything found for `url`'s host
    so far -- report_generator.py, wired here for the first time. The
    module was fully built and tested (test_report_generator.py) but had
    no caller anywhere: no endpoint, no CLI hook, nothing -- found during
    a dead-code audit prompted by the same pattern already found and
    fixed once this session for retry_policy.py/payload_library.py.
    Passing the live orchestrator's effort ledger (not omitted, unlike
    the module's own standalone-script default) gets cost-aware ordering
    of unconfirmed findings for real, in-session token-spend data.
    """
    _require_auth(authorization)
    import report_generator
    markdown = await __import__("asyncio").to_thread(
        report_generator.generate_report_for_host, url, orchestrator.effort_budget.ledger,
    )
    return PlainTextResponse(markdown, media_type="text/markdown")


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

    # Not confirmed on a retryable (xss/ssrf/business_logic, Burp-plane)
    # capability: decide whether another attempt with a genuinely
    # different payload is warranted -- see active_verification.py for
    # why this exists (retry_policy.py and payload_library.py were fully
    # built but never wired to any caller before this).
    response: dict = {"accepted": True, "plan_id": submission.plan_id}
    plan = await __import__("asyncio").to_thread(store.get_test_plan, submission.plan_id)
    if plan is not None:
        step = await active_verification.decide_next_step(
            plan, submission, ollama_client=orchestrator.ollama,
        )
        if step.next_plan is not None:
            await __import__("asyncio").to_thread(store.persist_retry_plan, step.next_plan)
            response["next_plan"] = step.next_plan.model_dump()
        if step.handover_required:
            response["handover_required"] = True
        if step.note:
            response["note"] = step.note
    return response


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


@app.post("/prioritize", response_model=PrioritizeResponse)
async def prioritize(req: PrioritizeRequest, authorization: str | None = Header(default=None)):
    """
    Structure-only (method/URL/param names, no bodies) LLM triage pass for
    the Attack Surface Map tab's "Scan Site Map" -- see
    surface_prioritizer.py's own docstring. Batches req.items into chunks
    of surface_prioritization.max_items_per_call, one LLM call per chunk,
    run concurrently -- bounded even for a large site map, not one call
    per endpoint.
    """
    _require_auth(authorization)
    cfg = config.get("surface_prioritization", {})
    if not cfg.get("enabled", True):
        raise HTTPException(status_code=403, detail="surface_prioritization is disabled in config.yaml")
    if not req.items:
        return PrioritizeResponse(results=[])

    chunk_size = max(1, cfg.get("max_items_per_call", 40))
    chunks = [req.items[i:i + chunk_size] for i in range(0, len(req.items), chunk_size)]
    model = cfg.get("model") or orchestrator.coordinator_model
    chunk_results = await asyncio.gather(*[
        surface_prioritizer.prioritize(chunk, orchestrator.ollama, model, cfg.get("temperature", 0.1))
        for chunk in chunks
    ])
    results: list[PrioritizeResultItem] = [r for chunk in chunk_results for r in chunk]
    return PrioritizeResponse(results=results)


from pydantic import BaseModel as _BaseModel


class CrawlRequest(_BaseModel):
    base_url: str
    # Optional session the tester's Burp already holds (Authorization / Cookie),
    # so the crawl reaches authenticated surface. Never populated by the server.
    headers: dict[str, str] = {}
    max_pages: int = 40
    max_depth: int = 2


@app.post("/crawl")
async def crawl_endpoint(req: CrawlRequest, authorization: str | None = Header(default=None)):
    """Discover the application's real endpoint surface by fetching its pages
    AND mining the JavaScript bundles they load (js_endpoint_extractor.py) --
    the API surface a link-only spider misses. Scope-gated to the engagement's
    server.allowed_hosts, paced by the global request throttle, and bounded by
    max_pages/max_depth. Drives the Burp "Crawl" button; returns the discovered
    endpoints for the site map / attack-surface tab."""
    _require_auth(authorization)
    import crawler
    result = await crawler.crawl(
        req.base_url,
        headers=req.headers or {},
        allowed_hosts=orchestrator.allowed_hosts,
        max_pages=max(1, min(req.max_pages, 200)),
        max_depth=max(0, min(req.max_depth, 4)),
    )
    return result.to_dict()


class MissingAuthRequest(_BaseModel):
    base_url: str
    # Endpoints to probe, as call shapes recovered from the app's JS
    # (js_endpoint_extractor.extract_call_shapes) or supplied by the tester.
    call_shapes: list[dict[str, str]] = []   # [{"method": "...", "path": "..."}]
    # Extra bare paths with no known method are probed as GET.
    paths: list[str] = []
    # The tester's Burp session headers, if any -- the probe STRIPS the auth
    # ones and keeps the rest; the point is to fire with credentials removed.
    headers: dict[str, str] = {}
    # If true and no call_shapes given, crawl base_url first and probe every
    # discovered endpoint as a GET shape.
    discover: bool = False
    max_pages: int = 40
    send_garbage_token: bool = True
    # Off by default: probing mutating methods (POST/PUT/PATCH/DELETE) is gated
    # by the safety gate and only fires when active testing + mutating replay
    # are enabled in config.yaml. Left off, mutating shapes are skipped.
    include_mutating: bool = False
    # The caller knows these endpoints are meant to be authenticated (e.g. they
    # were only referenced in authenticated JS) -- nudges confidence up.
    expected_protected: bool = False


@app.post("/probe-missing-auth")
async def probe_missing_auth_endpoint(req: MissingAuthRequest, authorization: str | None = Header(default=None)):
    """Fire discovered endpoints with authentication stripped and flag the ones
    that still return data -- the "generateReport unauthenticated" class an
    always-authenticated capture never reveals (missing_auth_probe.py).

    Scope-gated to server.allowed_hosts, paced by the global request throttle,
    and read-only unless include_mutating AND the safety gate allow it. Provide
    call_shapes (method+path) mined from the app's JS, bare `paths` (probed as
    GET), or set `discover` to crawl base_url first. Returns per-endpoint
    outcomes plus the missing_authentication findings."""
    _require_auth(authorization)
    import missing_auth_probe
    from js_endpoint_extractor import CallShape

    shapes: list[CallShape] = []
    for cs in req.call_shapes:
        method, path = cs.get("method"), cs.get("path")
        if method and path:
            shapes.append(CallShape(method=str(method).upper(), path=str(path)))
    shapes.extend(CallShape("GET", p) for p in req.paths if p)

    if not shapes and req.discover:
        import crawler
        crawl = await crawler.crawl(
            req.base_url, headers=req.headers or {}, allowed_hosts=orchestrator.allowed_hosts,
            max_pages=max(1, min(req.max_pages, 200)),
        )
        shapes.extend(CallShape("GET", p) for p in sorted(crawl.endpoints))

    if not shapes:
        raise HTTPException(status_code=400, detail="no call_shapes, paths, or discoverable endpoints to probe")

    outcomes = await missing_auth_probe.probe_call_shapes(
        req.base_url, shapes,
        allowed_hosts=orchestrator.allowed_hosts,
        baseline_headers=req.headers or None,
        send_garbage_token=req.send_garbage_token,
        include_mutating=req.include_mutating,
        expected_protected=req.expected_protected,
    )
    findings = missing_auth_probe.findings_from(outcomes)
    return {
        "base_url": req.base_url,
        "probed": len(outcomes),
        "findings_count": len(findings),
        "outcomes": [o.to_dict() for o in outcomes],
        "findings": [f.model_dump() for f in findings],
    }


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
