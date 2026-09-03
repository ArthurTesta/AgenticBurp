"""
Worklist investigator -- Milestone B: per-node multi-step investigation.

Pass 1 fired every agent at every captured request, once each, and gave up when
one shot found nothing. This drives the ITERATIVE agent instead, TOP-DOWN off the
harness's own prioritised worklist (engagement_builder): take the highest-value
node, derive a hypothesis from what the access matrix already knows about it, and
give it a bounded send->observe->adapt investigation -- N steps, stop on confirm
or budget -- rather than a single guess. Findings fold back into the graph, so a
node that's been investigated changes status and sinks in the ranking: the harness
does not re-test what it has already worked.

This is the loop the earlier sessions described ("an agent with a number of
interactions / reasoning steps") wired to coverage + prioritisation: what to test
is chosen by the graph, how hard to test it is the per-node step budget.

`probe_fn` is the investigation seam -- in production it is
orchestrator.run_active_probe (the iterative agent + pivot integration); tests
inject a stub. No LLM or network logic lives here, only the derive -> drive ->
integrate loop.
"""
from __future__ import annotations

import logging
from urllib.parse import urlsplit

from models import HttpExchange

log = logging.getLogger("harness.worklist_investigator")

# Trust order so the driver probes from the LOWEST-privilege identity that can
# reach a node -- proving a bug from a weak role is the stronger result.
_TRUST = {"anonymous": 0, "user": 1, "agent": 2, "service": 2, "manager": 3, "admin": 4}


def _trust(role: str) -> int:
    return _TRUST.get((role or "").lower(), 1)


def _derive_probe(node: dict) -> tuple[str, str] | None:
    """Map a worklist node to (specialty, hypothesis), or None to skip a node
    with no actionable signal. The signal is what the access matrix already
    established -- object-scoping, an unconfirmed IDOR candidate, or a low-trust
    role reaching a privileged-looking path -- so the hypothesis is grounded, not
    a blind guess."""
    method, path = node.get("method", "GET"), node.get("path", "/")
    reach = node.get("reachable_roles", []) or []
    reasons = node.get("reasons", []) or []
    findings = node.get("findings", []) or []
    has_idor = any((f.get("vulnerability_class") or "").lower().startswith(("idor", "insecure direct"))
                   or "object" in (f.get("vulnerability_class") or "").lower() for f in findings)
    low_trust_priv = any("privileged-looking" in r and "reach" in r for r in reasons) or \
        any("authz gap" in r.lower() for r in reasons)

    if node.get("object_scoped") or has_idor:
        return "idor", (
            f"Object-scoped endpoint {method} {path} is reachable by {', '.join(reach) or 'unknown roles'}. "
            f"Enumerate the object id to reach another identity's object and confirm broken "
            f"object-level authorization (IDOR/BOLA).")
    if low_trust_priv:
        return "auth", (
            f"{method} {path} is a privileged-looking endpoint reachable by a low-trust role "
            f"({', '.join(reach) or 'unknown'}). Probe for broken function-level authorization / auth bypass.")
    return None


def _seed_exchange(base_url: str, node: dict, headers: dict, id_fill: str) -> HttpExchange:
    path = node.get("path", "/").replace("{id}", id_fill)
    url = base_url.rstrip("/") + path
    return HttpExchange(
        url=url, method=node.get("method", "GET"),
        request_headers=dict(headers or {}), request_body="",
        response_status=None, response_headers={}, response_body="",
    )


def _findings_from_outcome(outcome: dict) -> list[dict]:
    """Pull the findings the probe produced (iterative agent + pivot integration),
    as plain dicts ready for EngagementState.ingest_findings."""
    out: list[dict] = []
    ir = (outcome or {}).get("iterative_result", {}) or {}
    out.extend(ir.get("findings", []) or [])
    integ = (outcome or {}).get("integration", {}) or {}
    out.extend(integ.get("held_findings", []) or [])
    return out


async def investigate_worklist(
    probe_fn,
    state,
    base_url: str,
    roles,
    *,
    max_nodes: int = 8,
    step_budget: int = 16,
    id_fill: str = "1",
) -> list[dict]:
    """Drive `probe_fn` over the top `max_nodes` actionable worklist nodes.

    `probe_fn(exchange, hypothesis, specialty, step_budget) -> outcome dict`.
    Returns a per-node outcome list; findings are folded back into `state`."""
    role_headers = {r.role: dict(r.headers or {}) for r in roles}
    outcomes: list[dict] = []
    investigated = 0

    for node in state.worklist(50):
        if investigated >= max_nodes:
            break
        if node.get("status") == "validated":
            continue  # already proven -- never re-test
        derived = _derive_probe(node)
        if derived is None:
            continue
        specialty, hypothesis = derived
        reach = node.get("reachable_roles", []) or []
        # probe from the lowest-trust identity that can reach it (strongest proof).
        probe_role = min(reach, key=_trust) if reach else (roles[0].role if roles else "anonymous")
        headers = role_headers.get(probe_role, {})
        exchange = _seed_exchange(base_url, node, headers, id_fill)

        try:
            outcome = await probe_fn(exchange, hypothesis, specialty, step_budget)
        except Exception as e:  # one node's failure must not sink the sweep
            log.warning("investigate_worklist: node %s %s failed: %s", node.get("method"), node.get("path"), e)
            outcomes.append({"path": node.get("path"), "specialty": specialty, "error": repr(e)})
            investigated += 1
            continue

        findings = _findings_from_outcome(outcome)
        for f in findings:
            f.setdefault("url", exchange.url)  # stamp the concrete url for chain/capability linking
        if findings:
            state.ingest_findings(exchange.url, exchange.method, findings)
        outcomes.append({
            "path": node.get("path"), "specialty": specialty, "probe_role": probe_role,
            "findings": len(findings),
            "findings_detail": findings,
            "confirmed": any(f.get("confirmed") for f in findings),
            "stop_reason": (outcome or {}).get("iterative_result", {}).get("stop_reason"),
        })
        investigated += 1

    log.info("investigate_worklist: %s -- investigated %d nodes", base_url, investigated)
    return outcomes
