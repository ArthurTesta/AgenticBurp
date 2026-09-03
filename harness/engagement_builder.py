"""
Engagement builder -- the harness-owned assembly of the app model.

This is the spine of the graph-driven engagement (Milestone A). It runs the
capabilities in the right order and fuses their output into ONE EngagementState
the harness then prioritises from, instead of firing every agent at every
captured request:

  1. DISCOVER the real surface (api_surface_discovery, via role_crawl's
     active_discovery) -- the full route set, not the fraction JS-mining finds.
  2. Build the per-role ACCESS MATRIX (role_crawl) -- who can reach what, plus
     the deterministic auth-bypass / IDOR candidates that fall out of it.
  3. INGEST both into EngagementState -- surface (endpoint x role x findings) and
     identities -- so a single fused, auditable "test-next" ranking exists.

The result is a prioritised worklist: privileged-looking endpoints reachable by a
low-trust role rank above a bare high-tier path, already-validated endpoints sink.
That worklist is the object the next milestones (iterative per-node investigation,
the task-graph driver) consume -- coverage and prioritisation first, in one place.

Pure orchestration: no new network or LLM logic of its own, only the ordering and
the fusion. Deterministic given the same live responses.
"""
from __future__ import annotations

import logging
from urllib.parse import urlsplit

import engagement
import role_crawl
from role_crawl import RoleSession

log = logging.getLogger("harness.engagement_builder")


def _host_of(base_url: str) -> str:
    return urlsplit(base_url).netloc or base_url


async def build_engagement(
    base_url: str,
    roles: list[RoleSession],
    *,
    allowed_hosts: list[str] | None = None,
    host: str | None = None,
    max_endpoints: int = 150,
    discovery_max_probes: int = 6000,
    id_fill: str = "1",
) -> tuple[engagement.EngagementState, role_crawl.RoleCrawlResult]:
    """Discover + build the access matrix + fuse into an EngagementState.

    Returns (state, raw_role_crawl_result). `state.worklist()` is the prioritised
    ranking; the raw result carries the endpoints, candidates and IDOR findings."""
    result = await role_crawl.crawl_roles(
        base_url, roles,
        allowed_hosts=allowed_hosts,
        max_endpoints=max_endpoints,
        id_fill=id_fill,
        active_discovery=True,
        discovery_max_probes=discovery_max_probes,
    )

    state = engagement.EngagementState(host=host or _host_of(base_url))
    state.ingest_role_crawl(result.to_dict())
    for r in roles:
        state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")

    log.info("build_engagement: %s -- %d endpoints, %d idor candidates, %d idor findings",
             base_url, len(result.endpoints), len(result.idor_candidates), len(result.idor_findings))
    return state, result
