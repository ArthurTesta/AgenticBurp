"""
Role-aware crawl -> access matrix.

A plain crawl finds an application's endpoint surface. It doesn't tell you WHO
can reach each endpoint -- and that is exactly the question broken-access-control
testing turns on. This module crawls the same target once per supplied role
(using that role's real captured session headers), unions the discovered
surface, then probes every endpoint with every role and records the result as an
ACCESS MATRIX: endpoint -> {role: status}. From that matrix two high-value
candidate sets fall out deterministically:

  - auth-bypass / missing-auth: an endpoint the ANONYMOUS role reaches with
    substantive 2xx content, or one a lower-trust role reaches that a
    higher-trust one doesn't -- a function-level access-control gap (BFLA).
  - IDOR / BOLA: an object-scoped endpoint (a path carrying an {id}) reachable
    by more than one authenticated identity -- the precise target the existing
    cross-identity compare needs (same object, two identities).

Credentials are never stored here. Each role's headers arrive per call from the
caller (Burp, which holds the real captured session) exactly like the plain
crawl and missing-auth probe -- the harness's standing rule that sessions record
fingerprints, not secrets, is preserved. Scope-gated to allowed_hosts and paced
by the global request throttle throughout.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

import crawler
import global_throttle
import missing_auth_probe as map_

log = logging.getLogger("harness.role_crawl")

# Trust ordering for the built-in identity roles (identity.IdentityRole). A role
# reaching something a STRICTLY higher-trust role also reaches is normal; a
# lower-trust role reaching something a higher one can't is the interesting
# (privilege) direction. Unknown/custom role labels sort as mid-trust.
_TRUST = {"anonymous": 0, "user": 1, "service": 2, "admin": 3}


def _trust(role: str) -> int:
    return _TRUST.get((role or "").lower(), 1)


@dataclass
class RoleSession:
    role: str                 # "anonymous" | "user" | "admin" | "service" | free label
    headers: dict             # real captured session headers; empty/none for anonymous

    def norm_headers(self) -> dict:
        return dict(self.headers or {})


@dataclass
class EndpointAccess:
    method: str
    path: str                 # normalized (may contain {id})
    by_role: dict = field(default_factory=dict)   # role -> status (int) or None on error
    reachable_roles: list = field(default_factory=list)  # roles that got substantive 2xx

    @property
    def object_scoped(self) -> bool:
        return "{id}" in self.path

    def to_dict(self) -> dict:
        return {"method": self.method, "path": self.path, "by_role": self.by_role,
                "reachable_roles": self.reachable_roles, "object_scoped": self.object_scoped}


@dataclass
class RoleCrawlResult:
    base_url: str
    roles: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)          # EndpointAccess
    auth_bypass_candidates: list = field(default_factory=list)  # dicts
    idor_candidates: list = field(default_factory=list)         # dicts
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "roles": self.roles,
            "endpoint_count": len(self.endpoints),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "auth_bypass_candidates": self.auth_bypass_candidates,
            "idor_candidates": self.idor_candidates,
            "errors": self.errors,
        }


async def _probe(method: str, url: str, headers: dict, timeout: float) -> tuple[int | None, str]:
    if not method:
        method = "GET"
    try:
        await global_throttle.acquire()
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.request(method, url, headers=headers or None)
        return resp.status_code, (resp.text or "")
    except httpx.HTTPError as e:
        return None, f"request failed: {e.__class__.__name__}"


async def crawl_roles(
    base_url: str,
    roles: list[RoleSession],
    *,
    allowed_hosts: list[str] | None = None,
    max_pages: int = 40,
    max_endpoints: int = 150,
    id_fill: str = "1",
    timeout: float = 15.0,
) -> RoleCrawlResult:
    """Crawl `base_url` once per role, union the surface, probe every endpoint
    with every role, and derive auth-bypass + IDOR candidates from the matrix.

    `roles` is a list of RoleSession; include an anonymous role (empty headers)
    to detect auth bypass. Probing is bounded by `max_endpoints` (the union is
    truncated, most-specific first is not assumed -- simply capped) so a large
    surface can't fan out into an unbounded number of requests."""
    result = RoleCrawlResult(base_url=base_url, roles=[r.role for r in roles])
    if not roles:
        result.errors.append("no roles supplied")
        return result

    # 1. Discover the surface, per role (authenticated pages/JS may reveal more).
    discovered: set[str] = set()
    for r in roles:
        try:
            cr = await crawler.crawl(base_url, headers=r.norm_headers(),
                                     allowed_hosts=allowed_hosts, max_pages=max_pages)
            discovered |= cr.endpoints
            result.errors.extend(f"[{r.role}] {e}" for e in cr.errors)
        except Exception as e:  # a bad role's crawl must not sink the whole run
            result.errors.append(f"[{r.role}] crawl failed: {e.__class__.__name__}")

    paths = sorted(discovered)[:max_endpoints]
    if len(discovered) > max_endpoints:
        result.errors.append(f"surface truncated to {max_endpoints} of {len(discovered)} endpoints for probing")

    # 2. Probe each endpoint with each role -> access matrix.
    for path in paths:
        url = map_._build_url(base_url, path, id_fill)
        if not map_._host_allowed(url, allowed_hosts):
            continue
        access = EndpointAccess(method="GET", path=path)
        for r in roles:
            status, body = await _probe("GET", url, r.norm_headers(), timeout)
            access.by_role[r.role] = status
            if map_._substantive(status, body):
                access.reachable_roles.append(r.role)
        result.endpoints.append(access)

    _derive_candidates(result, roles)
    log.info("role_crawl: %s -- %d endpoints, %d auth-bypass, %d idor candidates",
             base_url, len(result.endpoints), len(result.auth_bypass_candidates),
             len(result.idor_candidates))
    return result


def _derive_candidates(result: RoleCrawlResult, roles: list[RoleSession]) -> None:
    anon_roles = {r.role for r in roles if _trust(r.role) == 0}
    for e in result.endpoints:
        reachable = set(e.reachable_roles)
        if not reachable:
            continue

        # Auth bypass: reachable anonymously at all -> served without credentials.
        anon_reach = reachable & anon_roles
        if anon_reach:
            result.auth_bypass_candidates.append({
                "path": e.path, "method": e.method, "reached_by": sorted(reachable),
                "reason": "reachable with no authentication (anonymous role got substantive 2xx)",
                "severity": "high", "class": "missing_authentication",
                "by_role": e.by_role,
            })
        else:
            # Function-level authz gap: a lower-trust role reaches something a
            # strictly higher-trust role in this run does NOT -- the privilege
            # direction is inverted from what RBAC would produce.
            reached_trust = min(_trust(x) for x in reachable)
            higher_absent = sorted(r.role for r in roles
                                   if r.role not in reachable and _trust(r.role) > reached_trust)
            if higher_absent and reached_trust > 0:
                result.auth_bypass_candidates.append({
                    "path": e.path, "method": e.method, "reached_by": sorted(reachable),
                    "reason": f"reachable by lower-trust role(s) but not higher-trust role(s) "
                              f"{higher_absent} -- inverted privilege direction, a broken "
                              f"function-level authorization candidate",
                    "severity": "medium", "class": "authz",
                    "by_role": e.by_role,
                })

        # IDOR/BOLA: an object-scoped endpoint reachable by >=1 authenticated
        # identity -- the target for a same-object cross-identity comparison.
        authed_reach = sorted(x for x in reachable if _trust(x) > 0)
        if e.object_scoped and authed_reach:
            result.idor_candidates.append({
                "path": e.path, "method": e.method, "reached_by": authed_reach,
                "reason": "object-scoped endpoint ({id} in path) reachable by an authenticated "
                          "identity -- test same object id across identities for IDOR/BOLA",
                "severity": "high", "class": "idor",
                "by_role": e.by_role,
            })
