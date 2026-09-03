"""
Active black-box API surface discovery.

crawler.py mines an app's JS/HTML for endpoints -- which finds nothing on a
headless JSON API (no bundle, no links). Real coverage on an API needs active
probing, the way a human reaches for ffuf/gobuster once they realise the app is
API-only. This module is that layer: it discovers routes the tester's proxied
browsing never touched -- the "generateReport unauthenticated" class -- so the
engagement graph is built on the real surface, not the fraction that happened to
be exercised.

Four techniques, cheapest-signal first:
  1. SPEC probe   -- GET the well-known OpenAPI/Swagger locations; if the app
                     serves its own contract, that IS the surface (jackpot).
  2. WORDLIST     -- REST + domain nouns across prefixes, bare / id-scoped, and
                     NESTED two-segment (/api/<collection>/<noun>). Single-segment
                     lists miss most of a real API (/api/admin/users lives two
                     deep); nesting is what makes this find the majority.
  3. ALLOW mining -- a route that exists but rejects GET answers 405 with an
                     `Allow` header -> learn its real methods (POST-only routes,
                     otherwise invisible to a GET sweep).
  4. RESPONSE-driven -- mine 2xx JSON bodies for object ids and enumerate their
                     siblings (a list of tickets reveals ids 4,5,6...).

The existence oracle is deliberately app-agnostic: a route is REAL unless the
response is a not-found (a plain 404, or a framework "NotFound" marker some apps
wrap as a 500). Everything else -- 200/401/403/405/400/3xx -- means the route
is there, only the auth/method/shape differs.

Scope-gated to allowed_hosts and paced by the global throttle, exactly like the
validators. Discovery is READ-ONLY: every probe is a GET (plus a bounded method
sweep for Allow mining); it never sends a mutating body.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

# Framework "route does not exist" markers some apps leak in the body (Flask/
# Werkzeug wraps 404s this way; others return a bare 404 status, handled too).
_NOT_FOUND_MARKERS = (
    "werkzeug.exceptions.NotFound",
    "404 Not Found: The requested URL was not found",
)

# Well-known machine-readable API contracts. If any is served, it is the surface.
SPEC_PATHS = (
    "/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json",
    "/api-docs", "/api/docs", "/v3/api-docs", "/swagger/v1/swagger.json",
    "/.well-known/openapi.json", "/api/schema", "/api/spec",
)

# A compact, generic REST + support-app vocabulary. Callers can extend with terms
# mined from the app (response bodies, JS) for better hit rates.
DEFAULT_NOUNS = (
    "login logout register token refresh session sessions password reset verify mfa "
    "users user me whoami profile account accounts admin roles permissions "
    "tickets ticket comments attachments replies assign escalate close reopen import export search mine "
    "kb articles faq categories tags labels "
    "integrations webhook webhooks connect oauth callback fetch proxy notify "
    "refunds reports invoices payments billing credits approve reject "
    "diagnostics debug logs audit config settings backup system health status metrics maintenance "
    "files upload uploads download media avatar "
    "notifications feed activity orgs organizations teams groups version info stats"
).split()

# Path segments that plausibly parent a nested resource (/api/<collection>/<noun>).
DEFAULT_COLLECTIONS = (
    "account users admin tickets kb integrations reports system auth org orgs "
    "billing config me files"
).split()

DEFAULT_PREFIXES = ("/api/", "/api/v1/", "/", "/admin/", "/internal/")


@dataclass(frozen=True)
class Route:
    """One discovered route. `methods` are the real HTTP verbs it accepts
    (from an Allow header when the probe method was rejected, else the probe
    method that succeeded)."""
    path: str
    status: int = 0
    methods: tuple[str, ...] = ()
    length: int = 0
    source: str = "wordlist"  # spec | wordlist | nested | allow | response


@dataclass
class SurfaceResult:
    base_url: str
    routes: list[Route] = field(default_factory=list)
    spec_found: str | None = None
    probes_sent: int = 0
    errors: list[str] = field(default_factory=list)

    def paths(self) -> list[str]:
        return sorted({r.path for r in self.routes})

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "spec_found": self.spec_found,
            "probes_sent": self.probes_sent,
            "routes": [
                {"path": r.path, "status": r.status, "methods": list(r.methods),
                 "length": r.length, "source": r.source}
                for r in sorted(self.routes, key=lambda x: x.path)
            ],
            "errors": self.errors,
        }


def _is_not_found(status: int, body: str) -> bool:
    if status == 404:
        return True
    return any(m in body for m in _NOT_FOUND_MARKERS)


def _host_in_scope(url: str, allowed_hosts) -> bool:
    if not allowed_hosts:
        return True
    return (urlparse(url).hostname or "") in set(allowed_hosts)


class SurfaceDiscovery:
    def __init__(self, base_url: str, *, headers: dict | None = None,
                 allowed_hosts: list[str] | None = None,
                 nouns=None, collections=None, prefixes=None,
                 timeout: float = 8.0, max_probes: int = 6000):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.allowed_hosts = allowed_hosts or []
        self.nouns = list(nouns) if nouns is not None else list(DEFAULT_NOUNS)
        self.collections = list(collections) if collections is not None else list(DEFAULT_COLLECTIONS)
        self.prefixes = list(prefixes) if prefixes is not None else list(DEFAULT_PREFIXES)
        self.timeout = timeout
        self.max_probes = max_probes
        self._seen: dict[str, Route] = {}
        self._probes = 0

    async def _probe(self, method: str, path: str):
        """One live request. A method seam so tests inject a canned responder and
        never touch the network. Returns (status, body, allow) or None on error.
        Throttled and scope-gated identically to the validator path."""
        url = self.base_url + path
        if not _host_in_scope(url, self.allowed_hosts):
            return None
        import global_throttle
        await global_throttle.acquire()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=False) as client:
                resp = await client.request(method, url, headers=self.headers or None)
        except Exception:
            return None
        return resp.status_code, (resp.text or ""), resp.headers.get("Allow", "")

    def _budget_left(self) -> bool:
        return self._probes < self.max_probes

    async def _raw(self, method: str, path: str):
        """Budget-guarded, counted single probe -- every phase goes through this
        so max_probes bounds the whole run (spec + wordlist + allow + response),
        not just the wordlist. Returns None when the budget is spent."""
        if not self._budget_left():
            return None
        self._probes += 1
        return await self._probe(method, path)

    async def _check(self, path: str, source: str, method: str = "GET") -> Route | None:
        if path in self._seen:
            return self._seen[path]
        r = await self._raw(method, path)
        if r is None:
            return None
        status, body, allow = r
        if _is_not_found(status, body):
            return None
        methods = tuple(m.strip().upper() for m in allow.split(",") if m.strip()) or (method,)
        route = Route(path=path, status=status, methods=methods, length=len(body), source=source)
        self._seen[path] = route
        return route

    async def discover(self) -> SurfaceResult:
        result = SurfaceResult(base_url=self.base_url)

        # 1. spec probe -- if the app hands us its contract, use it verbatim.
        for sp in SPEC_PATHS:
            r = await self._raw("GET", sp)
            if r and not _is_not_found(r[0], r[1]) and r[0] == 200 and _looks_like_spec(r[1]):
                result.spec_found = sp
                for path in _paths_from_spec(r[1]):
                    self._seen.setdefault(path, Route(path=path, status=0, source="spec"))
                break

        # 2. wordlist: single-segment, bare and id-scoped, across prefixes.
        for pre in self.prefixes:
            for n in self.nouns:
                for suffix in ("", "/1"):
                    await self._check(pre + n + suffix, "wordlist")
        # 2b. NESTED two-segment: /api[/v1]/<collection>/<noun>. Bare only -- id
        #     depth is reached far more cheaply by response mining + sub-resources
        #     below than by blindly appending /1 to every combination.
        for pre in ("/api/", "/api/v1/"):
            for coll in self.collections:
                for n in self.nouns:
                    await self._check(f"{pre}{coll}/{n}", "nested")

        # 3. response-driven: mine 2xx JSON for ids -> enumerate id-scoped siblings.
        await self._mine_response_ids()

        # 4. SUB-RESOURCES: nest nouns under one representative object per
        #    collection (/api/tickets/1/comments, /assign, /attachments...). One id
        #    per collection is enough -- the sub-resource SHAPE repeats across ids,
        #    so this finds the pattern without re-probing it for every object.
        await self._mine_subresources()

        # 5. Allow mining (LAST, over the FULL route set incl. sub-resources): a
        #    route that rejects GET answers 405 with an `Allow` header -> learn its
        #    real verbs so POST-only routes aren't mislabelled GET-only.
        for path, route in list(self._seen.items()):
            if route.methods == ("GET",) and route.status in (405, 500):
                for m in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                    r = await self._raw(m, path)
                    if r and r[2]:
                        methods = tuple(x.strip().upper() for x in r[2].split(",") if x.strip())
                        if methods:
                            self._seen[path] = Route(path=path, status=route.status,
                                                     methods=methods, length=route.length, source=route.source)
                        break

        result.routes = list(self._seen.values())
        result.probes_sent = self._probes
        return result

    async def _mine_response_ids(self) -> None:
        seeds = [p for p, r in list(self._seen.items()) if 200 <= r.status < 300]
        for p in seeds:
            r = await self._raw("GET", p)
            if not r or _is_not_found(r[0], r[1]):
                continue
            try:
                data = json.loads(r[1])
            except (ValueError, TypeError):
                continue
            items = data if isinstance(data, list) else [data]
            base_coll = re.sub(r"/\d+$", "", p)
            for it in items[:20]:
                if isinstance(it, dict) and "id" in it and self._budget_left():
                    await self._check(f"{base_coll}/{it['id']}", "response")

    async def _mine_subresources(self) -> None:
        # One representative id per collection (lowest), nest nouns under it.
        reps: dict[str, str] = {}
        for p in list(self._seen):
            m = re.match(r"^(.*)/(\d+)$", p)
            if m and (m.group(1) not in reps or int(m.group(2)) < int(reps[m.group(1)])):
                reps[m.group(1)] = m.group(2)
        for coll, idv in reps.items():
            for n in self.nouns:
                if not self._budget_left():
                    return
                await self._check(f"{coll}/{idv}/{n}", "subresource")


def _looks_like_spec(body: str) -> bool:
    return ('"openapi"' in body or '"swagger"' in body) and '"paths"' in body


def _paths_from_spec(body: str) -> list[str]:
    try:
        doc = json.loads(body)
        paths = doc.get("paths", {})
        # OpenAPI templates ids as {id}; keep them as-is (the graph normalises).
        return [p for p in paths.keys() if isinstance(p, str) and p.startswith("/")]
    except (ValueError, TypeError, AttributeError):
        return []
