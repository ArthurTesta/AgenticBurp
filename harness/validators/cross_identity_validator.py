"""
Cross-identity (Autorize-style) access-control validator.

The single-exchange idor/auth/api agents can only GUESS at broken access control:
one captured request cannot distinguish "a 200 returning my own data" (secure)
from "a 200 returning someone else's data" (IDOR). The only way to tell is the
Autorize move -- replay the SAME request as a DIFFERENT identity (and
unauthenticated) and compare -- which needs credentials the harness deliberately
never stores.

This validator does exactly that, tester-fed: it reads other identities' session
headers from identity_headers (in-memory, never persisted -- the tester supplies
them, like configuring Autorize's low-priv cookie), replays the request as each,
plus an anonymous baseline, and runs the already-proven identity_compare decision
logic (authorization_boundary_compare):

  - CONFIRMED  -> another identity reached the owner's protected resource while
                 anon was denied: a real broken-access-control finding. Sets
                 finding.confirmed and boosts confidence (via _validate_findings).
  - not_confirmed (deterministic REJECT) -> every other identity AND anon were
                 denied: the control held. The orchestrator downgrades the
                 single-exchange hypothesis (mirroring access_control_gate).
  - skipped    -> no identities configured, out of scope, or non-GET (safe by
                 default; mutating replay is intentionally not attempted here).

Off by default: gated by validators.cross_identity.enabled AND
validators.active_enabled (it sends live requests), and scoped to
server.allowed_hosts. GET-only.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs

import httpx

import access_control_gate
import identity_compare
import identity_headers
from models import Finding, HttpExchange
from .base import Validator, ValidationResult

# A path segment that looks like an OBJECT IDENTIFIER (the thing an IDOR swaps):
# all-digits (/orders/1), a long hex/uuid (/tickets/a1b2c3d4-...), or a long hash.
_ID_SEGMENT = re.compile(r'^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,})$')
# Query params that carry an object reference.
_ID_QUERY_KEYS = {"id", "user", "user_id", "userid", "uid", "order", "order_id",
                  "account", "account_id", "oid", "object", "resource", "doc", "file"}

# Collection nouns that, when a NON-numeric slug directly follows them
# (/users/alice, /tickets/support-42), mark that slug as a specific object an
# IDOR could swap -- the case _ID_SEGMENT can't catch because the id is a name
# rather than a number/hash. A closed allowlist (singular + plural) keeps this
# conservative: only after one of these is a bare slug treated as an object.
_COLLECTION_NOUNS = frozenset({
    "users", "user", "accounts", "account", "orders", "order", "tickets", "ticket",
    "invoices", "invoice", "customers", "customer", "clients", "client",
    "documents", "document", "docs", "doc", "files", "file", "profiles",
    "posts", "post", "items", "item", "products", "product", "projects", "project",
    "reports", "report", "records", "record", "messages", "message",
    "comments", "comment", "notes", "note", "transactions", "transaction",
    "payments", "payment", "subscriptions", "subscription", "groups", "group",
    "teams", "team", "organizations", "orgs", "org", "companies", "company",
    "employees", "employee", "members", "member", "articles", "article",
    "images", "image", "photos", "photo", "videos", "video", "carts", "cart",
    "addresses", "address", "bookings", "booking", "reservations", "reservation",
    "appointments", "appointment", "events", "event", "folders", "folder",
    "resources", "resource", "entities", "entity",
    # relationship / sub-collection nouns -- a collection following a collection
    # (/products/reviews) is a nested list, not one object; listing them here
    # lets the nested-collection guard in _looks_like_object_slug skip them.
    "reviews", "review", "likes", "like", "tags", "tag", "roles", "role",
    "permissions", "permission", "followers", "following", "notifications",
    "notification", "replies", "reply", "ratings", "rating", "attachments",
    "attachment", "versions", "version", "revisions", "revision", "favorites",
    "favorite", "tokens", "token",
})
# Words that, even when they follow a collection noun, are NOT an object id:
# self-references (/users/me returns the caller's OWN data -- the TN3 FP) and
# route verbs / non-object views (/users/search, /orders/export). Denylisting
# biases toward SKIPPING (a miss, never a false positive) -- the safe direction.
_RESERVED_SLUGS = frozenset({
    # self-reference
    "me", "self", "current", "mine", "my", "own",
    # profile / meta views
    "profile", "account", "dashboard", "settings", "preferences", "home",
    "overview", "index", "default", "none", "null", "undefined",
    # CRUD / action / list verbs
    "new", "create", "add", "edit", "update", "delete", "remove", "save",
    "search", "filter", "query", "list", "all", "export", "import", "upload",
    "download", "bulk", "batch", "count", "stats", "summary", "history",
    "activity", "feed", "latest", "recent",
})


def _looks_like_object_slug(prev: str, seg: str) -> bool:
    """A non-numeric slug counts as an object identifier only when it directly
    follows a known collection noun and is not itself a self-reference/verb/
    sub-collection keyword -- so /users/alice matches, but /users/me,
    /users/search and /products/reviews do not. Deliberately conservative: when
    unsure it returns False (skip, no cross-identity), which is the safe
    direction -- a miss, never the /users/me-style false positive the
    object-identifier gate exists to prevent (TN3)."""
    if prev.lower() not in _COLLECTION_NOUNS:
        return False
    base = seg.split(".", 1)[0].lower()  # strip a trailing .json/.xml before matching
    if not base or base in _RESERVED_SLUGS:
        return False
    # A collection noun following a collection noun is a nested sub-collection
    # (/products/reviews), not a single object -- don't treat it as an id.
    return base not in _COLLECTION_NOUNS


def has_object_identifier(url: str) -> bool:
    """True iff the URL references a SPECIFIC object an IDOR could swap. A
    token-relative endpoint (/users/me, /profile, /account, /dashboard) has no
    such identifier -- it returns each identity's OWN data, so a cross-identity
    'match' there is two different self-profiles that merely share a JSON shape,
    not an access-control bug. This is the fix for the /api/users/me false
    positive (TN3). A numeric/hash id (/orders/1) is caught by _ID_SEGMENT; a
    named-slug id (/users/alice) by the collection-noun rule in
    _looks_like_object_slug."""
    p = urlparse(url)
    segments = [s for s in p.path.split("/") if s]
    if any(_ID_SEGMENT.match(s) for s in segments):
        return True
    if any(_looks_like_object_slug(prev, seg) for prev, seg in zip(segments, segments[1:])):
        return True
    return any(k.lower() in _ID_QUERY_KEYS for k in parse_qs(p.query))


class CrossIdentityValidator(Validator):
    name = "cross_identity"
    active = True  # sends live requests; only runs when validators.active_enabled

    def __init__(self, allowed_hosts: list[str] | None = None,
                 timeout: float = 10.0, max_identities: int = 3):
        self.allowed_hosts = set(allowed_hosts or [])
        self.timeout = timeout
        self.max_identities = max_identities

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        # Reuse the access-control gate's markers so the two never drift.
        return access_control_gate._is_access_control_class(finding.vulnerability_class)

    async def _probe(self, url: str, headers: dict) -> identity_compare.Probe:
        """Live GET, throttled. A method seam so unit tests can replace it with
        a canned responder and never touch the network."""
        import global_throttle
        await global_throttle.acquire()
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=False) as client:
            resp = await client.get(url, headers=headers or None)
        return identity_compare.Probe(resp.status_code, resp.text)

    def _skip(self, fc: str, why: str) -> ValidationResult:
        return ValidationResult(validator=self.name, status="skipped", finding_class=fc, summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        fc = finding.vulnerability_class
        if (exchange.method or "GET").upper() != "GET":
            return self._skip(fc, "cross-identity replay is GET-only (safe); a mutating request is not replayed here")
        host = urlparse(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(fc, f"host {host!r} is outside server.allowed_hosts scope")
        if not has_object_identifier(exchange.url):
            return self._skip(fc, "no object identifier in the path/query -- a token-relative "
                                  "endpoint (e.g. /users/me, /profile, /dashboard) returns each "
                                  "identity's OWN data and is not an IDOR candidate; cross-identity "
                                  "needs a specific object reference to swap")
        idents = identity_headers.identities_for_host(host)
        if not idents:
            return self._skip(fc, "no identities configured for this host -- supply another identity's "
                                  "session headers via POST /identities/session-headers (Autorize-style)")

        candidate = identity_compare.Probe(exchange.response_status or 0, exchange.response_body or "")
        try:
            anon = await self._probe(exchange.url, {})
        except Exception as e:  # network/scope error -- degrade, never crash the pipeline
            return ValidationResult(validator=self.name, status="error", finding_class=fc,
                                    summary=f"anonymous baseline probe failed: {e}")

        considered = 0
        rejects = 0
        for ident in idents[:self.max_identities]:
            try:
                attempt = await self._probe(exchange.url, ident["headers"])
            except Exception:
                continue
            considered += 1
            ev = identity_compare.evaluate(
                "authorization_boundary_compare", False, candidate, candidate, attempt, anon)
            if ev.verdict == identity_compare.Verdict.CONFIRMED:
                return ValidationResult(
                    validator=self.name, status="confirmed", finding_class=fc,
                    confidence=ev.confidence, confirmed=True,
                    summary=f"Cross-identity ({ident['name']}): {ev.summary}", evidence=ev.detail)
            if ev.verdict == identity_compare.Verdict.REJECTED:
                rejects += 1

        if considered == 0:
            return self._skip(fc, "no configured identity probe could be sent")
        if rejects == considered:
            return ValidationResult(
                validator=self.name, status="not_confirmed", finding_class=fc, confidence=0.8, confirmed=False,
                summary="Access correctly restricted: every configured other identity, and the anonymous "
                        "baseline, were denied this resource -- the single-exchange access-control hypothesis "
                        "is contradicted by an active cross-identity test.",
                evidence=f"{considered} identity/identities tested against {exchange.url}; all rejected")
        return self._skip(fc, "cross-identity comparison inconclusive (no confirmation, and not every "
                              "identity was cleanly rejected)")
