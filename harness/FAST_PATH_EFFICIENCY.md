# fast_path.py over-dispatch fix

## The bug

`select_fast_path_agents()` is supposed to bypass the coordinator LLM call
only for exchanges with an obvious, specific signal (`fast_path.py`'s own
docstring: "conservative... never miss a relevant agent", "60-80% reduction
in coordinator calls"). In practice, once *any* strong signal fired
(URL/query/header/body pattern), the code unconditionally unioned in two
lookup tables keyed on HTTP method and response status. Those tables mapped
`GET`/`POST` and `200`/`201` — the overwhelming majority of all real
traffic — to 4-6 agents each. The result: fast-path returned ~6 agents for
almost every exchange regardless of actual relevance, including static
assets and generic unmatched paths. Measured before the fix:

| exchange | agents dispatched |
|---|---|
| GET /rest/products/search?q=apple, 200 | 6 |
| GET /rest/user/login, 200 | 6 |
| GET /static/main.js, 200 | 6 |
| GET /foo/bar/baz (nothing else matches), 200 | 6 |
| same, 404 | 4 |

No existing test asserted an upper bound on selection size, so this was
invisible to the 410-test suite the whole time.

## The fix

Removed `GET`/`POST` from `_METHOD_PATTERNS` and `200`/`201` from
`_STATUS_PATTERNS` — these four keys contributed agents unconditionally on
the majority of traffic and were the entire mechanism behind the floor.
Kept every other entry unchanged: 3xx/4xx/5xx status codes and
PUT/DELETE/PATCH methods are genuinely informative (a 403, a 500, or a
mutating verb tells you something a plain 200 GET doesn't), so those stay.
The PUT/DELETE/PATCH → `{idor, auth}` mapping specifically encodes an
established heuristic (state-mutating endpoints deserve an authorization
check even with no textual signature for it) and is cheap (2 agents, and
only added on top of an already-established signal — method/status have
never been standalone triggers here).

Measured after the fix (same exchanges):

| exchange | agents dispatched |
|---|---|
| GET /rest/products/search?q=apple, 200 | 4 |
| GET /rest/user/login, 200 | 5 |
| GET /static/main.js, 200 | 2 |
| GET /foo/bar/baz (nothing else matches), 200 | 2 |
| same, 404 | 2 |

Verified the fix doesn't blunt genuinely evidence-rich exchanges:

| exchange | agents dispatched |
|---|---|
| GET /admin/config, 403 | 4 (auth, idor, misconfig, supply_chain) |
| GET /api/users?id=1, 500, SQL error in body | 6 |
| POST /api/graphql, 200, json | 6 |

## What this does and doesn't prove

Every URL/query-param/header/body pattern — the parts of fast-path that
are actually evidence-based — are unchanged. Nothing that used to get
dispatched *because of specific content in the request or response* stops
getting dispatched. What's removed is exclusively the part that dispatched
agents *regardless of content*, purely because the method was common or
the status was a success code.

That said: per `HANDOVER.md` §4.6, this project has no live precision/
recall baseline against a real deployed model for fast-path or anything
else. I cannot empirically prove this changes zero real-world detections —
only that it removes the two table entries that fired unconditionally on
the two most common method/status values, and that every case exercised
above still selects agents proportionate to actual signal strength. If a
recall regression is discovered later, the fulcrum to re-examine first is
whether `PUT`/`POST` genuinely never need `sqli`/`xss` as a standalone
signal (they don't currently contribute it at all now) — that's the one
place a legitimate case for adding narrow, discriminating entries back
could plausibly exist, e.g. `POST` with no JSON/form content-type header
present at all.

## Fixed after review: sqli on GET searches with uncommon param names

A follow-up review correctly flagged: search functionality is commonly
implemented as a plain `GET` with a query parameter, and `sqli`/`xss` for
GET now depend entirely on the URL/query-param tables rather than a
blanket. The query-param table only recognized specific names (`id`, `q`,
`query`, `search`, `keyword`, `term`, `filter`, ...) — real search
features frequently use others (`s=`, `text=`, `k=`). Before this fix,
those cases fell through to `None` (coordinator fallback) instead of
fast-pathing, silently losing the efficiency win on exactly the case this
whole change was meant to keep fast.

Fixed: `select_agents_by_query_params()` now treats *any* non-empty query
parameter as carrying `sqli`/`xss` baseline risk, regardless of its name.
This is still narrower than the old GET-method blanket — it only fires
when a request actually carries a parameter value (static assets and
bare unmatched paths still correctly get nothing or fall back to
coordinator), not on every GET. Verified: `?s=apple`, `?text=apple`,
`?name=apple` all now get `{sqli, xss}`; `/static/main.js` (no query)
still gets only `misconfig`; a bare unmatched path with no query still
returns `None`. Regression test:
`test_fast_path.py::TestQueryParamPatterns::test_unrecognized_param_name_still_gets_sqli_xss_baseline`.

## Not addressed here

`coordinator.py`'s fail-open-to-all-36-agents fallback (`HANDOVER.md`
§4.4) and the duplicate `_resolve_known_vulnerabilities` call
(`HANDOVER.md` §4.1) are separate, real efficiency issues, left
untouched — out of scope for this fix.
