# cache.py exchange-hash volatility fix

## The bug

`ExchangeCache.compute_exchange_hash()` hashed every request/response
header verbatim, plus full bodies. `cache.py`'s own docstring claims
"Typically 30-50% reduction in LLM calls for real-world spidering
workflows where the same endpoints are hit multiple times" — but any two
requests to the "same" endpoint in a real Burp session will normally
differ in `Date`, `ETag`, `X-Request-Id`, and similar tracing headers,
which are regenerated on every single request/response regardless of
whether anything analytically relevant changed. Verified directly:
two requests differing only in `Date`/`X-Request-Id`/`ETag` hashed
differently, guaranteeing a cache miss. The 22 pre-existing cache tests
only exercised byte-identical exchanges, so this was invisible to the
suite. In practice this cache was very likely delivering close to 0%
real-world hit rate for exactly the workflow it exists to speed up.

## The fix

Added `_VOLATILE_HEADER_NAMES` (`date`, `age`, `etag`, `x-request-id`,
`x-correlation-id`, `traceparent`, `tracestate`, `cf-ray`,
`server-timing`, `via`, `x-amzn-trace-id`, `x-runtime`,
`x-response-time`) and strip these from both request and response
headers before hashing. All other fields — including full bodies,
`Cookie`, `Authorization`, `Set-Cookie`, and CSRF-token headers/values —
are unchanged.

## What was deliberately NOT touched, and why

This harness's IDOR/access-control detection depends on being able to
tell "same request, different identity" apart — that's often exactly
what an analyst is testing (replay the same request as a different
user). `Cookie` and `Authorization` are therefore excluded from the
volatile-header list on purpose. Verified directly: two exchanges
differing only in session cookie still hash differently, so the cache
cannot serve one user's cached result to a different user's identical-
looking request.

CSRF-token-shaped values (e.g. `X-CSRF-Token`) were also left untouched.
Unlike `Date`/`ETag`, normalizing these away requires a judgment call —
CSRF tokens aren't identity-bearing, but stripping them is less clearly
risk-free than dropping a `Date` header, so this was scoped out rather
than assumed safe. Verified directly: two exchanges differing only in
CSRF token value still hash differently (still a miss, as before this
fix) — this is an intentional scope limit, not an oversight, and is a
candidate for a future, separately-reviewed follow-up if same-session
hit rate still isn't good enough after this fix.

Regression tests: `test_cache.py::TestExchangeHashing::
test_volatile_headers_do_not_affect_hash`,
`test_identity_bearing_headers_still_affect_hash`,
`test_csrf_token_values_still_affect_hash`.

## Not addressed here

Two other real compute-efficiency issues surfaced during this review,
left untouched:

- **Agent model tiering.** 26 of the 36 agents aren't listed in
  `config.yaml`'s `agents:` block and silently fall back to the
  coordinator's model (currently `llama3.1:8b` for all of them) — despite
  `config.yaml`'s own comment inviting cheaper/smaller models for
  "narrow, well-scoped classification tasks." The mechanism for
  per-agent model override already exists and works; nobody has ever
  populated it. This needs a decision about which specific smaller model
  is actually pulled and acceptable quality-wise, which isn't
  determinable from this sandbox (Ollama isn't reachable here — see
  `archive/HANDOVER.md` §1b).
- `coordinator.py`'s fail-open-to-all-36-agents fallback (`archive/HANDOVER.md`
  §4.4) and the duplicate `_resolve_known_vulnerabilities` call
  (`archive/HANDOVER.md` §4.1) — external-API compute, not LLM compute, but
  still real waste.
