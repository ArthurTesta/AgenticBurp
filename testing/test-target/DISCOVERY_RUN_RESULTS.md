# PixelMart discovery run — results

**Read this before the numbers below mean anything to you.** Two separate
substitutions are stacked in this run, and both matter:

1. **Claude substituted for the LLM at every call site** (agents,
   coordinator, critique) — Ollama isn't reachable in this sandbox. I
   read each agent's *real, harness-constructed* prompt (via a recording
   proxy in front of the actual `OllamaClient`) and answered from the
   evidence shown, the same discipline a real model call is instructed
   to follow. This is the same substitution the project's own
   `HANDOVER.md` used for its Juice Shop sessions.
2. **Claude built PixelMart and wrote the answer key.** Unlike the Juice
   Shop sessions, there's a second, harder-to-remove contamination layer
   here: I already know where every bug is. I read each prompt and
   reasoned only from what was actually shown to that agent (redacted
   headers stayed redacted in my reasoning; ambiguous evidence got
   hedged, not resolved using outside knowledge) — but I can't fully
   certify my own blindness to myself. Treat the **recall** numbers below
   as a ceiling on what a careful reasoner *could* find from this
   evidence, not a prediction of what `llama3.1:8b` or `gemma2:9b`
   actually would. The **dispatch-coverage gaps** found below are real
   regardless of who's reasoning, though — those are properties of
   `fast_path.py`'s pattern tables and `security.py`'s redaction list,
   not of any model's judgment.

**What this run does prove, independent of both caveats above:** the
architecture runs end-to-end for the first time in this project's
history — real dispatch, real critique gating, real known-vulnerability
lookup (a genuine network call to the GitHub Advisory API), real
cross-exchange chaining, and real caching all executed as unmodified
production code, not simulated.

---

## Bugs found and fixed by this run

Both were previously-unknown, and both are the first-ever real exercise
of `orchestrator.analyze()`'s cache read/write paths — no existing test
constructs a real `Orchestrator` and calls `analyze()` through a full
cache cycle.

| # | Bug | Effect | Fix |
|---|---|---|---|
| 1 | `cache.compute_exchange_hash` doesn't exist — it's `cache.ExchangeCache.compute_exchange_hash` | Crashed **every** successful, non-bypassed call to `analyze()`, on both the cache-hit and cache-write paths | Both call sites in `orchestrator.py` corrected |
| 2 | Cache-hit reconstruction of `AnalysisResponse` passed `summary` both via `**model_dump()` and explicitly | `TypeError: multiple values for keyword argument 'summary'` on every cache hit | Added `"summary"` to the `exclude` set |

Full 421-test suite still green after both fixes.

## Architecture findings (real, not model-dependent)

1. **`jwt` and `csrf` have zero entries anywhere in `fast_path.py`.** They
   can only ever be reached via the coordinator LLM call. Across all 22
   real exchanges in this run, the coordinator was **never invoked
   once** — fast_path was confident every time (good for cost; bad for
   these two agents' reachability in practice). Recommend adding
   URL/header patterns that route to these agents (e.g. any
   `Authorization: Bearer <jwt-shaped-token>` implies `jwt`; any
   CSRF-token-named header/param implies `csrf`) so they aren't
   effectively dead code.
2. **No URL pattern for `/order`, `/orders`, `/invoice`, `/booking`, or
   similar** in `fast_path.py`'s `idor`-relevant table — only `/user`,
   `/users`, `/profile`, `/account`, `/me`. `/api/orders/<id>`, a
   textbook IDOR shape, never dispatches `idor` unless something else
   incidentally fires it.
3. **`fast_path.py` never inspects request-body content or response
   numeric values at all** — only response body *text* via regex. A
   business-logic exploit that shows up as a negative number in a JSON
   response (`"total_price": -399.95`) produces no matchable signal.
   `business_logic` was correctly dispatched on the *safe* `sort`-param
   test (TN4) and never dispatched on the *actual* negative-quantity
   exploit (TP7) — a concrete, reproducible illustration of exactly the
   precision/recall tension this whole exercise exists to surface.
4. **`security.redact_headers()` strips `Authorization` before any agent
   ever sees it.** This is almost certainly the right default for
   privacy, but it has a real cost: the `alg:none` JWT-forgery bug (TP11)
   is **structurally invisible** to every current agent, since the
   evidence needed to catch it (the token's own header field) never
   reaches the model. No amount of prompting or model quality fixes this
   — it needs either a narrow, deliberate exception for JWT structure
   (not full token value) or a dedicated deterministic JWT-parsing check
   analogous to `github_advisories.py`.

## Scored against ANSWER_KEY.md

**True positives — 8 of 12 hit, 1 partial, 3 missed:**

| # | Bug | Result |
|---|---|---|
| 1 | SQLi auth bypass | **Hit** — via `auth` (0.85), not the dedicated `sqli` agent, which was never dispatched for `/api/login` at all (no query params, POST body isn't pattern-matched, URL pattern for `/login` doesn't include sqli). Real coverage, but fragile/incidental. |
| 2 | SQLi UNION exfil | **Hit** — `sqli`, 0.97, direct |
| 3 | IDOR profile | **Hit** — `idor`, 0.55, honestly hedged as a candidate (correctly can't confirm cross-identity from one redacted exchange) + a genuine chaining detection linking it to finding #2 |
| 4 | IDOR order | **Missed** — `idor` never dispatched (architecture gap #2 above) |
| 5 | Reflected XSS | **Hit** — `xss`, 0.95 |
| 6 | Stored XSS | **Hit** — `xss`, 0.95 |
| 7 | Business logic (negative qty) | **Missed** — `business_logic` never dispatched (architecture gap #3 above) |
| 8 | Race condition | **Partial** — missed on the success response alone; hit (`race_condition`, 0.6, correctly framed as a candidate) once the rejection response was also shown. A harness that only ever captures one side of this exchange in practice would miss it. |
| 9 | SSRF | **Hit** — `ssrf`, 0.9 |
| 10 | Path traversal | **Hit** — via `ssrf`'s stated "file path" scope, 0.9 |
| 11 | JWT `alg:none` forgery | **Missed** — structurally invisible (architecture gap #4 above); the `idor` finding that did fire is a real but different, generic concern, not this bug |
| 12 | Unauthenticated admin config | **Hit** — `auth`, 0.97, direct |

**True negatives — 6 of 6 correctly left alone**, including the two
deliberately similar-looking-to-vulnerable cases (safe parameterized
lookup, allowlisted `sort` param). One low-confidence (0.3), explicitly
`basis: assumed` note on TN4 about downstream XSS risk from unescaped
JSON content — correctly distinguishes "this JSON response itself
doesn't execute" from "something downstream might mishandle it," which
is the calibrated behavior the project's own design asks for, not a
false positive.

## What worked end-to-end for the first time

- Real critique gating: fired exactly 10 times, matching the real
  `confidence_threshold: 0.5` config value against the real findings
  produced — verified by checking which exchanges' top finding
  confidence cleared 0.5.
- Real critique verdicts landed on findings (`review_verdict: "survived"`
  correctly appears on reviewed findings) — never previously exercised
  end-to-end.
- Real chaining: `chaining.py` correctly linked the SQLi finding to the
  IDOR finding on the same host into a `potential-attack-chain:sqli+idor`
  entry, unprompted, via deterministic code.
- Real known-vulnerability lookup: a genuine network call to
  `api.github.com` for the `Werkzeug` component, which correctly hit
  GitHub's real unauthenticated rate limit — confirms the pipeline
  reaches real external APIs, not just that the code compiles.
- Real cache hit: replaying an identical exchange was correctly served
  from cache (`"(cached)"` in the summary) — the exact code path that
  was broken by bug #1/#2 above until this run.

## Fixes applied after the first run

All three misses were diagnosed to root causes, not model reasoning
failures, and all three are now fixed:

| Miss | Root cause | Fix | Verified |
|---|---|---|---|
| IDOR order (#4) | No `/order`/`/orders`/etc. URL pattern in `fast_path.py` | Added an order/invoice/booking/ticket/transaction pattern → `idor, auth, misconfig` | `idor` now dispatches on `/api/orders/<id>`; re-run produces a genuine 0.55-confidence candidate finding |
| Business logic (#7) | `fast_path.py` never inspects request-body content or numeric values, only response-body text | Added `select_agents_by_body_anomalies()`: a structural (JSON-aware, not regex) check for a negative value in a money/quantity-shaped field, checked against both request and response body | `business_logic` now dispatches; re-run produces a 0.9-confidence finding directly citing the negative `total_price` |
| JWT `alg:none` (#11) | `security.redact_headers()` fully redacted `Authorization`, hiding the token's algorithm field along with the payload/signature | `redact_headers()` now discloses *only* the JWT header segment (e.g. `{"alg":"none"}`) for JWT-shaped bearer tokens — payload and signature stay fully redacted; non-JWT tokens are unaffected | Confirmed the `alg:none` value now reaches the agent; re-run produces a 0.9-confidence finding |

Full 432-test suite green after all three fixes (11 new regression tests
added: 6 for the two `fast_path.py` fixes, 5 for the `security.py` fix,
including explicit checks that opaque API keys, Basic auth, and
malformed JWT-shaped tokens still get full redaction with no regression).

**Re-scored: 11 of 12 true positives now hit, 1 still conditional (race
condition — inherent to needing to see the rejection response, not a
bug), 6 of 6 true negatives still correctly clean** — no new false
positives introduced by any of the three fixes.

---


This is the first time this project has had **any** numbers, on
**anything**, from a live end-to-end run. They should be read as: the
plumbing works, precision looks strong (zero confident false positives
across 6 true-negative traps), and recall has three concrete,
diagnosed, fixable gaps that trace to fast_path's pattern coverage and
header redaction — not to reasoning quality. What they cannot tell you
is what the actually-configured `llama3.1:8b`/`gemma2:9b` would really
notice; that still requires a reachable Ollama instance and a fresh
model with no knowledge of this app, which this sandbox can't provide.
