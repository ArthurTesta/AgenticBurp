# Re-verification audit — AgenticBurp harness

Everything below was re-run or re-derived from the current code, not read off a prior handover. Where I quote a number, I produced it myself in this session.

## 1. Quantitative claims — all confirmed exact

| Claim (from `HANDOVER_NEXT_SESSION.md`) | Re-run result |
|---|---|
| `unittest discover`: 325 tests, OK | **325, OK** ✓ |
| `pytest test_plugin_system.py`: 26 passed | **26 passed** ✓ |
| 36 agents, 15 validators | **36, 15** ✓ |
| Java compile: 16 errors, 5 named categories, nothing new | **16 errors, same 5 categories** ✓ |
| Java logic-only suite: 48 passed, 0 failed | **48 passed, 0 failed** ✓ |
| `test_safety_gate.py`: 34 tests (via its own `Ran` line) | **34, OK** ✓ |
| `test_report_generator.py`: 20 tests | **20, OK** ✓ |

No drift, no rounding, no "close enough." This handover's numbers are trustworthy as of this snapshot.

## 2. Bug-fix claims — spot-checked by reproduction, not by reading

- **CORS fast-path fix** (`fast_path.select_agents_by_response_headers` previously matched header *values* only): I built a live `{'Access-Control-Allow-Origin': '*'}` dict and called the function directly — `cors` now fires. Confirmed, not assumed.
- **`CANONICAL_CATEGORIES` missing `recon`/`http_request_smuggling`**: both present now, 36 total. Confirmed.
- **`recon_validator.py`'s `exchange.method` exemption from the safety-gate structural test**: traced the actual call graph — the only live network call in that file hardcodes `method='GET'`; the `exchange.method` reference is written into a `TestPlan` record and an in-memory `endpoint.methods` set, never into a live send. The exemption is correctly justified, not a hidden hole.
- **Migration path** (`findings` table gaining `model`/`prompt_version`/`evidence`/`suggested_test`/`owasp_category`): I built an independent old-schema DB matching the pre-migration column set, inserted a row, and opened it with the current `store.py`. Result: old row survives intact, all five new columns present with correct defaults (`''`/`NULL`/`0`), no exception. This is a second, independent confirmation of the same claim `REVIEW_INSTRUCTIONS.md` asked for — it still holds.
- **`value_density` zero-cost formula** — this is actually **better than what an earlier review round flagged**. `REVIEW_INSTRUCTIONS.md` (written against an older snapshot) worried that `cost=0` would produce a huge, ranking-dominating `value_density` via a `1e-9` floor. The *current* code doesn't do that: it treats any `cost <= 0` as "unknown" and substitutes the neutral default (`1.0`), not a near-zero floor. I tested it directly — a zero-cost, low-severity finding scored *below* a normal-cost critical finding, not above it. The gap the earlier reviewer worried about has since been closed.

## 3. A real, previously unflagged defect: the critique pass's circuit breaker is inert

**The claim nowhere states this is broken — I found it by tracing object identity, not by reading a comment that admitted it.**

`OllamaClient.__init__` builds its own `circuit_breaker.OllamaCircuitBreaker("ollama")` directly, rather than going through `circuit_breaker.get_circuit_breaker("ollama")` — the shared-registry accessor that exists in the same module and *is* used correctly by `rate_limiter.get_token_limiter("ollama")` and `audit_logger.get_audit_logger()` (both confirmed as true global singletons by reading their source). The circuit breaker is the one subsystem that breaks this pattern.

This only matters because of who constructs `OllamaClient`:
- `orchestrator.py` builds **one** `OllamaClient`, once, at startup — its circuit breaker accumulates real failure state across the session, as intended.
- `analysis_pipeline.py`'s `_critique()` builds a **brand-new `OllamaClient()` inline, on every single critique call** (the code even says `# For now, we'll use a workaround`).

I verified directly: `OllamaClient(base_url='x').circuit_breaker is OllamaClient(base_url='x').circuit_breaker` → **False**. Two clients never share breaker state.

**Concrete failure case:** if Ollama starts erroring mid-session, the orchestrator's long-lived breaker will trip after 3 consecutive failures and stop hammering it (working as designed, and unit-tested in isolation). The critique path, by contrast, gets a fresh, always-CLOSED breaker every call and will keep making live HTTP calls to a down/erroring Ollama on every single exchange's critique step, indefinitely — the resilience control that exists specifically for this scenario doesn't apply to roughly half the LLM traffic this project generates.

I did not simulate a full 3-failure trip through `.call()` (that requires wiring an actually-failing coroutine through the async call path, which is more setup than the finding needs) — the object-identity result plus the constructor trace is sufficient to establish the defect exists; treat "does a real trip actually fail to propagate" as the one-line residual check if you want belt-and-suspenders confirmation. No existing test (`test_circuit_breaker.py`, `test_execution_protocol.py`, or anything else) exercises the critique path's breaker at all — grep confirms `critique` and `circuit_breaker` never appear together in any test file.

**Fix is small**: change `OllamaClient.__init__` to call `circuit_breaker.get_circuit_breaker("ollama")` instead of constructing `OllamaCircuitBreaker(...)` directly, and have `analysis_pipeline._critique()` accept an injected `OllamaClient` from the orchestrator rather than constructing its own. Both are consistent with the pattern already used correctly elsewhere in the same file.

## 4. Credential redaction — checked for bypass paths, none found in what I sampled

Per `REVIEW_INSTRUCTIONS.md`'s specific concern (does a header value reach an LLM prompt through any path other than `_user_prompt()`):

- `orchestrator.py`'s `prior_context` (built by `store.prior_findings_summary`) only ever selects the `summary` column via SQL — never `evidence`, and the query itself has no header content in it.
- Two near-identical `_exchange_text()` helpers exist (`orchestrator.py` and `analysis_pipeline.py`, genuinely duplicated code — a maintenance smell, not a security bug) that *do* interpolate raw header values — but both are used exclusively for a local, non-LLM string-containment check (`name in text`) to verify a component name/version is actually observed in the exchange. Neither ever feeds an LLM prompt. Confirmed by grepping every call site of each function — one call site each.
- The critique prompt (`analysis_pipeline._critique`) doesn't include raw headers at all — only method, URL, response status, and each finding's own `summary`/`evidence` text. Since findings are only ever produced by agents that saw redacted headers, there's no path for a real secret to reach the critique prompt through this route either.
- Spot-checked `deserialization_validator.py`, `cors_validator.py`, `oauth_validator.py`, `header_injection_validator.py` for evidence/summary fields that might echo a raw header/cookie *value* rather than its name or format: all of them report header **names**, detected **formats** (e.g. "Java serialized object"), or **parameter names** — never the raw value. No leak found in these four.

**What I didn't finish**: I checked 4 of 15 validators for this specific pattern, not all 15. This is disclosed shallow coverage, not a claim of exhaustiveness — the four checked are the ones most likely to touch header/cookie *values* (deserialization fingerprinting, CORS, OAuth, header injection), so the sample was chosen for risk, not convenience, but a full sweep would be cheap if you want it closed out completely.

The already-disclosed gap (a token inside a JSON response *body*, not a header, still reaches the prompt unredacted) remains open and is honestly labeled as such in `HANDOVER.md` — not a new finding, just confirming the project's own disclosure is accurate.

## 5. `Identity.role` string/enum fallback (`store.save_identity`'s `hasattr(identity.role, "value")`)

Traced the only production call site: `server.py`'s `POST /identities` handler does `role = identity_mod.IdentityRole(req.role)` — which raises (caught, turned into a 400) on any value that isn't a real enum member — **before** constructing the `Identity` object that reaches `save_identity`. The fallback branch in `store.py` is therefore defensive code for an input shape (`role` as a raw string) that cannot currently occur via the only live path into this function. Verdict: **not a loose type contract in practice** — it's dead-but-harmless defensive code. Worth a one-line comment saying so, otherwise a future reader will spend time on it wondering the same thing I just did.

## 6. `chaining.py` — real, material coverage gap the handover's phrasing understates

`HANDOVER_NEXT_SESSION.md` says chaining was "audited and fixed," citing `sqli` as an example of a category that "had zero path into any chain rule before this session." That sentence is true as written (it never claims full coverage) but easy to misread as "this is now handled." I counted directly:

**24 of 36 canonical categories have zero chain-rule reachability right now** — including `sqli`, `xxe`, `ssti`, `idor`, `csrf`, `jwt`, `nosql`, `command_injection`, `race_condition`, `info_disclosure`, `misconfig`, `crypto`, `csp`, `cors`, `api_security`, `file_upload`, `supply_chain`, `http_request_smuggling`, `recon`, `session_timeout`, `auth`, `business_logic_enhanced`, `anomaly`, `ai_llm`. Only 12 categories, spread across 14 rules, are chain-detectable.

This is a genuine business-value gap for a pentest tool, not a code defect: the highest-severity, most classic vulnerability classes (SQLi, XXE, SSTI, IDOR, CSRF) currently generate zero chain hypotheses no matter what else is found alongside them. An authenticated IDOR next to a blind SQLi — a textbook escalation pair — will never be flagged as a chain by this module as it stands. The 7 rules added this session were all built for the session's *new* categories (web cache poisoning, OAuth, subdomain takeover, etc.) — reasonable scoping, but it left the pre-existing high-value categories exactly where they started. Worth treating this as a named backlog item, not a "done" line item.

## 7. Structural/business observations (not defects, but worth your attention)

- **Duplicated `_exchange_text()` helper** in `orchestrator.py` and `analysis_pipeline.py` — identical logic, two copies. Low risk today (both are correct), but a future redaction-scope change made in one and not the other is exactly the kind of silent-divergence bug this project's own `HANDOVER.md` says it's been bitten by twice before (`categories.py`'s match bug, the `profileImage` SSRF miss). Worth collapsing into one shared function.
- **The chaining gap (§6) and the circuit-breaker gap (§3)** are both cases where a good test suite (325 green tests) coexists with a real hole, because the hole is in *what's wired together*, not in any one function's correctness — this matches the project's own stated failure pattern ("a well-tested module that sounds complete... but is never actually called from the live path"). That pattern predicted both of these findings before I went looking, which is a point in favor of the handover's self-diagnosis being accurate, even where its optimism about "fixed" items overshoots slightly.
- **Everything Java-side remains compile-verified or Montoya-free-unit-tested only** — the 16-error stub-compile state and the 48-test logic suite are both real, but neither is evidence the Burp extension actually runs. This is disclosed accurately in the handover and I have nothing to add — it's still the single largest verification gap in the project, and it's honestly labeled as such.

## Verdict

Ship this snapshot's tested claims as accurate — I could not find a single quantitative claim that didn't reproduce exactly, which is a meaningfully strong result across 325+48+16 checks. Before calling the session "done," I'd fix the two items below; neither is large:

1. **Fix the critique-path circuit breaker** (§3) — route `OllamaClient` through the existing shared-registry pattern, or inject one `OllamaClient` from the orchestrator into `analysis_pipeline`. This is a live-target resilience gap with a cheap fix and a concrete failure case.
2. **Re-scope the chaining.py claim** (§6) — either add a `test_chaining.py` assertion that names which categories are intentionally still unreachable (so the gap is a documented decision, not a thing the next session has to rediscover by counting), or spend the (probably small) effort to add rules for at least `sqli`+`idor` and `csrf`+`weak_auth`, which are higher-value pairs than several of the 7 already added.

Everything else — the redaction discipline, the migration path, the risk-ranking formula, the identity type contract — held up under independent re-derivation.
