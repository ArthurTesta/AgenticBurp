# Changelog — audit follow-up session

Every number below was produced by actually running the command shown, in this session, after the change. Before/after test counts are both real runs, not estimates.

## Fixes

### 1. Critique pass's circuit breaker never shared state (real resilience gap)

**Before:** `analysis_pipeline._critique()` constructed a brand-new `OllamaClient()` inline on every call. `OllamaClient.__init__` built its circuit breaker via `OllamaCircuitBreaker("ollama")` directly, which does **not** register into the shared registry the way `get_circuit_breaker(name)` does. Result: `OllamaClient(...).circuit_breaker is OllamaClient(...).circuit_breaker` → `False`. The orchestrator's long-lived client accumulated real failure state; the critique path's breaker reset every call and could never trip, even while the main dispatch path had already stopped calling a failing Ollama instance.

**Fix:**
- `circuit_breaker.py`: added `get_ollama_circuit_breaker(name, config=None)`, a shared-registry accessor for `OllamaCircuitBreaker`, matching the pattern already used correctly by `rate_limiter.get_token_limiter()` and `audit_logger.get_audit_logger()`.
- `ollama_client.py`: `OllamaClient.__init__` now calls the shared accessor instead of constructing `OllamaCircuitBreaker(...)` directly.
- `analysis_pipeline.py`: `AnalysisPipeline.__init__` now accepts an `ollama_client` parameter; `_critique()` uses `self.ollama_client` instead of building its own. Falls back to building a standalone client (logged as such) only if none is injected, for tests/standalone use.
- `orchestrator.py`: passes its own long-lived `self.ollama` into `AnalysisPipeline(...)`.

**Verified:** `OllamaClient(base_url='x').circuit_breaker is OllamaClient(base_url='x').circuit_breaker` → now `True`. New tests: `test_circuit_breaker.py::TestGetOllamaCircuitBreakerIsShared` (4 tests) and `test_analysis_pipeline.py` (4 tests, new file) proving `_critique()` calls the injected client and constructs no second one.

### 2. `chaining.py`: 4 of the highest-value uncovered categories closed; the rest made an explicit, tested list

**Before:** 24 of 36 canonical categories, including `sqli`, `csrf`, `xxe`, `command_injection`, had zero chain-rule path. The prior session's "audited and fixed" framing was accurate but easy to over-read as complete.

**Fix:** Added 4 new `ChainRule`s, each grounded in a documented real-world escalation pattern (not invented for coverage's sake):
- `sqli+idor` — SQLi reachable only through a broken object-level access check
- `csrf+weak_auth` — CSRF whose real impact depends on session strength/lifetime
- `xxe+ssrf` — XXE's external entity resolution as a common route to SSRF
- `command_injection+known_vuln` — a low-confidence command-injection finding corroborated by a known-vulnerable version of the invoked binary

Added `TestChainRuleCoverageIsDocumented` in `test_chaining.py`, which pins the exact remaining 18 uncovered categories as a named constant (`KNOWN_UNCOVERED`) rather than leaving the gap undocumented. A future session that adds a rule updates the constant as part of that change; an accidental regression (a rule silently stops matching) fails the test instead of going unnoticed.

**Verified:** 5 new passing tests (`test_sqli_plus_idor_fires`, `test_csrf_plus_weak_auth_fires`, `test_xxe_plus_ssrf_fires`, `test_command_injection_plus_known_vuln_fires`, `test_categories_with_no_chain_rule_are_the_known_documented_set`), each constructing real `Finding`-shaped dicts and confirming `chaining.detect()` actually fires the new rule — not just that the rule object exists.

### 3. Duplicated `_exchange_text()` helper had silently diverged (found while fixing, not the original target)

**Before:** `orchestrator.py` and `analysis_pipeline.py` each had their own copy of the same exchange-flattening logic, meant to be identical. They weren't: `orchestrator.py`'s included `exchange.analyst_note`; `analysis_pipeline.py`'s omitted it. This meant whether an analyst's own note counted as evidence a component was actually observed in an exchange (for known-vulnerability confirmation) depended on which code path handled a given request — exactly the "duplicated logic silently diverges" pattern `HANDOVER.md` names as this project's own recurring failure mode.

**Fix:** New module `exchange_text.py` with one canonical `exchange_text()` function (includes `analyst_note`, matching the more-complete of the two prior copies). Both `orchestrator._exchange_text()` and `AnalysisPipeline._exchange_text()` now delegate to it.

**Verified:** New `test_exchange_text.py` (3 tests) — one specifically reproduces the exact regression (a component-identifying string placed only in `analyst_note` is now found via both call paths, and both paths are asserted to produce byte-identical text for the same input).

### 4. `store.save_identity`'s role-fallback branch — documented, not changed

Traced the only production call site (`server.py`'s `POST /identities`) and confirmed it always constructs `identity.role` via `IdentityRole(req.role)`, which 400s on invalid input before an `Identity` object is built. The `hasattr(identity.role, "value")` fallback in `store.py` is therefore defensive code for an input shape no current caller produces — not a loose type contract in active use. Added an inline comment explaining this so a future reader doesn't have to re-derive it. No behavior change; `test_identity.py`'s 8 tests still pass.

### 5. Full 15/15 validator sweep for credential-value leakage (no fix needed — confirmed clean)

Extended the audit's partial (4/15) sweep to all remaining validators (`api_security`, `crypto`, `csp`, `http_request_smuggling`, `race_condition`, `recon`, `sqlmap`, `subdomain_takeover`, `web_cache_poisoning`, `websocket`). Found two places that legitimately handle raw credential values (`recon_validator.py` records raw `Authorization`/`Cookie` values into an in-memory `EndpointInfo.headers` dict; `websocket_validator.py` replays a real `Cookie` value to test Cross-Site WebSocket Hijacking) — in both cases traced every downstream consumer and confirmed the raw value never reaches a `ValidationResult.summary`/`evidence`/`raw_output` field, an API response, or an LLM prompt. No fix made — introducing one for a theoretical, currently-nonexistent path would be its own source of risk. Flagged as a minor hygiene note below, not a defect.

## Full verification after all changes

```
cd harness && python3 -m unittest discover -p "test_*.py"   # Ran 341 tests, OK  (was 325)
cd harness && python3 -m pytest test_plugin_system.py -q    # 26 passed          (unchanged)
```

Java side untouched this session — reconfirmed unchanged: 16 compile errors (same 5 categories), 48/0 logic-suite tests.

## Not fixed — explicitly still open

- **19 of 36 categories still have no chain-rule path** (`ai_llm`, `anomaly`, `api_security`, `auth`, `business_logic_enhanced`, `cors`, `crypto`, `csp`, `file_upload`, `http_request_smuggling`, `info_disclosure`, `jwt`, `misconfig`, `nosql`, `race_condition`, `recon`, `session_timeout`, `ssti`, `supply_chain` — see `test_chaining.py::KNOWN_UNCOVERED`). This is now a documented, tested constant rather than a silent gap, but the categories themselves are still not chain-detectable. Deliberately not force-filled with invented rules.
- **`recon_validator.py`'s in-memory retention of raw header values** (§5 above) — zero current risk, but the value sits in a data structure that outlives the reason it doesn't need to be there. A cheap future hardening: redact at collection time (`endpoint.headers[header.lower()] = redact(value) if header.lower() in SENSITIVE else value`) so a future feature can't accidentally serialize it. Not done this session — no live path currently exposes it, so the fix would be pure prevention with no reproducible bug behind it, which didn't meet the bar for a code change today.
- **The known, pre-existing gap disclosed in `HANDOVER.md`**: a credential inside a JSON response *body* (not a header) still reaches an LLM prompt unredacted. Unchanged this session; still accurately disclosed.
- **The Java extension has still never run in a live Burp session.** Unchanged, unrelated to this session's fixes.

## Addendum — forced-egress safety proxy (M2)

Built `harness/safety_proxy_addon.py`, a mitmproxy addon implementing the design in `PROXY_WATCHER_TODO.md`, plus `harness/test_safety_proxy_addon.py` (22 tests) and `PROXY_SETUP.md`. Full detail in `PROXY_WATCHER_TODO.md`'s updated status section. Summary:

- **Fail-closed by design**: any exception in request handling kills the flow rather than falling through to mitmproxy's own default (log-and-continue = allow). The addon refuses to start if mitmproxy is configured with `ignore_hosts`, `allow_hosts`, `tcp_hosts`, or `udp_hosts` — all real options that would let traffic silently skip inspection.
- **Cross-component burst ceiling**: `CombinedBurstTracker` enforces a ceiling on mutating requests per host across every source the proxy sees (Python, sqlmap, Java/Burp combined) — the one accounting an in-process gate structurally cannot do alone.
- **A real, previously-undetected bug found and fixed in `safety_gate.py` itself** while building this: `classify()` never URL-decoded before checking hard-deny patterns, so `rm+-rf+/` / `rm%20-rf%20/` classified as SAFE where `rm -rf /` correctly classified as HARD_DENIED. This predates this session and affected the in-process gate too, not just the new proxy. Fixed with a decode-then-check pass; 5 new regression tests in `test_safety_gate.py`.
- **CA trust setup is source-verified, not guessed**, for two of the three legs: cloned sqlmap's actual repository and read `httpshandler.py` directly (confirms sqlmap disables all certificate verification unconditionally — needs no CA trust at all) and read httpx's installed `_config.py`/`_client.py` directly (confirms `SSL_CERT_FILE`/`HTTPS_PROXY` env vars work for every httpx client in this codebase, since none override `verify`/`trust_env`). The Burp/JVM leg is standard `keytool` procedure, explicitly marked as unverified against a real Burp instance.
- **Full test suite: 368 passing** (up from 341 before this addendum — 22 new addon tests + 5 new safety_gate regression tests).
- **Not done**: the actual live-target run (`PROXY_SETUP.md` §5) — starting the proxy, pointing real clients at it, and confirming traffic flows end-to-end. This sandbox cannot run a real Burp instance or a real sqlmap binary, so two of the seven verification steps in that section cannot be completed here regardless of further code work.

## Addendum 2 — M5 (cost-aware ranking) and M4 (cross-run suppression)

### M5 — `risk_allocator` wired into `report_generator.py`

**Real scope was larger than previously stated**: `risk_allocator.rank()` and `allocate_retry_budget()` had zero callers anywhere in the live codebase (confirmed by grep before writing code) — not a partially-wired cost term as characterized in `MILESTONES.md`.

Wired `risk_allocator.RiskScore`/`rank()` into `report_generator.generate_markdown_report()`: unconfirmed findings are reordered by cost-aware `value_density` when an optional `effort_ledger` parameter is supplied, using real `EffortLedger.average_tokens(CallKind.VALIDATION_RETRY)` data. Confirmed findings keep the plain severity/confidence sort — a forward-looking cost question doesn't apply to findings already resolved. Backward compatible: omitting the parameter (the default) reproduces the exact prior behavior.

**Honesty note preserved in the code itself**: `cost` here is a per-call-kind average, not a true per-finding cost — this codebase doesn't persist which finding a given validation retry's tokens were spent confirming, so per-finding attribution isn't available data. Documented as an approximation, not claimed as precision it doesn't have.

5 new tests in `test_report_generator.py` (25 total in that file), including a regression guard for same-category/same-URL findings not being conflated during reordering (RiskScore has no back-reference to the ReportFinding it came from).

### M4 — cross-run finding suppression

New `store.py` API: `suppress_finding()`, `unsuppress_finding()`, `is_suppressed()`, `list_suppressions()`, backed by a new `finding_suppressions` table. `all_host_findings()` now excludes suppressed findings by default (`include_suppressed=True` to see them) and returns `fingerprint`/`suppressed` on every row.

**Side effect confirmed with a test, not assumed**: because `orchestrator.py`'s chain-detection step consumes `all_host_findings()`'s default output, suppressing a finding also removes it from future chain-detection input on that host — not just from the main findings list.

**Known limitation, stated in the code**: suppression is keyed on the existing `fingerprint` scheme, which includes the agent's free-text summary. A re-run producing a differently-worded summary for the same underlying issue won't match a previous suppression and will resurface. Built on the existing identity scheme rather than silently reworking `persist_findings()`'s fingerprint computation, which would be a separate, more invasive change.

New server.py endpoints: `POST /findings/suppress`, `DELETE /findings/suppress/{fingerprint}`, `GET /findings/suppressions`. Verified via a **new `test_server.py`** using FastAPI's real `TestClient` for genuine HTTP round-trips — no test file previously exercised any of server.py's endpoints this way; this is the first one, scoped to the new endpoints.

`report_generator.py`'s summary line now discloses a suppressed-finding count when nonzero, rather than silently omitting suppressed findings from the total with no indication they exist. Each rendered finding also shows its fingerprint so an analyst knows what to reference when suppressing a false positive.

**Full verification, all real runs:**
```
cd harness && python3 -m unittest discover -p "test_*.py"   # Ran 389 tests, OK (after M4+M5, before recon hardening)
```

### Small item — `recon_validator.py` header-value redaction at collection time

Previously flagged as zero-current-risk hygiene, now fixed: all four sites in `recon_validator.py` that stored raw header key/value pairs into `EndpointInfo.headers` now redact sensitive VALUES (Authorization, Cookie, Set-Cookie, X-API-Key, X-Auth-Token) via the existing `security.redact_headers()` — the same function already used elsewhere in this project for this exact purpose, not a new redaction mechanism. Header NAMES are preserved (needed for `auth_required`/`sensitive` classification, which is name-based and unaffected). Tech-fingerprinting (`_analyze_header_for_tech`) still sees real values, since fingerprint headers are never sensitive and redacting them would break fingerprinting for no safety benefit.

New `test_recon_validator.py` (6 tests) — the first dedicated test file for this validator, which previously had zero direct unit test coverage (only an indirect mention in `test_safety_gate.py`'s bypass-exception list).

**Full verification, final count for this session:**
```
cd harness && python3 -m unittest discover -p "test_*.py"   # Ran 395 tests, OK
cd harness && python3 -m pytest test_plugin_system.py -q    # 26 passed
```
Java side unchanged and reconfirmed (16 compile errors, same 5 categories; 48/0 logic-suite tests) — no Java files were touched this session.

### Not done this session

- **M3 (Java-side Identity wiring)** — not started. Requires editing `ValidationExecutor.java`'s `identityCompare()` to query the `/hosts/{host}/sessions` endpoint instead of its current `JOptionPane` picker. Deliberately not attempted without more session budget: unlike the Python-side work above, this can only be "compile-verified" or "Montoya-free-unit-test-verified" in this sandbox, never runtime-verified against real Burp UI behavior, and deserves dedicated attention rather than being rushed at the end of a session already covering three other pieces of work.
- **M6 (deciding chain-rule coverage scope deliberately)** — not addressed further this session; the 19-category gap from the previous session's work remains as documented.
- **M1 (live-target run)** — structurally impossible in this sandbox; unchanged.

## Addendum 3 — M3 (Java-side Identity wiring)

**Scope delivered:** `ValidationExecutor.identityCompare()`'s picker now shows a registered identity's name and role (e.g. "Alice (admin) -- GET /api/orders/5 [a1b2c3d4]") for any candidate exchange with a matching session, falling back to the exact prior unlabeled format otherwise. A new "Register as identity session..." context-menu action lets an analyst link a captured exchange to an existing identity directly from Burp, so the read side has something to read without needing curl.

**New files:**
- `IdentityLabelResolver.java` (`com.harness.llm.logic`) — Montoya-free label-resolution logic, matching this project's established pattern of keeping decision logic separate from Montoya-dependent I/O. 11 new tests in `IdentityLabelResolverTest.java`, run via the existing reflection-based `RunTests` harness. **Logic-suite total: 59 passed, 0 failed (up from 48).**

**Modified files:**
- `AnalysisModels.java` — added `IdentityInfo`/`SessionInfo`, with field names verified against `store.py`'s actual `list_identities()`/`sessions_for_host()` output (not assumed from `identity.py`'s raw dataclass fields, which don't match — `sessions_for_host()` already JOINs the identity's name/role in, a detail that would have produced a silently-broken lookup if assumed rather than checked).
- `HarnessClient.java` — added `listIdentities()`, `sessionsForHost()`, `createSession()`, following the exact existing method pattern (auth headers, timeout, `HarnessException` wrapping).
- `ValidationExecutor.java` — wired `IdentityLabelResolver` into `identityCompare()`'s picker; added `netloc()` (host-extraction matching `store.py`'s `host_of()`) and `fetchSessionLookup()` (fails open to the pre-existing unlabeled behavior on any harness-server error, since nothing here authorizes a mutating action — unlike `safety_gate.py`/`safety_proxy_addon.py`, a less-informative label is the correct failure mode, not a blocked request).
- `HarnessContextMenu.java` — added the `AnalysisRunner.registerSession()` write-side action and its menu item (single-selection only, deliberately — linking multiple selected requests to one identity in bulk would be wrong more often than right).

**Verified precisely, not assumed:**
- Traced Java's `exchangeFingerprint()` and Python's `planner.exchange_fingerprint()` formulas character-by-character and confirmed they produce identical output for the normal case (both `\x1f`-join method/URL/sorted-lowercased-headers/body identically) — this is what makes a `Session.exchange_hash` computed by one side matchable against the other's fingerprint at all.
- Recompiled the full stub set after every edit (four times across this addendum) and diffed the error output each time: went from the documented 16 to 19, with all 3 new errors traced to the two `com.google.gson`/`com.google.gson.reflect` imports the new `listIdentities()`/`sessionsForHost()` methods require (`TypeToken` for generic list deserialization) — the exact same "gson isn't on this stub-only sandbox's classpath" root cause as the pre-existing baseline, not a new defect category. `ValidationExecutor.java` and `IdentityLabelResolver.java` compile with **zero errors**.

**Explicitly not done or verified — stated plainly, not glossed over:**
- **No real Burp runtime verification.** Every claim above is "compiles cleanly" or "Montoya-free logic unit-tested," never "confirmed the picker actually shows this in a running Burp instance." This sandbox has no real Burp/Montoya jar and cannot produce that evidence regardless of further code changes here.
- **No identity-creation UI.** `registerSession()` requires at least one identity to already exist via `POST /identities` (curl or equivalent) — creating identities from Burp's UI was scoped out to keep this addendum bounded; the dialog explicitly tells the analyst what to do if none exist yet, rather than silently failing.
- **Cross-language fingerprint drift has no automated guard.** If `store.host_of()`'s normalization or `planner.exchange_fingerprint()`'s formula ever changes on the Python side, `ValidationExecutor.netloc()`/`exchangeFingerprint()` must be updated to match by hand — there is no test that spans both languages to catch this automatically, a limitation stated in `netloc()`'s own docstring rather than left implicit.

## Addendum 4 — M1: live-target verification, at last

Previously classified as "structurally impossible in this sandbox." That was wrong — it required getting a real target running (the recipe existed in `HANDOVER.md`, just needed executing and re-verifying), not new infrastructure. See **`LIVE_TARGET_VERIFICATION_REPORT.md`** for the full account. Summary:

Got a real OWASP Juice Shop instance running, hand-verified two critical vulnerabilities (SQLi login bypass, IDOR on `/rest/basket/{id}`), independently confirmed the IDOR via this session's own `IdentityCompareLogic.java` against the real captured data (first real-world run of that class), confirmed a CORS misconfiguration via the live `cors_validator.py`, and watched the `sqli+idor` chain rule (added earlier this session) fire for real.

**Then, running the actual `orchestrator.analyze()` pipeline surfaced three real, previously-undiscovered bugs**, none of which any of the 407 unit tests could have caught, because none exercised the true live call path:

1. **Crash**: `analysis_pipeline.py`'s `_resolve_known_vulnerabilities` imported a class name (`Component`) that doesn't exist anywhere in this codebase. Fixed. Found, but did **not** fix, a related unresolved issue: a second, non-identical copy of this method in `orchestrator.py` is also live-reachable on the same path, likely causing known-vulnerability lookups to run twice per exchange.
2. **Severe**: every one of the 36 specialist agents was completely non-functional. `validate_system_prompt()` applied a check meant for untrusted user content to the harness's own trusted, hardcoded system prompt, which contains a literal `"; so"` in shared boilerplate that the shell-injection pattern matched. Fixed by scoping the check to user prompts only, where it belongs.
3. **Severe**: the same pattern, once correctly scoped to user prompts, turned out to reject ordinary HTTP syntax like `Content-Type: application/json; charset=utf-8` — while simultaneously missing realistic attack strings with a space before the operator. Root cause: a `\b` anchor against non-word-character operators, confirmed precisely by direct testing both directions. Replaced with a pattern requiring a recognized dangerous command name after the operator.

With all three fixed, the real pipeline now gets all the way through prompt construction and validation, genuinely attempts to reach Ollama, and fails cleanly and informatively — the correct, designed behavior for the one environmental gap (no Ollama in this sandbox) that remains.

**Full verification:**
```
cd harness && python3 -m unittest discover -p "test_*.py"   # Ran 407 tests, OK (up from 395)
```

**Not done**: reconciling the duplicate `_resolve_known_vulnerabilities` implementations; root-causing why `sqlmap` missed the hand-verified SQLi; auditing the rest of `blocked_patterns` against real traffic (only the one pattern that actually broke was fixed); a full multi-agent run once a real Ollama backend is available. All named explicitly in `LIVE_TARGET_VERIFICATION_REPORT.md`.
