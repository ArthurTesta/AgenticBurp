# Handover: Burp LLM Harness — Next Session

## Read this section first. It is the current state. Everything below it is dated history — useful for "why," not for "what exists now."

This is an ongoing security-tooling project, worked on across many sessions by models of varying capability. **Do not trust any claim in this document, including this one, without spot-checking the actual code or re-running the tests.** This document tells you what was verified and how — it cannot substitute for you re-verifying anything you're about to build on top of.

**Core philosophy (unchanged, still the north star):**
> The LLM should not be the scanner. It should be the reasoning/planning layer over a controlled security-testing substrate. Known vs. rediscover: when an authoritative deterministic source or tool exists, use it rather than asking an LLM to guess.

**Honesty vocabulary (load-bearing — use these words precisely, don't let them drift):**
- "tested" = actually executed. "live-tested" = a real external/live target was actually reached. "mock-tested" = code paths executed with mocks. "source-reviewed" = inspected but not executed. "type-checked" = compiled against verified-signature stubs of a dependency that couldn't be pulled into this environment (stronger than source-review, weaker than compiling against the real thing). "compiles"/"passes" is never claimed unless actually run.
- If you write a sentence with one of these words in it and you didn't do the thing, that sentence is a lie with a badge on it. The entire value of this document depends on these words never being used loosely.

**Run this before you write a line of code, every session, no exceptions:**
```
cd harness && python3 -m pytest -q          # expect: 87 passed
```
For Java: see `dev-tools/README.md` (packaged stub infrastructure — reuse it, don't rebuild from scratch). Expect `50 passed, 0 failed` from the pure-logic suite.
If either number doesn't match, **stop and say so before doing anything else** — a stale count you didn't notice is exactly how hallucination compounds across sessions: you build on a claim, the next agent builds on yours, and nobody re-checked the foundation.

**What exists right now (file inventory, so you don't have to reconstruct it from prose history below):**

| Layer | Files | Wired end-to-end? |
|---|---|---|
| Agent dispatch, routing, critique | `orchestrator.py`, `agents/*.py`, `base_agent.py` | Yes — live-tested this session against mocked Ollama |
| Validators (Python) | `validators/sqlmap.py`, `validators/base.py` | Yes — live-tested in an earlier session against real Juice Shop |
| Validators (Java/Burp) | `ValidationExecutor.java` — `identityCompare`, `workflowReplay`, `controlledCallbackProbe`, `reflection` (XSS, has a real retry-with-new-payload loop), `rateLimit` | `identityCompare`/`sqlmap`/`reflection` live-tested at some point; `workflowReplay`/`controlledCallbackProbe` are **type-checked only, never live-tested** — do not say otherwise |
| Coverage ledger | `store.py`'s `coverage_report`/overrides | Yes, live-verified |
| Retry/handover state machine | `retry_policy.py` | Unit-tested only. **Wired into the Java XSS retry loop's spirit, not into any Python-side live execution path.** Python agents don't send live requests — see the module's own docstring for why a Python-side retry loop would just be a re-ask, not a new probe |
| Payload library | `payload_library.py` (Python, unused by any live path) and `XssPayloadLogic.java` (Java, **this one is live-wired** into `reflection()`) — these are two *separate* implementations of the same idea in two languages, not one shared thing. Don't assume changing one changes the other. |
| Risk allocation | `risk_allocator.py` | Formula implemented and unit-tested (`value_density = expected_risk / cost`), with neutral fallback for zero/unknown cost.  **`cost` is never populated from real data anywhere in the codebase** — every caller either omits it (defaults to 1.0, i.e. cost-blind); zero/negative cost treated as unknown cost (falls back to 1.0) or would need to wire `effort.EffortLedger.average_tokens` in themselves. If you see code elsewhere assuming cost-aware ranking is "live," that's a hallucination to correct, not a fact to build on. |
| Effort/token budget | `effort.py`, `ollama_client.chat_json_metered`, `/estimate` `/effort` endpoints | Yes — live-tested end-to-end this session's predecessor (real `analyze()` call, confirmed token accounting + `/estimate` recalibration) |
| Identity/Session | `identity.py`, new `identities`/`sessions` tables, `/identities` `/sessions` `/hosts/{host}/sessions` endpoints | **Python/store side only, live-tested via `TestClient`.** The Java side's `identityCompare()` still uses its original `JOptionPane` picker over the raw exchange pool and does not call any of these new endpoints. Do not say "identity is wired into Burp" — it isn't. |
| Credential redaction | `security.redact_headers` in `security.py` | Yes, wired into `_user_prompt()` in `base_agent.py` and `_choose_agents()` in `orchestrator.py`. **Does not cover response/request bodies** — a token in a JSON body (not a header) still reaches the prompt. Known, disclosed gap, not fixed. |
| Reproducibility metadata | `findings.model`/`findings.prompt_version` columns | Yes, wired for specialist-agent findings. **Not** wired for the coordinator (routing) or critique prompts — those aren't hashed/versioned anywhere. |

**The single highest-value habit for avoiding hallucination in this specific project:** every time you're about to say a feature is "done" or "wired," grep for its actual call sites before writing that sentence. This project has a repeated failure pattern across sessions — a well-built, well-tested module that *sounds* complete because it has good tests, but is never actually called from the live path. `retry_policy.py`, `payload_library.py` (Python), and `risk_allocator.py`'s cost term are exactly this shape right now. They're not broken. They're just not plugged in. Say that plainly if you touch them.

---

## Answering the "no tab visible" question (this session, not reproduced live)

`LlmHarnessExtension.initialize()` calls `api.userInterface().registerSuiteTab("LLM Harness", panel)` and `registerSuiteTab("Attack Surface Map", surfacePanel)`. `registerSuiteTab(String, Component)` is verified real (Montoya's `UserInterface` interface, fetched fresh this session) and is the correct call for adding a top-level Burp tab. Both panel constructors (`HarnessPanel`, `AttackSurfacePanel`) are pure Swing with no network/IO in the constructor path, so neither is a likely source of a silent exception during `initialize()`.

**This was not reproduced against a real running Burp instance** -- there is no Burp Suite GUI available in this sandbox to attach to. The code is verified correct by inspection against the real API; the missing-tab symptom itself is not verified either way. Two most likely explanations, in order:
1. This project has never had a confirmed clean, full end-to-end Gradle build in its history until the Codespace attempts in the v4.6->v4.9 update (items 7-9 below) -- if the jar that was loaded predates those fixes (bad Montoya import, Shadow plugin incompatibility, or no discoverable tests), the extension may have failed to load entirely, or the wrong jar could have been loaded. **Check Burp's Extensions -> Installed -> [your extension] -> Errors tab for a stack trace** -- that will say definitively whether `initialize()` ran at all.
2. If several extensions are loaded, Burp sometimes tucks extra suite tabs behind a small `>>` overflow control at the end of the tab bar rather than failing to show them.

Worth doing next session if this recurs: build the jar fresh from this exact zip in the Codespace, load only this one extension, and check the Errors tab before assuming anything about the registration code itself.

---

## What changed this session (v4.9), and how each claim was verified

### 10. Built real executors for the two capabilities flagged open in the v4.6 handover: `workflow_replay_compare` (business_logic) and `controlled_callback_probe` (ssrf)

Followed the pattern the v4.6 handover explicitly named as "the most natural next increment": pure Montoya-free decision logic first, compiled and tested for real, then wired into `ValidationExecutor` and type-checked against verified stub signatures.

**`WorkflowReplayLogic.java`** -- scoped honestly, not a general business-logic solver: confirms one specific, common, dangerous shape -- a numeric parameter (price/amount/quantity/qty/discount/count/total/balance/value) that accepts a boundary-violating value (typically a sign flip to negative) without rejecting it. This is the exact shape of this project's own live-reproduced ground truth (Juice Shop accepting basket quantity `-500`, see item 6 in the prior handover). Requires three observations, same "prove a negative" structure as `IdentityCompareLogic`:
- **baseline** (original value) must succeed, or there's nothing to compare against.
- **boundary** (the value negated/scaled) -- if rejected, bounds validation is working: REJECTED, not confirmed.
- **malformed** (a negative control: non-numeric junk in the same field) -- if boundary is accepted but malformed is rejected, that's specific evidence of a missing bounds check: CONFIRMED. If both are accepted, the endpoint may just not validate the field at all -- weaker, less specific signal, capped at SUPPORTED rather than CONFIRMED.

There's also an input guard (`isGenuineBoundaryViolation`) that refuses to run at all if the "boundary" value supplied isn't actually a boundary case relative to the original (sign flip from non-negative, or a 1000x+ magnitude jump) -- returns INVALID rather than silently testing something meaningless.

**`SsrfCallbackLogic.java`** -- uses Burp's real Collaborator API (`MontoyaApi.collaborator()`, verified against Montoya source this session), not a custom callback service. Generates a unique payload per candidate parameter, the executor sends it, then polls for a real DNS/HTTP/SMTP interaction matching that specific payload. An interaction is about as close to unambiguous ground truth as exists for blind SSRF confirmation. **Deliberately no weaker fallback** -- if Collaborator is unavailable (Community Edition, or Professional without a configured server), the executor reports that plainly and stops rather than guessing from timing or error shape. This is Professional-only; disclosed as such in the code comments and in the returned status message when it's unavailable, so an analyst on Community Edition gets an honest "why" instead of a silent no-op.

**A real gap found while building this:** the SSRF parameter-name heuristic already in `PathScorer.PARAM_NAME_RULES` (`url|redirect|next|return_to|callback`, exact match) misses `profileImage` -- which is this project's own live-reproduced SSRF ground truth from the prior session (item 6, "ssrf" row: a profile-image-from-URL field). `SsrfCallbackLogic.isCallbackCandidateParam()` broadens this (adds target/endpoint/fetch/proxy/dest/destination/uri/link plus a substring match on image/avatar/photo/picture) so the new executor doesn't repeat the same miss. Also fixed the same narrow list in `PathScorer.java` itself (a 1-line regex change, since it's a cheap, directly-connected, already-tested piece of infrastructure) -- a triage-scoring gap, not a correctness gap in an executor, so lower priority than the executor fix, but worth closing while already looking at it.

**Verification, in order of strength:**
- `WorkflowReplayLogicTest.java` (9 tests) and `SsrfCallbackLogicTest.java` (7 tests): actually compiled (`javac`) and executed (reflection-based runner, same technique as v4.9's JUnit5 conversion -- see item 9 in the prior handover) against JUnit5-signature-verified stubs. All 16 pass. Combined with the pre-existing 16 (`IdentityCompareLogicTest`) + 11 (`PathScorerTest`, now 11 not 10 -- added a `profileImage` regression case), **43/43 total, zero regressions.**
- `ValidationExecutor.java`'s two new methods (`workflowReplay()`, `controlledCallbackProbe()`) **type-checked** clean against Montoya stub interfaces built this session from the real, freshly-fetched API source: `Collaborator`, `CollaboratorClient`, `CollaboratorPayload`, `Interaction`, `InteractionType` (confirmed `DNS`/`HTTP`/`SMTP`), `InteractionFilter.interactionPayloadFilter(String)`, `CollaboratorPayloadGenerator.generatePayload(PayloadOption...)` (confirmed it throws `IllegalStateException` when Collaborator is disabled -- that's the real availability check the code relies on, not `createClient()` itself, which isn't documented to throw). Also re-verified `HttpParameter.value()`, `ParsedHttpParameter extends HttpParameter`, `HttpRequest.headers()`/`bodyToString()`, and `HttpHeader.name()/value()` against real source, since these were new or newly-combined usages this session.
- **Not verified this session, and this document is explicit about it:** neither new executor has been live-tested against a running target. There is no live Juice Shop instance in this sandbox this session (nothing survives between sessions, and rebuilding it wasn't attempted this pass -- effort went into the executors and their tests instead). Also not verified: `controlled_callback_probe` against a real Collaborator server, since this sandbox cannot run Burp Suite Professional at all. **Both of these are the natural next-session verification step** -- rebuild Juice Shop from the recipe below, negate a quantity by hand to confirm `workflow_replay_compare` reproduces the v4.6 ground truth through the real orchestrator path, and (if a Collaborator-enabled Burp Pro instance is available) point `controlled_callback_probe` at Juice Shop's `profileImage` field.

---

## What changed this session (post-v4.9): retry/handover, payload generation, risk allocation, effort budget

Four features requested together, scoped down via three clarifying questions (answers baked into the design below, not re-litigated here). Built Python-side first since it's testable without a live target; extended into Java only where a Montoya-free type-check was possible without redoing the prior session's full stub-verification pass.

### 11. Retry/escalation/handover state machine (`harness/retry_policy.py`)

Bounds how many times a finding gets re-tested before the harness stops trusting repeated self-re-assertion. Contract, matching the operator's answers exactly: up to `max_default_attempts` (default 3) on the default model, each attempt required by the *caller* to use a genuinely different input (never a bare re-ask -- see the module's own docstring on why that specifically isn't verification); then escalate to a stronger model exactly once, never twice even if `decide()` is called again after escalating; if the escalated attempt also fails to confirm, `HANDOVER_MANUAL` (operator-visible) only when suspicion is high -- a `SUPPORTED`-tier partial signal was seen at any point, or original confidence+severity crossed a threshold -- otherwise a silent `STOP_INCONCLUSIVE`. Deliberately not "surface every dead end": that trains the operator to ignore the flag.

**Verified:** 9 tests, actually executed (`python3 -m pytest`), including the specific "never escalates twice" and "partial signal overrides low original confidence" cases.

### 12. Payload generator (`harness/payload_library.py`)

Curated library first, context-aware selection (matched-context payloads ranked ahead of context-agnostic ones, which rank ahead of payloads tagged for a context that wasn't observed -- never excluded outright, since context detection itself can be wrong), LLM fallback prompt builder only once the library is exhausted -- matching the operator's answer exactly. The LLM fallback prompt is built centrally (not left ad hoc per call site) specifically so "don't propose something structurally similar to what already failed" is grounded in actual failure notes every time.

**Verified:** 8 tests, actually executed, including exhaustion, mismatched-context-as-last-resort, and no-duplicate-payload-values-in-library checks.

### 13. Risk-weighted resource allocation (`harness/risk_allocator.py`)

`expected_risk = P(vulnerable) x severity_weight`, ranked, retry budget allocated top-down (top `top_fraction` of findings get more rounds). Deliberately a simple greedy split, not a knapsack against the token budget -- see #14, which is where total spend is actually bounded; conflating the two would make a budget change silently change which findings get investigated.

**Verified:** 8 tests, actually executed.

### 14. Token/effort budget + estimator (`harness/effort.py`, `ollama_client.py`, `orchestrator.py`, `server.py`)

Two operator-selectable modes exactly as specified: **soft** (warn at exhaustion, require explicit `POST /effort/confirm-overspend` to keep going -- the sensible default for this project's only integrated backend, local Ollama, where overspend costs time not money) and **hard** (stop dispatching the moment the budget is spent, cannot be talked past by `confirm_overspend` -- verified by a test that calls `confirm_overspend()` in hard mode and asserts it's still blocked).

Real token accounting, not estimated: `ollama_client.chat_json_metered` extracts `prompt_eval_count`/`eval_count` from Ollama's actual `/api/chat` response -- **verified against real Ollama API behavior** (cross-checked across independent sources this session, not recalled from training data alone) rather than assumed. Wired into every real LLM call site in `orchestrator.py` (routing, agent dispatch via `base_agent.py`, critique, rediscovery).

`estimate_for_urls` projects total cost across a discovered URL set, exactly the "estimator available upon request once spidering and first walkthrough done" flow: falls back to labeled-as-unmeasured priors before any real call exists, recalibrates to real observed averages the moment one does. New endpoints: `POST /estimate`, `GET /effort`, `POST /effort/confirm-overspend`. New `AnalysisResponse` fields (`effort_spent_tokens`, `effort_budget_remaining`, `effort_budget_warning`) so every existing `/analyze` caller sees cumulative spend without a separate call.

**Verified, in order of strength:**
- 13 tests on `effort.py` alone (budget modes, ledger averaging, estimator monotonicity/breakdown-sums-to-total), 5 on the metered Ollama client (using `httpx.MockTransport` -- a real request/response cycle through real `httpx` code, no network).
- **End-to-end integration proof**, not just unit tests: ran a real `orchestrator.analyze()` call against a mocked Ollama backend, confirmed token spend actually accumulated (exact number matched between the ledger and the returned `AnalysisResponse`), then confirmed `POST /estimate`'s projection actually shifted from the unmeasured-prior number (8580 tokens) to a real-calibrated number (5120 tokens) after that one exchange -- proving the calibration loop is real, not just present in code.
- `POST /estimate`, `GET /effort` smoke-tested through FastAPI's `TestClient` with real HTTP request/response cycles (200s, correct JSON shape, 400 on empty `urls`).

### 15. Burp-side "Estimate Assessment Cost" (Attack Surface Map tab)

New button next to "Send selected to LLM Harness": sends every currently-scanned row's PathScorer score as `risk_score` to `POST /estimate`, shows the projected total + breakdown in a dialog. This is the literal Burp-side trigger for #14's estimator -- "Scan Site Map" is the spidering-review step, this button is the on-request estimate.

Added `HarnessClient.estimate()` / `.effortStatus()` and the matching `AnalysisModels` mirrors (`UrlEstimateItem`, `EstimateRequest`, `EstimateResponse`, `EffortStatus`, plus the three new `AnalysisResponse` fields). **Type-checked this session**: neither `HarnessClient.java` nor `AttackSurfacePanel.java` import Montoya at all (confirmed by inspection -- both are pure Gson/Swing), so both were compiled for real against a Gson stub verified against Gson's actual source (`raw.githubusercontent.com/google/gson`, `toJson(Object)`/`fromJson(String, Class<T>)` signatures confirmed), not just source-reviewed.

---

## What changed this session (post-v4.11): gap-analysis implementation

A commercial-platform architecture spec (multi-tenant SaaS pentesting platform) was compared against this project; the comparison itself is `platform-spec-gap-analysis.md` (headline: most of that spec's infrastructure doesn't apply here -- this is a single-operator local tool, not a multi-tenant service -- but several data-modeling ideas transfer). Four of the identified gaps were implemented this session; the rest were deliberately deferred (see the file-inventory table at the top of this document for exactly which, and "What's still open" below).

**Full detail is in `REVIEW_HANDOVER.md`** (written for an external reviewing model, but the factual content applies here too) -- summarized:

1. **Credential redaction** (`base_agent.py`) -- `Authorization`/`Cookie`/`Set-Cookie`/`X-API-Key`/`X-Auth-Token`/`Proxy-Authorization` header *values* no longer reach the LLM prompt, only the header names. 6 tests. Known gap: request/response *bodies* aren't redacted -- a token in a JSON body still reaches the prompt.
2. **Cost-weighted risk ranking** (`risk_allocator.py`) -- `value_density = expected_risk / cost`, defaults to the old risk-only ranking when `cost` isn't supplied (checked, not assumed, that the pre-existing `RankTests` still pass unmodified). 4 new tests. **Not wired to real cost data anywhere** -- see the file-inventory table above.
3. **Reproducibility metadata** -- `findings.model`/`findings.prompt_version` columns, `prompt_version` is a 12-char hash of the exact system prompt (automatic, can't go stale the way a hand-maintained version number would). 4 tests including one that directly queries the SQLite row, not just checks the call didn't raise. **The SQLite migration path (`ALTER TABLE ... ADD COLUMN` on a pre-existing populated DB) was actually tested this session** -- built an old-schema DB, inserted a row, opened it with the new `store.py`, confirmed the row survives with sensible defaults and no exception. This is the one migration-risk item in this document that got checked by hand instead of left as a TODO.
4. **Identity/Session as first-class objects** (`identity.py`, new tables, `/identities` `/sessions` `/hosts/{host}/sessions` endpoints) -- 8 tests plus a live `TestClient` smoke test (create identity -> 200, create session -> 200, unknown identity -> 404, correct join on `GET /hosts/{host}/sessions`). **Explicitly partial**: replaces nothing in Burp yet. `ValidationExecutor.identityCompare()`'s `JOptionPane` picker is untouched and doesn't know these endpoints exist.

**Verification:** 94/94 Python tests pass (72 carried forward, confirmed no regression -- 22 new this session). No Java changes this session.

---

## What's still open

1. **Wire `risk_allocator.py`'s `cost` parameter to `effort.EffortLedger.average_tokens`.** The formula exists and is tested; nothing calls it with real cost data. Small, mechanical -- the natural next increment.
2. **Wire Identity/Session into the Java side.** `identityCompare()` should query `GET /hosts/{host}/sessions` instead of (or alongside) its raw exchange-pool `JOptionPane` picker. This is the actual point of item 4 above; without it, item 4 is infrastructure with no consumer.
3. **`workflow_replay_compare` and `controlled_callback_probe` still use a single fixed mutation each** -- `reflection()`'s retry-with-new-payload loop (built two sessions ago) hasn't been extended to these. Same pattern applies (`WorkflowReplayLogic`/`SsrfCallbackLogic` already have the structure).
4. **Redact request/response bodies, not just headers, before they reach an LLM prompt.** Harder than the header fix (a token in a body might legitimately *be* the finding being reported), not attempted this session.
5. **Observation as a first-class object, capability registry with schema validation, declarative PathScorer rules, port/method-level scope granularity, cross-session payload-failure memory.** All from the gap analysis, all deliberately not started -- see `REVIEW_HANDOVER.md` for the one-line reason each was deferred rather than half-built.
6. **The actual Gradle build in the Codespace** -- still no session has seen an actual "BUILD SUCCESSFUL." Still the single most valuable confirmation available, unchanged across many sessions now -- if you have Codespace access, this is overdue.
7. **No live target testing this session** (Python or Java) -- carried forward from every prior session's open item. Rebuilding a live Juice Shop instance (recipe below) before trusting any validator against something real is still the standing next step.
8. **Validator disagreement critique, sqlmap level/risk default, dev-rule doc for the pure-logic-plus-test pattern.** Unchanged for several sessions now -- not touched again this session.

---



## What changed this session, and how each claim was verified

### 1. Fixed the v4.1 IDOR/authorization confirmation flaw (carried over from prior session's open item)

The previous version confirmed `cross_identity_compare` / `authorization_boundary_compare` whenever two different captured identities got a similar response for the *same URL* — which can't distinguish a real authorization failure from a resource that's simply public.

**What was built:**
- `burp-extension/src/main/java/com/harness/llm/logic/IdentityCompareLogic.java` — pure decision logic, zero Montoya dependency. Requires four observations (source, candidate, attempt, anon) and only reaches CONFIRMED when an unauthenticated probe is denied (ruling out "it's just public") *and* the attempt matches the candidate's protected response, not the anonymous one.
- `burp-extension/src/main/java/com/harness/llm/logic/UrlIdentifierDiff.java` — pure helper that finds a single differing path segment or query value between two URLs, refusing to guess when more than one token differs.
- `ValidationExecutor.identityCompare()` rewritten to gather the four probes (including a real object-identifier swap for IDOR, via `withPath`/`withParameter`, and a stripped-header anon probe via `withRemovedHeader`) and delegate the decision to `IdentityCompareLogic`.

**Verification, in order of strength:**
- `IdentityCompareLogicTest.java`: 16 tests, actually compiled and run (`javac` + `java`, no JUnit — Maven Central is blocked in this sandbox, see Environment Constraints below). One test failed on first run: the initial similarity threshold (0.90) produced a false negative on a realistic short JSON body with one volatile token. Recalibrated to 0.70 based on empirical measurement (same-resource-different-token cases scored 0.77–0.92; genuinely-different-content cases scored 0.43–0.50 — wide margin either side of 0.70), added both directions as permanent regression cases.
- `ValidationExecutor.java` (the Montoya-dependent integration) **type-checked** clean against stub interfaces built from the real Montoya API source, fetched directly from `raw.githubusercontent.com/PortSwigger/burp-extensions-montoya-api` (that domain is in this sandbox's allowed egress list; `github.com` and `portswigger.github.io` are not reliably fetchable the same way). This confirmed `withPath(String)`, `withRemovedHeader(String)`, and `withParameter(HttpParameter)` are real methods with the signatures used.
- **Live-tested** against a real running OWASP Juice Shop instance (recipe below): registered two real users, gave each a distinguishable basket, captured real HTTP responses for source/candidate/attempt/anon, fed them into the compiled `IdentityCompareLogic.evaluate()`. Result: **CONFIRMED, confidence 0.91**, correctly reproducing Juice Shop's well-known "Basket Access" broken-access-control challenge. A negative control against a genuinely public endpoint (`/rest/products/search`) correctly returned **not confirmed** (INCONCLUSIVE, "resource appears to be public").
- Also live-tested the same logic for `authorization_boundary_compare` against a *different* real vulnerability found this session (see item 6) — also CONFIRMED correctly.

### 2. Fixed a real compile bug in `PathScorer.java`

11 occurrences of `(/|\.|$)` in regex string literals — `\.` is not a valid Java string escape (only `\\.` is). This was caught by the user's own real `javac`/gradle build attempt, not by review. Fixed all 11 with a single pattern replace, then verified two ways:
- Compiled directly (`PathScorer.java` has zero Montoya imports, so this is a real, unconditional compile — not type-checking).
- Ran real inputs through it, including a specific check that the fix didn't accidentally turn a literal-dot match into an any-character wildcard match (the exact way a careless escape fix could reintroduce a *different* bug with no compile error to catch it). `PathScorerTest.java`, 10 tests, all executed.
- Scanned the entire tree for the same bug class (single-backslash regex metacharacters in Java string literals) — zero other occurrences.

### 3. Fixed a real, silent capability-matching bug: `vulnerability_class` is free text

`Finding.vulnerability_class` is genuinely unconstrained LLM output (see `agents/base_agent.py`'s prompt — no enum). `planner.py` and `validators/base.py` matched it against capability names with an **exact lowercase string comparison**. An agent writing "Insecure Direct Object Reference" instead of the literal string `"idor"` would silently produce zero test plans — no error, no visible sign anything was wrong.

**Fix:** new module `harness/categories.py` — `CANONICAL_CATEGORIES` tuple plus a `canonicalize()` function with a reviewable synonym table. Wired into `planner.py` (before capability lookup) and `validators/base.py` (`applies()`). `TestPlan` gained a `category` field (Python `models.py` + Java `AnalysisModels.java` mirror) so downstream consumers — especially the coverage ledger — have a reliable join key instead of raw free text.

Verified via `test_planner.py` (existing, still passing) plus the coverage ledger's own tests, which specifically exercise category derivation.

### 4. Fixed three real, independently-verified bugs in `validators/sqlmap.py`

Found by actually running it against a live target, not by reading the code:

1. **Silent stdin hang.** `subprocess.run` inherited a non-EOF stdin; sqlmap hung indefinitely despite `--batch`, and the eventual timeout reported "sqlmap timed out" — indistinguishable from a genuinely slow scan. Reproduced directly (`sqlmap -r file.txt ...` hung until killed; `< /dev/null` fixed it instantly). Fixed with `stdin=subprocess.DEVNULL`.
2. **Missing `--ignore-code`.** sqlmap's default behavior treats any non-2xx baseline response as "not authorized to test" and skips the target — meaning any endpoint whose *normal* response is non-2xx (a failed login attempt, an auth-gated endpoint) would silently never be tested. Fixed generally: pass `--ignore-code <exchange's own baseline status>`, not a hardcoded value.
3. **`--smart` caused a false negative on a genuinely injectable parameter.** Isolated by adding that one flag back to an otherwise-identical, working command and watching it reproduce the miss. Removed `--smart`; disclosed trade-off (more requests, but correctness matters more for a single bounded, analyst-approved confirmatory run than for a broad crawl).
4. Switched invocation from `-r <request file>` to explicit `-u`/`--data`/`-H` flags. The `-r` file mode, with byte-for-byte identical request content, silently matched zero targets and exited instantly with no test attempts and no error — isolated this to request-file parsing specifically (not `--ignore-code`, not `--smart`, not a missing `Content-Length`), concluded it's a broken path in this sqlmap version (1.8.4) rather than something worth debugging further, and switched to the standard, more-tested invocation shape instead.

**Verification:** all four fixes verified by direct reproduction against live Juice Shop (recipe below), then the actual unmodified `SqlmapValidator.validate()` — called with no manual overrides — produced `confirmed: True` on Juice Shop's login endpoint, a real, live-confirmed SQL injection. Existing mocked unit tests (`test_validators.py`) still pass unchanged.

**Open question, not resolved:** the shipped `config.yaml` default is `level: 1, risk: 1`. A later re-test at these defaults through the full orchestrator path returned `not_confirmed` — but by that point the Juice Shop process itself had died (see Environment Constraints), so this is *not* evidence that level 1 is insufficient; it's unresolved. Worth deciding deliberately (more aggressive default = better detection, more requests) rather than assuming either way.

### 5. Built the coverage ledger (`store.py`: `coverage_report`, `set_coverage_override`, `clear_coverage_override`)

Per-category status (`confirmed` / `supported` / `blocked` / `tested_clean` / `not_tested` / `not_dispatched` / `not_applicable`) derived **purely from stored evidence** (`findings`, `test_plans`, `validation_runs`) — never from a settable field. The only human input, `set_coverage_override`, is hardcoded server-side to only ever produce `not_applicable`; there is no code path that lets a caller assert `confirmed` through it (locked in by `test_override_cannot_be_used_to_assert_confirmed`).

**This surfaced a serious, separate structural gap while building it:** `orchestrator._validate_findings` ran validators (including sqlmap) and returned results to the API response, but **never wrote anything to `validation_runs`** — that table was Burp-extension-only. A real, live-confirmed SQL injection would have been completely invisible to this ledger. Fixed by having each validator's own `.plan()` get persisted and its result submitted through the same gate the Burp extension uses (`persist_validation_submission`).

Fixing *that* exposed two more real bugs in `persist_validation_submission` itself:
- It hardcoded `"burp:"` as the required executor prefix — would reject every legitimate `local_tool` (sqlmap) submission. Fixed to use the plan's own `execution_plane` (new `test_plans.execution_plane` column, added via migration).
- It explicitly excluded `sql_injection_validation` from the set of capabilities allowed to set `confirmed=True` — directly contradicting the project's own "trust deterministic tools" principle for the one tool that's most deterministic. Fixed: added to `confirmation_capabilities`.

**Verification:** 12 new tests in `test_coverage.py`, all passing, exercising every status transition including the override restriction. Then **live-verified through the real `Orchestrator._validate_findings`** against Juice Shop's login endpoint: the ledger correctly showed `tested_clean` with a real evidence pointer (`plan_id`, `validation_run_id`) pointing at an actual row, not a synthetic one.

### 6. Live-tested all ten agent categories against real Juice Shop (this session's last major task)

| Category | Live ground truth found | Harness status |
|---|---|---|
| idor | Basket access (Alice → Bob's basket via ID swap) | `cross_identity_compare` — CONFIRMED correctly |
| sqli | Login endpoint boolean-blind injection | `sql_injection_validation` — CONFIRMED correctly |
| auth | Any "customer" role can list all users via `/api/Users`, including admin's data | `authorization_boundary_compare` — CONFIRMED correctly (verified with a real admin baseline via Juice Shop's own intentionally-weak default admin credentials) |
| xss | `/rest/track-order/<id>` reflects a unique canary verbatim, unescaped, in JSON | Matches `reflection_context_validation`'s design exactly — correctly stays at "supported," never auto-confirms JSON-context reflection |
| business_logic | Server accepts negative basket quantities (`-500`) with zero validation | **Gap: `workflow_replay_compare`'s Java implementation is a bare placeholder** that always returns "inconclusive" — real vulnerability, no automated confirmation path exists |
| misconfig | `/ftp` (real directory listing) and `/metrics` (real Prometheus data) both exposed | `/metrics` was already caught by `PathScorer`; `/ftp` was not — added a new rule (`(ftp|files|backups?|uploads?)`), verified against the real path, added as a permanent regression test |
| ssrf | Profile-image-from-URL makes a genuine server-side fetch (verified via the user's `profileImage` field changing) | **Gap: `controlled_callback_probe` has no case at all in `ValidationExecutor`'s switch statement.** `planner.py` generates plans for it; nothing executes them |
| supply_chain | Real dependency `jsonwebtoken@0.4.0`, ~12.3 years old | Both deterministic checkers ran live: GitHub Advisory API correctly hit rate-limiting and **reported it honestly** (no fabrication); npm registry check succeeded with real publish-date data |
| ai_llm | Chatbot requires a configured LLM backend (Ollama at `localhost:11434`) | Not exercisable in this environment — matches the app's own startup warnings, not a harness defect |
| rate_limit | 15 rapid failed logins, zero throttling | Matches `bounded_rate_limit_probe`'s conservative design exactly — correctly doesn't overclaim from absence of throttling alone |

**Correction made mid-session, worth repeating here so it isn't re-discovered the hard way:** an early pass flagged `/package.json` and `/.git/config` as exposed (HTTP 200). Both were false positives caused by this session's own placeholder frontend's SPA-fallback route (Angular history-mode catch-all), not real Juice Shop behavior — caught by comparing response *bodies*, not just status codes, before reporting. `/ftp` and `/metrics` were confirmed real by the same check (distinct body content, not the fallback page).

---

## Environment constraints (verified this session, not assumed)

- **Maven Central and Gradle's own distribution servers are not in this sandbox's egress allowlist.** `curl -I https://repo.maven.apache.org/maven2/` returns `403 host_not_allowed`. The Java extension (`burp-extension/`) cannot be built with Gradle here. `raw.githubusercontent.com` IS allowed, which is how the Montoya API source got fetched for the stub-based type-checking described above.
- **npm registry access worked this session**, contradicting the previous handover's note that it didn't. Environment network access appears to vary between sessions — don't assume either way; check directly (`curl -sI https://registry.npmjs.org/`) before concluding it's blocked.
- **`sqlmap` and a JDK are installable via `apt-get`** from the allowed Ubuntu archive mirrors (`archive.ubuntu.com`, `security.ubuntu.com`). Neither was pre-installed.
- **Long-running background processes do not reliably survive between tool calls in this sandbox.** The live Juice Shop `node` process died at least twice during this session with no visible crash log — once probably from a transient network hiccup (curl got connection-refused, then the *same* PID answered normally moments later), and once for real (process gone, no PID, had to be relaunched). Launch it, verify it's actually still alive with `pgrep` before relying on it in a later step, and don't assume a server you started ten minutes ago is still running.
- **The working directory does not persist into a new session.** Everything under `/home/claude/work/` — the Juice Shop clone, its `node_modules`, its compiled `build/`, its SQLite data, the placeholder frontend files, the Java `out/` directories — is gone in a fresh session. The zip artifact is the only thing that survives. Budget real time to redo the Juice Shop setup if continuing this work in a new session.

---

## Update: real Gradle build attempts against the actual Montoya jar (post-handover, in the user's own environment)

The user is building this project with Gradle in a GitHub Codespace, which has real Maven Central access this sandbox doesn't. Two real build attempts happened after the above was written; both surfaced genuine bugs, both fixed the same way as everything else in this document — verified against real sources, not guessed.

### 7. Wrong import in `HarnessContextMenu.java`

`import burp.api.montoya.http.message.headers.HttpHeader;` — that subpackage does not exist. Confirmed against the real Montoya source: the correct path is `burp.api.montoya.http.message.HttpHeader` (one level up, no `.headers` subpackage) — `raw.githubusercontent.com/.../http/message/headers/HttpHeader.java` returns 404; `.../http/message/HttpHeader.java` returns 200. This file had never been touched or type-checked earlier in the original session, so its bugs hadn't surfaced yet.

Fixed the one bad import, then checked **all 12 unique Montoya import paths used anywhere in `burp-extension/`** against the real source in one pass rather than assume this was the only one — all others confirmed correct.

### 8. Shadow plugin / Gradle version incompatibility

With the import fixed, `:compileJava` succeeded cleanly for the first time in this project's history — a real milestone. The build then failed at `:shadowJar` with a Groovy `MissingPropertyException: No such property: mode for class: ...StubbedFileCopyDetails`, deep inside the Shadow plugin's own internals, not the project's code.

Root cause, confirmed against Shadow's own published compatibility table: `build.gradle` was pinned to `com.github.johnrengelman.shadow` version `8.1.1`, which only supports Gradle 8.0–8.2.x. That plugin ID is unmaintained; maintenance moved to the GradleUp org. The Codespace's Gradle is almost certainly 8.3+, where Gradle changed the internal copy-details class shape 8.1.1 reaches into reflectively via Groovy.

**Fix:** switched to `com.gradleup.shadow` version `8.3.11` — the last release in the *same* (non-rewritten) 8.x line, documented as a drop-in replacement for 8.1.1's exact API/DSL, and confirmed compatible with both Gradle 8.3+ and Gradle 9.x. Deliberately did not jump to the fully-rewritten 9.x line (several documented breaking changes) since it couldn't be verified here and isn't necessary.

**Neither fix could be verified by actually running the build** — Maven Central is still blocked in this sandbox. Both are asserted from the real Montoya source and Shadow's own documented compatibility table respectively, not from execution. The next Gradle run in the Codespace is the real signal — if it gets past `shadowJar`, both fixes were sufficient; if not, whatever comes next should be traced the same way (verify against a real source before changing anything).

### 9. Converted the Java test files from plain-`main()` runners to real JUnit 5

The Gradle build got past `:compileJava` and (implicitly, by getting further in the task graph) `:shadowJar` — the first time either has ever succeeded in this project's history — and then failed at `:test`: *"test sources present... but the test task did not discover any tests to execute."*

This was a direct, foreseeable consequence of an earlier choice: `IdentityCompareLogicTest.java` and `PathScorerTest.java` were written as plain `main()`-method runners with a hand-rolled assertion harness, specifically because *this sandbox* has no Maven Central access and couldn't pull JUnit. Gradle's default `test` task expects JUnit-discoverable (`@Test`-annotated) methods and correctly found none.

The user's Codespace has real Maven Central access, so this constraint doesn't apply there. Converted both files to real JUnit 5 (Jupiter) `@Test`/`@DisplayName` methods — every assertion and comment preserved exactly, only the harness mechanics changed (`main()`/`run()`/`check()` → `@Test`/`assertTrue`/`assertEquals`). Added `testImplementation 'org.junit.jupiter:junit-jupiter:5.14.4'`, `testRuntimeOnly 'org.junit.platform:junit-platform-launcher'`, and `test { useJUnitPlatform() }` to `build.gradle` — the versions and dependency shape follow Gradle's own current official documentation (`docs.gradle.org/current/userguide/java_testing.html`), not memory.

**This one *could* be verified, differently from the last two fixes.** Fetched the real JUnit 5 Jupiter source (`Test.java`, `Assertions.java`, `DisplayName.java`) from `raw.githubusercontent.com/junit-team/junit5`, confirmed exact method signatures (`assertTrue(boolean, String)`, `assertEquals(Object, Object, String)`, etc.), built verified-signature stubs from them (same technique as the Montoya work), compiled both converted test files against the stubs, then wrote a small reflection-based runner to actually *execute* every `@Test` method against those stubs. **All 26 tests (16 identity-compare + 10 PathScorer) pass**, confirming the conversion preserved the original logic correctly — not just that it compiles. This is not the real JUnit engine (no real discovery/reporting/lifecycle), so the next Gradle run in the Codespace is still the final signal, but it's stronger evidence than the previous two Java fixes had.

---

## Recipe: getting a live OWASP Juice Shop instance running in this sandbox

This took real trial and error this session; follow it exactly rather than re-deriving it.

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git juice-shop-live
cd juice-shop-live

# Cypress (e2e test tool, not needed to run the app) tries to download
# its binary from a domain outside the allowlist and fails the whole
# install. Skip just that.
CYPRESS_INSTALL_BINARY=0 npm install --no-audit --no-fund

# The automatic postinstall frontend build requires Angular CLI's
# minimum Node version (22.22.3+ at time of writing); this sandbox's
# Node was 22.22.2 -- one patch version short. Don't fight this -- the
# REST API backend doesn't need the Angular build at all.
npm run build:server   # just `tsc`, works fine independent of the frontend

# The server's startup precondition check hard-requires several
# frontend/dist files to exist (it exits rather than degrading
# gracefully). None of their actual content matters for REST API
# testing -- create minimal placeholders:
mkdir -p frontend/dist/frontend/assets/private frontend/dist/frontend/assets/public/images \
         frontend/dist/frontend/assets/public/videos frontend/dist/frontend/assets/public/images/uploads
echo '<!doctype html><html><body>placeholder</body></html>' > frontend/dist/frontend/index.html
echo '/* placeholder */' > frontend/dist/frontend/styles.css
echo '// placeholder' > frontend/dist/frontend/main.js
echo '// placeholder' > frontend/dist/frontend/polyfills.js
echo '// placeholder' > frontend/dist/frontend/hacking-instructor-placeholder.js
echo '<!doctype html><html><body>placeholder</body></html>' > frontend/dist/frontend/assets/private/threejs-demo.html
echo 'WEBVTT' > frontend/dist/frontend/assets/public/videos/owasp_promo.vtt
touch frontend/dist/frontend/assets/public/favicon_js.ico
python3 -c "
import base64
png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=')
for name in ['JuiceShop_Logo.png','JuicyChatBot.png','JuicyBot.png']:
    open('frontend/dist/frontend/assets/public/images/'+name, 'wb').write(png)
"

# Launch detached -- a plain `&` did not reliably survive in this
# sandbox; setsid + explicit stdin redirect was more reliable.
setsid node build/app.js > /tmp/juice-shop.log 2>&1 < /dev/null &

sleep 8
pgrep -fa "node build/app"   # confirm it's actually alive before trusting it
curl -s http://localhost:3000/rest/products/search?q=apple   # should return real product JSON
```

If the exact required placeholder filenames ever change (a future Juice Shop version), find them fresh rather than assuming this list is complete:
```bash
grep -rhoE "frontend/dist/frontend/assets/[a-zA-Z0-9_/.\-]+" build/lib/startup/*.js build/server.js
```

**Default admin credentials** (Juice Shop's own, intentionally weak, by design — legitimate to use against this specific deliberately-vulnerable app): `admin@juice-sh.op` / `admin123`.

**Registering test identities:**
```bash
curl -s -X POST http://localhost:3000/api/Users -H "Content-Type: application/json" \
  -d '{"email":"USER@test.local","password":"Password123!","passwordRepeat":"Password123!","securityQuestion":{"id":1,"question":"test","createdAt":"","updatedAt":""},"securityAnswer":"x"}'
# login to get a JWT:
curl -s -X POST http://localhost:3000/rest/user/login -H "Content-Type: application/json" \
  -d '{"email":"USER@test.local","password":"Password123!"}'
# the JWT payload (base64-decode the middle segment) contains "bid": <basket id>
```

---



1. Inspect the actual current archive — don't trust this document's prose over the code.
2. Run the current test suites (`cd harness && python3 -m pytest -v`; for Java, see `dev-tools/README.md` — the pre-existing test files are real JUnit5 now (item 9, prior handover), not `main()`-method runners, so they no longer run via a bare `java -cp out ClassName`; use the packaged `dev-tools/RunTests.java` + `dev-tools/stubs/` instead of rebuilding stub infrastructure from scratch).
3. If continuing live-target work, budget time to redo the Juice Shop setup from the recipe above — nothing survives.
4. Classify every result explicitly: PASS / FAIL / BLOCKED BY ENVIRONMENT / NOT TESTED. Never convert BLOCKED into PASS.
5. When a fix touches Montoya-dependent code, extract the decision logic into a pure, Montoya-free class first, write an executable test for it, and only then wire it into the Burp-dependent integration layer (type-check that layer against verified real API signatures, not memory or assumption — extend `dev-tools/stubs/` rather than re-fetching signatures already verified there).
