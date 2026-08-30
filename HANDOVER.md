# HANDOVER — the full project state, read this before touching anything

This is the single authoritative current-state document for this
project. Every claim below is either (a) something verified by an exact
command given inline — run it yourself before trusting the claim, or
(b) explicitly marked as reported-but-not-independently-verified, with
a note on how confident that makes it. Nothing in between. That
distinction is the entire point of this document, so don't let it blur
as you extend this file in future sessions.

**A genuine problem this document tries to fix:** this repo has
accumulated at least 18 historical markdown documents at its root
(`ARCHITECTURE_NEXT_LEVEL.md`, `AUDIT_REPORT.md`, six separate
`JUICE_SHOP_*.md` reports, `MILESTONES.md`, `TEST_RESULTS_SUMMARY.md`,
and more) plus three prior full handovers
(`HANDOVER_PRIOR.md`, `HANDOVER_PRIOR_2.md`, and the pre-existing
`HANDOVER_LATEST.md`/`HANDOVER_NEXT_SESSION.md`/`REVIEW_HANDOVER.md`
that predate all of this session's work). **They are not mutually
consistent, and at least one of them (the on-disk `HANDOVER_PRIOR_2.md`)
was stale relative to the actual code for an unknown period before this
session** — real fixes existed in the codebase that its own prose never
mentioned. Don't try to reconstruct a clean linear history by reading
all of them; you'll end up averaging together some outdated claims with
some current ones and have no way to tell which is which. Use this
document plus direct inspection of the actual code instead.

---

## 0. The one thing to internalize before anything else

**Three separate times across this project's history, something that
looked done because it had good tests turned out to have never
actually run its real end-to-end path.** The specialist-agent pipeline
was non-functional for an unknown period until a prior session found
it (a system-prompt validator was rejecting every agent's own hardcoded
prompt). This session's `orchestrator.analyze()` crashed on its first
ever real cache read/write cycle — twice, on two different bugs,
neither caught by 400+ existing tests. And this session's blind test
looked like a damning detection failure until direct inspection of the
raw data showed the input contained zero exploitable evidence at all.

The pattern in all three: **a plausible-sounding number (test count,
finding count) was trusted instead of the underlying data being
inspected directly.** Whenever you're about to write a sentence
characterizing what this project's tests, findings, or historical docs
show, go look at the actual file first. This document tries to model
that by putting a command next to every claim; do the same for
anything you add.

**Also new this session, and worth internalizing separately: a real
user got a real Ollama-backed Burp installation actually working
end-to-end for the first time in this project's history**, against a
real target (Juice Shop). That surfaced a chain of real, previously-
invisible bugs in quick succession — proxy config, header handling,
HTTP/2 body loss, timeouts, a prompt-validator false positive, a
plan-generation bug, a category-canonicalization bug, and a large
capability-coverage gap (§5b, §5c) — none of which any sandbox, unit
test, or self-graded discovery run had ever surfaced, because none of
those ever ran a real model against a real, adversarial user driving
the extension live. If you have access to a real Burp+Ollama setup,
that is now by far the highest-value way to find what's actually still
broken — more valuable than anything achievable in a sandbox like the
one this document was written in, which still has no Ollama access at
all (see §1).

---

## 1. Current environment state — verify before assuming

```bash
cd /home/claude/project/project/harness && python3 -m unittest discover -p "test_*.py"
# Expected: Ran 448 tests, OK

python3 -m pytest test_plugin_system.py -q
# Expected: 26 passed

ls agents/*.py | grep -vc -E "__init__|base_agent|plugin.py"    # expect 36
ls validators/*.py | grep -vc -E "__init__|base.py"              # expect 15
ls test_*.py | wc -l                                             # expect 31
```

**If any of these differ from what's stated here, something changed —
trust the command, not this document.**

Ollama is not reachable from this sandbox and never has been, across
every session in this project's history. **Every LLM call this project
has ever made, in every session including this one, has been a
substitution** — a human or an agent reading the harness's real,
constructed prompts and answering them directly, not a real model
call. No claim anywhere in this project's history about what a
finding "looks like" has been checked against the actually-configured
`llama3.1:8b`/`gemma2:9b`. Say this explicitly whenever you write
anything down about this project's results — it is the single most
important piece of context missing from most of the older docs.

---

## 2. Architecture — where to actually read about it

Full accurate current architecture, setup, and GPU-feasibility guidance
is in **`README.md`** (rewritten this session from a 636-line research
narrative into an actual setup/architecture doc — the old content is
preserved as `RESEARCH_NOTES.md`, marked historical). Read that, not
this section, for "what does this do and how does it work." What
follows here is what changed, session by session, and what's still
broken.

---

## 3. Fixed this session (verified directly, high confidence)

### 3a. Two bugs that crashed `orchestrator.analyze()` on first-ever real end-to-end use

| # | File | Bug | Fix |
|---|---|---|---|
| 1 | `orchestrator.py` (2 sites) | `cache.compute_exchange_hash(...)` doesn't exist at module level — only `cache.ExchangeCache.compute_exchange_hash` does. Crashed every successful cache-hit and cache-write call. | Both sites corrected |
| 2 | `orchestrator.py` (cache-hit branch) | `AnalysisResponse(**cached_result.model_dump(exclude={...}), summary=..., ...)` passed `summary` twice | Added `"summary"` to the exclude set |

```bash
grep -n "cache.ExchangeCache.compute_exchange_hash" /home/claude/project/project/harness/orchestrator.py
# should show 2 matches
```

### 3b. Three real detection-coverage gaps, found by a live discovery run against a purpose-built test target, then fixed

Full before/after evidence: `testing/test-target/DISCOVERY_RUN_RESULTS.md`.

| # | Gap | Fix |
|---|---|---|
| 3 | No `fast_path.py` URL pattern for order/invoice/booking-shaped endpoints → `idor` never dispatched for them | Added a matching pattern |
| 4 | `fast_path.py` never inspected request-body content or numeric response values — a business-logic price/quantity manipulation produced no matchable signal | Added `select_agents_by_body_anomalies()`: structural JSON check for a negative value in a money/quantity-shaped field |
| 5 | `security.redact_headers()` fully redacted `Authorization`, making `alg:none` JWT forgery structurally invisible to every agent | Now discloses only the JWT header segment (e.g. `{"alg":"none"}`) for JWT-shaped bearer tokens; payload/signature stay fully redacted; non-JWT tokens unaffected |

```bash
python3 -m pytest /home/claude/project/project/harness/test_fast_path.py /home/claude/project/project/harness/test_base_agent.py -q
# should show all passing, including tests named for these three fixes
```

Re-running the discovery suite after these fixes: 11 of 12 known real
vulnerabilities in the test target now produce a genuine finding (up
from 8), zero new false positives. See `testing/test-target/DISCOVERY_RUN_RESULTS.md`
for the exact before/after numbers per vulnerability.

### 3c. Efficiency fixes (not correctness — these change cost, not detection)

- **Cache almost never actually cached.** `ExchangeCache.compute_exchange_hash()` hashed every header verbatim, including `Date`/`ETag`/`X-Request-Id`, which change on every request regardless of content — guaranteed cache miss in real traffic. Fixed: strip 13 pure-transport headers before hashing. Deliberately did NOT touch `Cookie`/`Authorization`/CSRF values (identity-bearing; this harness's IDOR detection depends on telling "same request, different user" apart). Detail: `harness/CACHE_HASH_VOLATILITY.md`.
- **`fast_path.py` was dispatching ~6 agents on almost every exchange regardless of content**, because `GET`/`POST` methods and `200`/`201` statuses were mapped to broad agent lists that fired unconditionally. Removed those four blanket entries, kept everything actually discriminating. A follow-up fix restored `sqli`/`xss` coverage for search functionality using uncommon parameter names (any non-empty query param now carries a baseline `sqli`/`xss` signal regardless of its name). Detail: `harness/FAST_PATH_EFFICIENCY.md`.
- **26 of 36 agents silently inherited the coordinator's model.** Added `agent_defaults` config section (default `gemma2:9b`) so agent model choice isn't coupled to a routing-quality decision. The 10 agents already explicitly pinned to `llama3.1:8b` are untouched.
- **Unbounded agent concurrency.** `agent_manager.run_multiple_agents()` fired every dispatched agent as a simultaneous request with no limit — risk of exceeding VRAM on a single GPU. `config.yaml`'s `concurrency.max_parallel_agents` (default 3) now bounds it via a real `asyncio.Semaphore`, verified with a test that measures actual peak concurrency, not just that the config is read (`test_agent_concurrency.py`).

```bash
python3 -m pytest /home/claude/project/project/harness/test_agent_concurrency.py -v
# 4 tests, including test_concurrency_never_exceeds_configured_limit
```

### 3d. A blind test was run, produced no usable signal, and the methodology was fixed

Full detail with exact reproducible commands: `HANDOVER_PRIOR.md` §0/§3/§4
(the version of this document written immediately after the blind test —
kept because it has the full command-by-command evidence trail this
summary compresses). Short version: the tester sent 26 requests, 92%
came back 401/404/405, zero carried a real auth session, zero contained
any payload. The harness's output (version-banner noise, "auth
enforced" observations) was the correct response to that input, not a
detection failure. `testing/blind-test-kit/METHODOLOGY.md` now has an explicit
pre-completion checklist (did you get a working session, is your
failure rate low, did you send payload-bearing requests, would this
response differ if a bug existed) that the original wording didn't
have. **A genuine, properly-adversarial blind test has still never
happened in this project's history** — this is the top priority (§7).

---

## 4. Reported by this project's history before this session

These claims come from documents written in earlier sessions. Where
practical, they were spot-checked directly this session (noted below);
where not, treat them as "probably true, not independently confirmed
this session" rather than fact.

**Spot-checked this session, confirmed still accurate:**
```bash
cd /home/claude/project/project/harness
grep -n "max_system_prompt_lines\|max_user_prompt_lines" prompt_validator.py
# confirms the prompt_validator fix (blocked-pattern check no longer
# applied to the harness's own trusted system prompts, and a separate
# line-limit split for system vs user prompts) is real and present
grep -rn "import risk_allocator" report_generator.py
# confirms risk_allocator.py, once fully unwired, is now called from
# report_generator.py for cost-aware ranking of unconfirmed findings
```

**Spot-checked this session, confirmed STILL unwired (not fixed by anyone yet):**
```bash
grep -rn "retry_policy\|RetryPolicy" *.py | grep -v "test_\|^retry_policy.py"
grep -rn "payload_library" *.py | grep -v "test_\|^payload_library.py"
# both should show zero real callers (only cross-references in each
# other's docstrings/comments) -- these modules are unit-tested and
# well-built but not called from any live execution path
```

**Not re-verified this session — reported by prior sessions' own
documents, take with appropriate caution:**
- A prior session found and fixed a bug where the prompt validator's
  shell-chaining regex rejected ordinary syntax (`Content-Type:
  application/json; charset=utf-8`) while missing real attacks with a
  space before the operator.
- A prior session found `sqlmap` missed two real, hand-confirmed SQL
  injections against a live Juice Shop instance (a heuristic dismissal
  and a genuine timeout that then crashed on a separate bytes/string
  bug, also fixed).
- A prior session built a forced-egress safety proxy
  (`safety_proxy_addon.py`) and cross-run finding suppression — both
  reportedly unit/mock-tested but never run against a real client or
  live traffic.
- The Java/Burp extension side (`ValidationExecutor.java`,
  `IdentityLabelResolver.java`, workflow-replay and SSRF-callback
  executors) is reported as compiled and type-checked against verified
  Montoya API stubs, but **never live-tested against a real running
  Burp instance** — no Burp GUI has ever been available in any session's
  sandbox. Do not upgrade this to "tested" without an actual Burp
  environment.

---

## 5. New this session: a real test target, a real discovery run, a blind-test kit

**Directory structure note:** `test-target/` and `blind-test-kit/` now
live under `testing/` (`testing/test-target/`, `testing/blind-test-kit/`),
and 28 historical/superseded documents (the old handover chain, six
Juice-Shop-era reports, audit/milestone docs predating this session)
moved to `archive/`. This was a deliberate cleanup, not a rename for its
own sake — the project root had 25+ markdown files before this, which
is exactly the "which of these do I trust" problem §0 warns about.
`testing/README.md` is the entry point for the two testing directories;
everything in `archive/` is historical, superseded, not maintained, and
not a source of current truth about anything.

- **`testing/test-target/`** — PixelMart, a small Flask app with 12 real,
  hand-exploited vulnerabilities and 6 correctly-implemented true
  negatives, built specifically because OWASP Juice Shop's
  vulnerabilities are so publicly documented that any LLM's "success"
  against it is contaminated by training-data recognition rather than
  genuine reasoning. Ground truth: `testing/test-target/ANSWER_KEY.md` — don't
  read it before running the harness against the app, including if
  that's you in a future session.
- **`testing/test-target/phase1_record.py`, `phase2_answers.py`,
  `phase3_run.py`** — the three-phase methodology (record real
  dispatch → answer genuinely from real prompts → run real end-to-end
  pipeline) used to produce `testing/test-target/DISCOVERY_RUN_RESULTS.md`.
- **`testing/blind-test-kit/`** — self-contained package (own harness copy,
  sanitized target with every hint stripped, generalized
  `harness_driver.py`, templates) for handing to a different agent who
  didn't build the target and doesn't have the answer key. Entry point:
  `testing/blind-test-kit/METHODOLOGY.md`. First real run's raw evidence is
  preserved at `testing/blind-test-kit/run-1-results/` (excluded from the
  handoff zip on purpose — showing a fresh tester a prior run's
  discovered endpoints would undercut their own exploration).
- **`README.md`** rewritten as an actual setup/architecture/GPU-feasibility
  guide; the old research-narrative content preserved as `RESEARCH_NOTES.md`.

---

## 5b. Fixed after this handover was written, during real live use

Once Ollama actually became reachable from a real Burp installation (a
first for this project), real use surfaced four more bugs in quick
succession — the exact pattern §0 describes, now happening live rather
than in a sandbox:

1. **`HarnessClient`'s `HttpClient` had no explicit proxy configured**,
   so it fell back to the JVM's default `ProxySelector`, meaning any
   system/VPN proxy silently intercepted even localhost traffic —
   reachable in a browser, "Unreachable" in the extension. Fixed:
   `.proxy(HttpClient.Builder.NO_PROXY)`.
2. **All 8 of `HarnessClient`'s HTTP call sites threw
   `IllegalArgumentException: wrong number, 0, of parameters`** on
   every single request whenever no bearer token was configured (the
   normal case) — `HttpRequest.Builder.headers(String...)` requires a
   non-empty, even-length array, and the old `authHeaders()` returned
   `new String[0]`. This meant `/analyze`, `/estimate`, and everything
   else were completely non-functional with no token set, not just the
   health check. Fixed with a `newRequestBuilder()` helper that only
   calls `.header(...)` when a token actually exists; reproduced the
   exact exception standalone before and after to confirm.
3. **Every request silently lost its body**, producing `HTTP 422:
   "loc":["body"], "msg":"Field required"` from the harness server,
   even though `Content-Length` was correct on the wire. Cause:
   `HttpClient`'s default version preference is HTTP_2, which sends a
   cleartext-upgrade attempt (`Upgrade: h2c`) alongside every request
   even for plain `http://` URLs; `uvicorn` mishandles that combination
   and drops the body. Reproduced deterministically (curl succeeds,
   identical Java request fails, forcing `HTTP_1_1` fixes it). Fixed:
   `.version(HttpClient.Version.HTTP_1_1)`.
4. **`/analyze` used the same 120s timeout as every fast, non-LLM
   endpoint**, which cannot survive real multi-agent dispatch at
   `concurrency.max_parallel_agents: 3` (added earlier this session
   specifically to protect VRAM — which trades wall-clock time for
   memory safety). Fixed: `/analyze` now has its own
   `analysisTimeoutSeconds` (default 600s), exposed as an editable
   field in the Harness panel so it's tunable per-hardware without a
   rebuild.
5. **A live run against testfire.net hit `prompt_validator.py`'s
   network-access blocked-pattern**, rejecting a real agent call
   because response content legitimately contained "Too many
   requests. Please try again" — the pattern's `requests\.|httpx\.|
   urllib\.` half required trailing whitespace after the dot, matching
   ordinary English prose as readily as `requests.get(...)`. This is
   the exact class of bug the original prompt_validator.py fix (see
   §4) already found once in a sibling pattern; this was the
   predicted-but-not-yet-done audit of the rest of `blocked_patterns`,
   forced by real use rather than done proactively. Fixed the same way:
   require no whitespace between the dot and the method name (real
   code never has a space there; English sentences always end the dot
   with one). Bare shell commands (`wget`, `curl`) are unaffected.
6. **`ValidationExecutor.exchangeFingerprint()` (Java) computed a
   different hash than `planner.py`'s `exchange_fingerprint()` (Python)
   for the exact same request**, whenever the request had a duplicate
   header name (e.g. two `Cookie` headers) — common enough in real
   traffic that "Execute selected test plan" was failing with "Source
   request fingerprint does not match the plan" repeatedly in live use.
   Cause: the original `/analyze` submission runs headers through
   `headersToMap()`, which merges duplicate names into one entry joined
   by `\n` (the wire format can't represent duplicate JSON keys) —
   `exchangeFingerprint()` re-hashed the raw, non-deduplicated header
   list instead. Fixed by deduplicating the same way before hashing.
   Also caught a second, subtler discrepancy in the same fix: Python
   sorts by the *original-case* header name before lowercasing for
   output, not after — lowercasing first (my initial fix) gives a
   different sort order whenever two header names' relative order
   depends on case (e.g. `Content-Type` vs `accept`). Verified with
   three test cases run independently through the real Python
   `exchange_fingerprint()` and a standalone reproduction of the fixed
   Java logic — all three hashes matched byte-for-byte, including the
   mixed-case case; confirmed the old Java code produces a different
   hash than Python for the duplicate-header case specifically.
7. **"Execute selected test plan" only ever reported its result to
   Burp's separate extension Output log** (`api.logging().logToOutput`),
   with no visible connection to the button just clicked and no
   in-tab history — real user confusion ("I don't see the results").
   Added a persistent result area directly in the LLM Harness tab,
   updated via the same callback that already logged to Output (kept
   both).

All Java fixes this session were verified against a real running
harness server in this sandbox where possible (not just compiled) —
reproduced each bug standalone first, then confirmed the fix resolves
it. The fingerprint fix specifically was cross-verified against the
real Python function it must match, not just against another Java
reproduction of itself. 439 tests pass at this checkpoint (before the
§5c fixes below add 9 more).

## 5c. Fixed and documented after 5b, during real live use against Juice Shop

A real, running Ollama model, tested against Juice Shop's known
vulnerable `PUT /api/BasketItems/<id>` (negative-quantity basket
manipulation), surfaced two more real bugs and one large, previously-
undocumented capability gap:

1. **A finding's self-reported `validation_hints: ["sqlmap"]` was
   trusted unconditionally, regardless of the finding's own resolved
   category.** The prompt's worked JSON example always showed
   `"validation_hints": ["sqlmap"]` as its only illustration,
   regardless of context, and models copy worked examples more
   reliably than they follow prose instructions — confirmed live: a
   single exchange's 9 findings (idor, business_logic, xss, graphql
   ×3, api_security ×2) produced an analyst-facing plan picker with 7
   near-identical `sql_injection_validation [local_tool]` buttons, for
   an exchange with no SQL injection finding at all. Fixed in two
   places in `planner.py` (the value was trusted both via a direct
   append and via a separate dispatch-loop branch — fixing only one
   left the other still firing), gated so `"sqlmap"` is only trusted
   when the category is `"sqli"` or genuinely unresolved (preserving
   the real fallback case). Also softened the prompt itself
   (`base_agent.py`): the worked example now shows `"validation_hints":
   []`, and the instruction text explicitly says `"sqlmap"` only
   applies to SQL injection hypotheses.
2. **`categories.canonicalize()`'s exact-match strictness rejected real,
   correctly-shaped category strings purely due to cosmetic decoration**
   — found live: `"Insecure Direct Object Reference (IDOR)"`,
   `"Broken Object-Level Authorization (BOLA/IDOR)"`, and `"Cross-site
   scripting (reflected)"` all returned `None` from `canonicalize()`,
   purely because of a trailing parenthetical annotation and (for the
   second one) a hyphen where the synonym table has a space. This
   meant those findings' *correct* test plans (`cross_identity_compare`,
   `reflection_context_validation`) either never got generated, or
   only got generated alongside the spurious sqlmap one from bug #1.
   Fixed by normalizing (strip one trailing `(...)`, hyphens to spaces,
   collapse whitespace) before the exact-match lookup — still an exact
   match against the fixed table afterward, not fuzzy/substring
   matching; genuinely ambiguous strings like `"Broken Access Control"`
   correctly still return `None`. Both fixes verified directly against
   the exact real strings from this session's transcript, cross-checked
   against what a made-up unrecognized phrase does (still `None`) and
   what a genuine sqli finding with the same hint does (plan still
   generated) — 12 new tests across `test_planner.py` and the new
   `test_categories.py`.
3. **Only 8 of 30 `_CAPABILITIES` entries `planner.py` declares as
   `execution_plane="burp"` (i.e. "approvable and runnable through
   Burp") had a Java executor.** Cross-referenced directly:
   `authorization_boundary_compare`, `bounded_rate_limit_probe`,
   `controlled_callback_probe`, `cross_identity_compare`,
   `logout_invalidation_compare`, `reflection_context_validation`,
   `session_fixation_compare`, `workflow_replay_compare` were
   implemented. Everything else — `api_security_validation`,
   `jwt_validation`, `csrf_validation`, `xxe_validation`,
   `http_request_smuggling_detection`, `cors_misconfiguration_detection`,
   and 16 others — fell to `ValidationExecutor`'s default case and
   reported `"No typed executor exists for capability '...'."`, an
   honestly-worded but easy-to-miss dead end. **5 of these were
   implemented in a follow-up pass — see §5d below; 17 remain.**
   The picker dialog (`HarnessPanel.choosePlan()`) marks any capability
   still lacking a real executor `(not yet implemented)`
   directly in its label, so the analyst sees this before spending an
   approval click, not after. The set of implemented capabilities is
   hardcoded in `HarnessPanel.java` and must be kept in sync with
   `ValidationExecutor.java`'s switch statement **by hand** — there is
   still no shared source of truth between the two, the same class of
   risk this project's own comments already flag for the fingerprint
   functions (§5b #6).

448 tests pass. Compiled clean against the same 19-error baseline.

## 5d. 5 of the 22 missing capabilities implemented

`csp_clickjacking_validation`, `info_disclosure_scan`,
`cors_misconfiguration_detection`, `open_redirect_validation`, and
`jwt_validation` now have real Java executors in
`ValidationExecutor.java`, each backed by a Montoya-free pure-logic
class in `com.harness.llm.logic` (matching the existing pattern —
`XssPayloadLogic`, `SsrfCallbackLogic`, etc.):

- **`CspClickjackingLogic`** / **`InfoDisclosureLogic`** — passive,
  classify the already-captured response, no new request needed.
- **`CorsMisconfigLogic`** — sends the captured request once more with
  an added, clearly-foreign `Origin` header; confirms only when
  `Access-Control-Allow-Origin` reflects it exactly AND
  `Access-Control-Allow-Credentials: true` is also present (the
  actually-dangerous combination, not just a permissive ACAO alone).
- **`OpenRedirectLogic`** — reuses `SsrfCallbackLogic`'s URL-shaped
  parameter name heuristic rather than duplicating it (SSRF and open
  redirect target near-identically-named parameters); confirms only on
  an exact `Location` match to the injected external URL.
- **`JwtForgeryLogic`** — forges an `alg:none` variant (payload left
  byte-for-byte unchanged — this probes signature verification, not
  claim tampering) and, if that's rejected, a garbled-signature variant;
  confirms only if the forged token gets both the same status code AND
  a similarly-shaped response body as the original legitimately-signed
  request. This is the same alg:none check worked through by hand in
  `testing/test-target/` earlier this project, now deterministic.

**Verification, in order:**
```bash
# Discovered dev-tools/RunTests.java (a real reflection-based JUnit
# runner) was already present but hadn't been exercised this session --
# ran the EXISTING logic tests for real first, to confirm the
# infrastructure works before relying on it:
cd /home/claude/project/project
find burp-extension/src/main/java/com/harness/llm/logic burp-extension/src/test/java/com/harness/llm/logic dev-tools/stubs/org -name "*.java" > /tmp/logicsrc.txt
javac -d /tmp/logictest -nowarn @/tmp/logicsrc.txt
javac -d /tmp/logictest -nowarn dev-tools/RunTests.java
cd /tmp/logictest && java RunTests com.harness.llm.logic.XssPayloadLogicTest com.harness.llm.logic.SsrfCallbackLogicTest com.harness.llm.logic.IdentityCompareLogicTest com.harness.llm.logic.WorkflowReplayLogicTest com.harness.llm.logic.SessionLifecycleLogicTest com.harness.llm.logic.IdentityLabelResolverTest com.harness.llm.logic.CspClickjackingLogicTest com.harness.llm.logic.InfoDisclosureLogicTest com.harness.llm.logic.CorsMisconfigLogicTest com.harness.llm.logic.OpenRedirectLogicTest com.harness.llm.logic.JwtForgeryLogicTest
# Expected: === TOTAL: 97 passed, 0 failed ===
```
59 pre-existing tests + 38 new ones across the 5 new logic classes, all
passing for real (not just compiled). Two stub files needed extending
to support this work — `HttpRequest`/`HttpResponse` (`withAddedHeader`,
`withUpdatedHeader`, `headerValue`) and JUnit's `Assertions`
(`assertNotEquals`) — verified against the real Montoya API javadoc via
web search before adding, not guessed. Compiled the full main-source
tree against the documented 19-error baseline afterward — still
exactly 19, all pre-existing missing-jar errors, zero new ones.

**17 capabilities remained unimplemented at that point** — deliberately
not attempted in the same pass, because they don't fit the same clean
mutate-resend-classify shape the 13 implemented ones share:
`http_request_smuggling_detection` and `web_cache_poisoning_detection`
need raw request framing / real cache-timing behavior, both with real
risk of affecting production infrastructure if done carelessly;
`websocket_cswsh_validation` needs actual WebSocket protocol handling;
`subdomain_takeover_detection` needs DNS resolution Burp's HTTP client
doesn't provide; `oauth_flow_validation` is a genuine multi-step
protocol flow, not a single mutate-and-compare; `crypto_transport_validation`
needs TLS-layer details the Montoya HTTP API doesn't expose;
`command_injection_validation` and `race_condition_validation` are
timing-based and need careful calibration to avoid false
positives/negatives without live testing. Two of the remaining ones
(`xxe_validation`, `csrf_validation`) were implemented next — see §5e.

## 5e. 2 more implemented: xxe_validation, csrf_validation

- **`XxeCollaboratorLogic`** — deliberately mirrors
  `SsrfCallbackLogic`'s `Verdict`/`Evidence`/interaction-list shape,
  since it's the same underlying mechanism (an out-of-band Collaborator
  callback) applied to a different injection point (an XML external
  entity in the request body, not a URL-shaped parameter). Detects
  XML-ness by both Content-Type and body shape (some real APIs accept
  XML with a generic or incorrect Content-Type header); replaces the
  entire body with a minimal, schema-agnostic external-entity test
  document rather than trying to graft an entity reference into an
  unknown schema — documented explicitly in the class's own comment
  that this can false-negative if the parser validates against a
  schema before ever reaching entity resolution, which is unusual but
  possible.
- **`CsrfLogic`** — scoped explicitly (in the class's own doc comment,
  not just this handover) to classic cookie-based session CSRF on
  state-changing requests. Bearer/API-key-authenticated requests get
  `REJECTED` with an explicit "not applicable the same way" reason
  rather than being silently skipped — a CORS misconfiguration could
  still expose the same endpoint differently, which is
  `cors_misconfiguration_detection`'s job, not this one's. If a
  CSRF-token-shaped header or form field is found, it's removed/
  invalidated and the request resent once; if none is found at all,
  reports the passive "no token observed" signal without spending an
  extra request.

Required extending the `HttpRequest` stub with `withBody(String)` —
verified against the real Montoya API javadoc (fetched directly, not
inferred from a search snippet) before adding, same as the header
methods in §5b.

**Verification:** 19 new tests (10 for `XxeCollaboratorLogicTest`, 9 for
`CsrfLogicTest`), run for real via the same `dev-tools/RunTests.java`
harness as before:
```bash
cd /home/claude/project/project
find burp-extension/src/main/java/com/harness/llm/logic burp-extension/src/test/java/com/harness/llm/logic dev-tools/stubs/org -name "*.java" > /tmp/logicsrc.txt
javac -d /tmp/logictest -nowarn @/tmp/logicsrc.txt
javac -d /tmp/logictest -nowarn dev-tools/RunTests.java
cd /tmp/logictest && java RunTests com.harness.llm.logic.XssPayloadLogicTest com.harness.llm.logic.SsrfCallbackLogicTest com.harness.llm.logic.IdentityCompareLogicTest com.harness.llm.logic.WorkflowReplayLogicTest com.harness.llm.logic.SessionLifecycleLogicTest com.harness.llm.logic.IdentityLabelResolverTest com.harness.llm.logic.CspClickjackingLogicTest com.harness.llm.logic.InfoDisclosureLogicTest com.harness.llm.logic.CorsMisconfigLogicTest com.harness.llm.logic.OpenRedirectLogicTest com.harness.llm.logic.JwtForgeryLogicTest com.harness.llm.logic.XxeCollaboratorLogicTest com.harness.llm.logic.CsrfLogicTest
# Expected: === TOTAL: 116 passed, 0 failed ===
```
Compiled the full main-source tree against the documented baseline
afterward — still exactly 19 errors, all pre-existing, zero new.

**15 of 30 `_CAPABILITIES` entries had a real Burp executor at this
point.** `ssti_validation` was implemented next — see §5f.
`nosql_validation` turned out to need more care than initially assumed
— also in §5f.

---

## 5f. ssti_validation implemented; nosql_validation deliberately deferred

**`ssti_validation`** — `SstiPayloadLogic` mirrors `XssPayloadLogic`'s
exact shape (a `Payload` list, `nextPayload()` cycling, a `classify()`
that needs real evaluation evidence, not just echo). Injects the same
arithmetic expression (`7*13` → `91`, chosen to avoid coincidental
appearance) across five template-engine syntaxes (Jinja2/Twig,
FreeMarker, Velocity, ERB, Smarty). `CONFIRMED` requires three things
simultaneously: the result appears in the mutated response, the result
is absent from the *baseline* (pre-injection) response — guards
against a response that just happens to already contain "91" somewhere
— and the raw template text does not survive, proving real evaluation
rather than plain reflection. The executor method
(`sstiValidation`) deliberately mirrors `reflection()`'s (XSS) exact
iteration structure (all non-cookie parameters × all payloads, stop at
first CONFIRMED) for consistency with the established pattern in this
file. 8 new tests, run for real:
```bash
cd /home/claude/project/project
find burp-extension/src/main/java/com/harness/llm/logic burp-extension/src/test/java/com/harness/llm/logic dev-tools/stubs/org -name "*.java" > /tmp/logicsrc.txt
javac -d /tmp/logictest -nowarn @/tmp/logicsrc.txt && javac -d /tmp/logictest -nowarn dev-tools/RunTests.java
cd /tmp/logictest && java RunTests com.harness.llm.logic.XssPayloadLogicTest com.harness.llm.logic.SsrfCallbackLogicTest com.harness.llm.logic.IdentityCompareLogicTest com.harness.llm.logic.WorkflowReplayLogicTest com.harness.llm.logic.SessionLifecycleLogicTest com.harness.llm.logic.IdentityLabelResolverTest com.harness.llm.logic.CspClickjackingLogicTest com.harness.llm.logic.InfoDisclosureLogicTest com.harness.llm.logic.CorsMisconfigLogicTest com.harness.llm.logic.OpenRedirectLogicTest com.harness.llm.logic.JwtForgeryLogicTest com.harness.llm.logic.XxeCollaboratorLogicTest com.harness.llm.logic.CsrfLogicTest com.harness.llm.logic.SstiPayloadLogicTest
# Expected: === TOTAL: 124 passed, 0 failed ===
```
Compiled clean against the same 19-error baseline. Python suite
unaffected (448 tests).

**`nosql_validation` was NOT implemented, on purpose, after
investigation rather than before it.** The obvious approach — replace a
JSON body field's string value with a MongoDB operator object like
`{"$ne": null}` — cannot be expressed through Burp's `HttpParameter`
API, which represents a parameter's value as a plain string; whether
passing a raw `{"$ne": null}` string through
`HttpParameter.parameter(name, value, JSON)` gets inserted as a literal
nested object or as an escaped string literal is genuinely uncertain
from the interface alone, and this sandbox has no live Burp instance to
check the real behavior against. A second approach (PHP-style bracket-
array parameter names, e.g. `password[$ne]=1`, a real and well-
established NoSQL injection technique against PHP+MongoDB backends)
avoids the nested-object problem but requires removing the original
parameter and adding a differently-named one — cleanly expressible via
`withRemovedParameters`/`withParameter`, but the combined behavior
(does the backend correctly merge/replace rather than see two
conflicting values) is exactly the kind of thing this project's own
recurring lesson (§0) says needs a real request-response round trip to
trust, not an assumption about how the API composes. Shipping a
plausible-but-unverified implementation here would be the same mistake
the earlier `HttpClient.headers()`/HTTP-2 bugs already made once this
session — confident-looking code that was never actually exercised.
Left for whoever next has live Burp access to verify the parameter
semantics empirically before writing the classifier logic.

---

## 5g. 2 more implemented: deserialization_format_confirmation, command_injection_validation

**`deserialization_format_confirmation`** — passive, no new request.
Deliberately scoped to pure-ASCII text signatures only (base64-encoded
Java serialized object prefix `rO0AB`, PHP's `serialize()` text format,
the `__VIEWSTATE` field name) — **not** raw binary magic bytes (Java
serialization's `0xAC 0xED` header, .NET BinaryFormatter's leading
bytes), because `HttpMessage.bodyToString()`'s exact byte-to-String
decoding isn't documented anywhere findable (checked via web search
before writing this, not assumed), and a raw non-ASCII byte sequence
run through an unknown decoder could come out as anything. Every
signature used here is confirmed to survive any common text encoding
unchanged, sidestepping the question instead of guessing at its answer
— the same discipline that led to deferring `nosql_validation` in §5f,
applied here to actually still ship something, because in this case a
narrower, verifiably-safe scope was available. 7 new tests.

**`command_injection_validation`** — the first timing-based check
implemented this session. Uses a **differential** design deliberately:
two different injected sleep durations (2s and 6s) compared against
each other, not one sleep duration against a noisy baseline. A single
slow response proves nothing by itself (ordinary network/server
jitter); but if the response-time *delta* between two otherwise-
identical requests tracks the *requested* duration delta, that's
specific evidence of real command execution, because jitter doesn't
scale proportionally with an attacker-chosen number baked into the
payload. This is the same principle sqlmap's own time-based blind SQLi
detection uses. Confidence is calibrated lower than the content-based
checks (0.75 `CONFIRMED` vs. 0.85-0.93 elsewhere) specifically because
timing evidence is inherently less certain than content evidence, and
that's stated in the finding text, not just in code comments. Bounded
deliberately (one candidate parameter, 2 of the 5 available payload
templates) unlike `reflection()`/`sstiValidation()`'s "try everything"
approach — each attempt here costs several real seconds of wait time
(the sleep durations, if the injection works), so exhaustively trying
every parameter and payload would make an analyst wait a genuinely
long time for one click. 8 new tests.

**Verification**, same discipline as every prior batch:
```bash
cd /home/claude/project/project
find burp-extension/src/main/java/com/harness/llm/logic burp-extension/src/test/java/com/harness/llm/logic dev-tools/stubs/org -name "*.java" > /tmp/logicsrc.txt
javac -d /tmp/logictest -nowarn @/tmp/logicsrc.txt && javac -d /tmp/logictest -nowarn dev-tools/RunTests.java
cd /tmp/logictest && java RunTests com.harness.llm.logic.XssPayloadLogicTest com.harness.llm.logic.SsrfCallbackLogicTest com.harness.llm.logic.IdentityCompareLogicTest com.harness.llm.logic.WorkflowReplayLogicTest com.harness.llm.logic.SessionLifecycleLogicTest com.harness.llm.logic.IdentityLabelResolverTest com.harness.llm.logic.CspClickjackingLogicTest com.harness.llm.logic.InfoDisclosureLogicTest com.harness.llm.logic.CorsMisconfigLogicTest com.harness.llm.logic.OpenRedirectLogicTest com.harness.llm.logic.JwtForgeryLogicTest com.harness.llm.logic.XxeCollaboratorLogicTest com.harness.llm.logic.CsrfLogicTest com.harness.llm.logic.SstiPayloadLogicTest com.harness.llm.logic.DeserializationFormatLogicTest com.harness.llm.logic.CommandInjectionTimingLogicTest
# Expected: === TOTAL: 139 passed, 0 failed ===
```
Compiled clean against the same 19-error baseline. Python suite
unaffected (448 tests).

**18 of 30 `_CAPABILITIES` entries now have a real Burp executor.** 12
remain: `http_request_smuggling_detection`, `web_cache_poisoning_detection`,
`websocket_cswsh_validation`, `subdomain_takeover_detection`,
`oauth_flow_validation`, `crypto_transport_validation`,
`race_condition_validation`, `nosql_validation` (deferred, §5f),
`file_upload_validation`, `attack_surface_mapping`, and 2 others.
`race_condition_validation` is the most reasonable next pick — it can
reuse the same differential-timing discipline established here
(concurrent identical requests, checking whether more than the
intended number succeed, similar in spirit to how the Python side's
own `test-target/`/PixelMart work already demonstrated this exact race
condition class by hand). The rest still need genuinely different
handling (raw sockets, DNS, WebSocket protocol, TLS internals, or
multipart construction).

---

## 6. Still open — consolidated, current status noted

1. **`coordinator.py`'s fail-open-to-all-36-agents fallback.** Confirmed
   still present (`grep -n "fallback: coordinator" harness/coordinator.py`).
   Across all 22 exchanges in this session's discovery run, fast_path
   was confident every time and the coordinator was never invoked once
   — its real behavior under live traffic is still unverified.
2. **`sqlmap`'s real-target miss rate** — reported by a prior session,
   not re-tested this session (this session's SQLi work confirmed
   injection via direct UNION-based exfiltration, not via `sqlmap`).
3. **Duplicate `_resolve_known_vulnerabilities` implementations** in
   `analysis_pipeline.py` and `orchestrator.py` — not touched this
   session, `grep -n "_resolve_known_vulnerabilities" harness/*.py` to
   confirm both still exist.
4. **No *rigorous, scored* live-model baseline exists yet — but a real
   live-model setup finally does.** This session, for the first time,
   had a real user with a real Ollama-backed Burp installation running
   against a real target (Juice Shop), producing genuine model
   completions (`agentic_burp.audit` logs show real `llama3.1:8b`/
   `gemma2:9b` calls with real token counts). Every prior handover's
   "no live model" caveat about *reachability* is now out of date. What
   still hasn't happened: running that real setup against
   `testing/test-target/`'s known answer key (§5) to get an actual
   precision/recall number, the way `testing/blind-test-kit/` was
   designed for. Do that next if you have access to the same setup —
   it's now a realistic, not hypothetical, next step.
5. **`jwt`/`csrf` agents have zero entries anywhere in `fast_path.py`'s
   pattern tables** and can only be reached via the coordinator, which
   (§6.1) essentially never fires. The JWT-forgery detection gap was
   closed this session by making the evidence visible to `auth` (§3b
   #5), not by giving `jwt` a way to be reached — `jwt` and `csrf` as
   standalone agents are still effectively dead code.
6. **`retry_policy.py` and `payload_library.py` (Python side) remain
   fully unwired** — confirmed this session (§4).
7. **A genuinely blind, adversarial test has never successfully
   happened.** The one attempt this session produced no usable signal
   (§3d). This is now the top priority.
8. **18 of 30 `_CAPABILITIES` entries now have a real Burp executor**
   (§5c #3, §5d, §5e, §5f, §5g) — 10 implemented this session in four
   passes (jwt_validation, csp_clickjacking_validation,
   info_disclosure_scan, cors_misconfiguration_detection,
   open_redirect_validation, xxe_validation, csrf_validation,
   ssti_validation, deserialization_format_confirmation,
   command_injection_validation), 12 remain. Not a bug to hunt for;
   deliberate, scoped work. `nosql_validation` was investigated and
   deliberately deferred (§5f) — needs live Burp access to verify
   parameter-mutation semantics before it can be implemented correctly,
   not just a different capability category. `race_condition_validation`
   is the next reasonable pick (§5g — can reuse the differential-timing
   discipline just established). The rest need genuinely different
   handling (raw sockets, DNS, WebSocket protocol, TLS internals, or
   multipart construction) and deserve their own focused pass.

---

## 7. Priority order for whoever picks this up next

1. **Run `testing/blind-test-kit/` again**, with the fixed `METHODOLOGY.md`,
   with a tester who has not read this document. This has been
   attempted once and failed to produce signal — it has not been
   abandoned, it needs a real second attempt. With a real Ollama setup
   now confirmed working (§0), this is more achievable than ever.
2. **Run `testing/test-target/`'s three-phase discovery against a real,
   reachable Ollama setup** (§6.4) instead of a human/agent substitute
   — no longer blocked on Ollama reachability itself, just on someone
   with that setup actually doing this specific run against the known
   answer key. This is the oldest, largest, most-repeated open item
   across every handover this project has had, and it's now genuinely
   within reach.
3. **Add fast_path coverage for `jwt` and `csrf`** (§6.5) — bounded,
   well-scoped, and `testing/test-target/`'s discovery run already gives you a
   ready-made JWT test case.
4. Items 1–3 and 6 in §6 — coordinator fail-open, sqlmap miss rate,
   duplicate known-vuln resolution, unwired retry/payload modules.
5. **Implement a handful of the still-missing 12 Burp validation
   executors** (§5g, §6.8) — 10 are done (`jwt`, `csp_clickjacking`,
   `info_disclosure`, `cors`, `open_redirect`, `xxe`, `csrf`, `ssti`,
   `deserialization_format_confirmation`, `command_injection_validation`).
   `race_condition_validation` is the next reasonable pick (reuse the
   differential-timing pattern from `command_injection_validation`).
   `nosql_validation` needs someone with live Burp access to verify
   `HttpParameter`'s JSON-value and remove+add-parameter semantics
   empirically first (§5f) — don't implement it from the interface
   alone. The rest need genuinely different handling per §6.8.

**Don't start by reading the other 20+ markdown files at this project's
root and trying to synthesize a mental model from them.** Start with
§1's verification commands, confirm the numbers match, then work
through §3–6 the same way — every claim here has a command next to it
for exactly that reason.
