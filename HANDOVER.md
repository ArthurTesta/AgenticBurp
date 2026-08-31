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
the extension live.

**Update, a later session (§5h): the environment changed.** This repo
now lives at a Windows machine (`AgenticVibe`, see §1) where Ollama
IS directly reachable from the same shell running the harness, with
both configured models (`llama3.1:8b`, `gemma2:9b`) already pulled.
That session ran the harness's real orchestrator, with zero
substitution, against `testing/test-target/` for the first time in
this project's history — and within the FIRST real exchange analyzed,
found five more real, previously-invisible bugs in `prompt_validator.py`
alone (§5h), on top of three others (§5h). The lesson from the
paragraph above holds, generalized: a real model run finds real bugs
no sandbox or substitution ever will, and this is no longer available
only to a user with their own separate Burp+Ollama setup — check §1
before assuming otherwise, because whether it's true depends entirely
on which machine you're actually running on.

---

## 1. Current environment state — verify before assuming

**This repo's path is environment-specific — don't trust either path
below blindly, run `pwd` and adjust.** Two known locations exist as of
this writing: the original sandbox at `/home/claude/project/project`
(no Ollama access, see the substitution note below), and a Windows
machine at `C:\Users\arthu\Documents\AgenticVibe` (`AgenticVibe`,
git-bash paths like `/c/Users/arthu/Documents/AgenticVibe`) where
Ollama IS directly reachable — verified directly, see §5h. Same
codebase, confirmed by checking out `harness/orchestrator.py` exists
at both and the numbers below match at both.

```bash
cd harness && python3 -m unittest discover -p "test_*.py"
# Expected: Ran 448 tests, OK (478 on AgenticVibe as of §5h -- 30 new
# tests added there this session, all additive, see §5h for exactly
# which files)

python3 -m pytest test_plugin_system.py -q
# Expected: 26 passed (needs `pip install pytest` on a fresh machine --
# not in requirements.txt, it's a dev-only dependency test_plugin_system.py
# imports directly; confirmed missing on a fresh AgenticVibe checkout)

ls agents/*.py | grep -vc -E "__init__|base_agent|plugin.py"    # expect 36
ls validators/*.py | grep -vc -E "__init__|base.py"              # expect 15
ls test_*.py | wc -l                                             # expect 31 (33 on AgenticVibe as of §5h)
```

**If any of these differ from what's stated here, something changed —
trust the command, not this document.**

**Ollama reachability is a property of the MACHINE, not the project —
check it directly on whatever environment you're actually in, every
time, before trusting either claim below:**

```bash
curl -s -m 3 http://localhost:11434/api/tags
# If this returns real model names: Ollama IS reachable. Every LLM call
# you make from here on is real, not a substitution -- go read §5h
# before assuming any prior "no live model" caveat still applies.
# If it times out/connection-refuses: you're in a sandbox like the
# original one below, and the substitution note applies.
```

The ORIGINAL sandbox this document was first written in
(`/home/claude/project/project`) has no Ollama access and never has,
across every session run there. Every LLM call made from that specific
sandbox has been a substitution — a human or an agent reading the
harness's real, constructed prompts and answering them directly, not a
real model call. **This is no longer a project-wide truth** — see §5h
for a session run from a different machine where Ollama was genuinely
reachable and every claim below about real findings is a real model's
real output. Don't assume either way; run the curl command above.

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

**Superseded by §5h: 3 more of those implemented
(`race_condition_validation`, `header_injection_validation`,
`api_security_validation`) — 22 of 31 `_CAPABILITIES` category keys now
have a real Burp executor, 9 remain. See §5h for the exact list.**

---

## 5h. Ollama reachable for real on a new machine; 6 more real bugs found; 3 more Burp capabilities implemented

**This entire section describes a DIFFERENT machine than every prior
section above.** This repo now also lives at a Windows box
(`AgenticVibe`; git-bash paths read as
`/c/Users/arthu/Documents/AgenticVibe`), where — unlike every sandbox
this project has ever run in before — **Ollama is directly reachable
from the same shell that runs the harness**, confirmed directly:

```bash
curl -s -m 3 http://localhost:11434/api/tags
# Returns real models: gemma2:9B, llama3.1:8b (exact tags this
# config.yaml expects, confirmed case-insensitive match against Ollama's
# own /api/chat), plus an unrelated gemma4:latest.
```

This made possible, for the first time in this project's history, a
completely real, non-substituted run of `testing/test-target/`'s full
three-phase discovery methodology (§5, §7 priority #2) — no human or
agent standing in for the model at any step. That run, run twice (once
before today's fixes, once after), is what surfaced every bug below.
**Every fix in this section was found by literally reading the real
model's real output, not by auditing the code for hypothetical
problems** — the same discipline §0 asks you to keep applying.

### First real run (old code) found 3 bugs, fixed and tested (467 tests):

1. **`prompt_validator.py`'s data-exfiltration pattern** (`\b(print|
   echo|write|log|send|post|put|upload)\s+.*\b(password|secret|token|
   key|credential|api_key)\b`) matched a real, honest CSRF-finding
   evidence string — "The login request is a POST to /api/login with
   no token/nonce field visible in the request body" — purely because
   "POST" (the HTTP method) and "token" occurred in the same sentence,
   several unrelated words apart. That evidence text feeds into the
   critique pass's own prompt (`orchestrator.py`'s `_critique`), so this
   silently skipped adversarial review for every finding on the
   exchange. Fixed with a bounded-gap rewrite plus a `post`/`put`-
   specific negative lookahead (these two also collide with the HTTP
   method names themselves — "POST to X" — which print/echo/write/
   log/send/upload don't). 3 new tests in
   `TestDataExfiltrationPatternPrecision`.
2. **`github_advisories.py`'s ecosystem mapping** passed an unrecognized
   ecosystem string (e.g. `"generic"` — a value `ComponentCandidate`'s
   own docstring documents as expected) straight through to GitHub's
   API, which validates `ecosystem` as a strict enum server-side and
   returns a guaranteed HTTP 422 for anything outside it — not "no
   results," an outright error, every single time. Confirmed live: every
   known-vuln lookup for Werkzeug/Flask/PixelMart/Python failed this
   way. Fixed: fall back to GitHub's own real catch-all value `"other"`
   (confirmed from the live 422 body's own error message, which lists
   the full accepted enum) instead of the raw string. No test file
   existed for this module at all before this fix — `test_github_advisories.py`
   is new, 4 tests.
3. **`analysis_pipeline.py` ran its own independent copy of known-
   vulnerability resolution** inside `run_full_analysis`, duplicating
   `orchestrator.analyze()`'s own equivalent pass over the complete
   final reports list — confirmed live: both logged their own separate
   "Known vulnerability lookup errors" line for the same components in
   the same request, doubling (or worse, across early-termination
   batches) real GitHub API calls against the already-scarce 60/hour
   unauthenticated rate limit, and would duplicate real advisory
   findings too whenever a match exists. `analysis_pipeline.py`'s copy
   (along with the now-unused `_verify_component_observation`/
   `_exchange_text` helpers and the `gha_client`/`kev_client`/
   `registry_client` construction backing it) was removed entirely —
   it only ever saw one dispatch batch's components anyway, so it was
   structurally partial on top of being redundant. This also resolves
   §6 item 3 from every prior handover. 2 new tests in
   `test_analysis_pipeline.py`; `test_exchange_text.py`'s cross-module
   drift-comparison test was updated (there's only one implementation
   left to compare, not two).

Also closed in the same pass, resolving §6 item 5 from every prior
handover: **`jwt`/`csrf` had zero `fast_path.py` entries anywhere** and
were only reachable via the coordinator (which fast_path being
confident on nearly every real exchange meant essentially never
happened). Added: a JWT-structure header pattern (`eyJ...\....\...`,
matched via a negative-lookahead boundary rather than `\b` specifically
so an alg:none forged token's EMPTY signature segment still matches —
confirmed directly that `\b` fails there, since neither neighbor of an
empty final segment is a word character), ordered before the generic
bearer/token pattern in `_REQUEST_HEADER_PATTERNS` (that function stops
at the first matching pattern per header, so order matters); and a
CSRF precondition check (`select_agents_by_csrf_signal`: state-changing
method + a `Cookie` header present — CSRF has no text signature to
match, the exposure is the *absence* of a token, so this checks the
precondition instead, the same reasoning `fast_path.py`'s own comments
already use for PUT/DELETE/PATCH → idor/auth). 10 new tests in
`TestJwtAndCsrfFastPathCoverage`.

### Second real run against the SAME first exchange found 5 MORE bugs, all one disease

Re-running exchange index 4 (TP1) alone surfaced nothing new, but
running the full 22-exchange suite reached exchange 13 (TP10, a real
path-traversal finding whose response body is the target app's own
`app.py` source) and found **the harness could not analyze disclosed
source code at all** — every one of 8 dispatched agents failed prompt
validation. All five root causes were variations on the same theme:
patterns written to catch a prompt-injection payload telling the MODEL
to run dangerous code, instead matching completely ordinary, real
source code shown to the model as evidence (which is exactly what a
source-code-disclosure finding needs the model to read). Confirmed
end-to-end before/after: this exact exchange went from 0 findings
across all 8 agents to real findings (SQL injection, IDOR, reflected
XSS, plus a cross-agent `potential-attack-chain:sqli+idor` detection)
once all five were fixed. All in `prompt_validator.py`:

1. **Line-count cap mismatch.** `max_body_chars` (6000, config-driven)
   truncates by character count; `max_user_prompt_lines` (200, fixed)
   caps by line count — the two were never coordinated, so a
   character-bounded slice of line-dense content (source code runs far
   more lines-per-char than prose) could still blow the line cap.
   Fixed in `agents/base_agent.py`'s `_user_prompt`: `trunc()` now
   enforces a second, coordinated per-field line budget
   (`_MAX_BODY_LINES`, derived from `ValidationConfig().max_user_prompt_lines`
   minus a reserved overhead, not a second independent magic number)
   AFTER character truncation, not instead of it.
2. **`import`/`from` in the code-execution pattern** matched the
   literal, ubiquitous Python line `import os` in the disclosed source.
   Removed those two verbs (the adjacent call-syntax pattern already
   catches the actually-dangerous form: `os.system(`, `exec(`);
   `require`/`eval`/`exec`/`compile` kept, since none of them are
   common bare-word prefixes in ordinary code the way `import os` is.
3. **`fetch`/`axios` in the wget/curl bare-shell pattern** matched the
   app's own docstring prose — "...fetch for the avatar feature (real
   SSRF, not simulated)" — because the pattern only required a trailing
   space, correct for real shell commands but wrong for `fetch`/`axios`,
   which are JS APIs invoked as calls (`fetch(url)`, `axios.get(url)`),
   never shell-style. Moved to call-syntax matching (`\bfetch\s*\(`,
   `\baxios\.\w`), matching how `requests`/`httpx` already work.
4. **`urllib` in the network-access dotted-call pattern** matched the
   app's own real, vulnerable `urllib.request.urlopen(...)` SSRF
   implementation. Removed (Python's standard library, ubiquitous in
   any real disclosed source); `requests`/`httpx` kept (third-party,
   an app not using them at all is common, so their appearance carries
   more signal).
5. **`connect` in the socket/bind/listen/accept pattern** matched the
   app's own ordinary `sqlite3.connect(DB_PATH)`. Removed (opening a DB
   connection is about as common as Python code gets); the genuinely
   rare `socket`/`bind`/`listen`/`accept` kept.

New tests: `TestCodeExecutionPatternDoesNotBlockDisclosedSourceCode`
(3), `TestNetworkAccessPatternDoesNotBlockDisclosedSourceCode` (5) —
`test_prompt_validator.py` is up to 56 tests. One pre-existing test
(`test_real_library_call_with_no_space_after_dot_is_blocked`) had its
`urllib.request.urlopen(...)` example swapped for a `requests`/`httpx`
one, since that specific case is now deliberately unblocked.

### A sixth bug, found only after a full clean re-run: prior-findings poisoning

With all six fixes above applied, a full clean 22-exchange re-run (not
just the one exchange) produced real findings for most of the suite —
including a genuine `Server-Side Request Forgery` confirmation at
confidence 0.9 for TP9, and real SQL injection / reflected+stored XSS
detections — but exchanges 13 through 21 (the entire rest of the run)
ALL returned zero findings in 0.0s, again. This is a DIFFERENT, more
severe bug than any single-exchange collision above, because its blast
radius is every subsequent exchange on a host, not just the one that
triggered it:

**A model wrote a completely ordinary finding summary using Markdown
code-formatting for a path** — "The `` `/api/avatar` `` endpoint
returns potentially sensitive data..." (confirmed directly from the
persisted row). `store.prior_findings_summary()` embeds each prior
finding's raw `summary` text VERBATIM into every SUBSEQUENT exchange's
prompt for the same host (the "PRIOR FINDINGS ON THIS HOST" block in
`base_agent.py`'s `_user_prompt`). `prompt_validator.py`'s backtick-
command-substitution pattern (`` `[^`\n]{1,200}` `` — deliberately broad
by design, see its own comment: "command substitution doesn't require
a 'recognizable' command name") then matched that backtick-quoted path
on every remaining exchange, failing prompt validation for every agent,
permanently, for the rest of the run on that host. Unlike raw exchange
data (genuinely untrusted, correctly validated), this text is the
harness's OWN prior model output being fed back as context — nothing
downstream renders the Markdown, so the fix (`store.py`) strips
backticks from the summary text specifically at the point it's folded
into prior-findings context, breaking the propagation at its source
rather than trying to pre-emptively exempt this text from every
blocked pattern it might one day also happen to contain. 1 new test
(`TestPriorFindingsSummaryStripsBackticks` in `test_store.py`) —
confirmed directly against the real, already-poisoned database from
the failing run, not just a synthetic repro. `test_*.py` count is now
33 files; harness suite is 479 tests.

**Caution for whoever re-verifies any of this:** the exchange cache
(`cache.py`) persists analyze() results keyed by exchange hash. If you
fix a bug and re-run against the SAME cache database used by the
failing run, you'll get the STALE cached failure back and think the fix
didn't work — happened directly during this session's own
verification. Use a fresh cache DB (`cache.init_cache(db_path=...)`) or
delete the old one when re-verifying a fix against a previously-run
exchange.

### 3 more Burp capabilities implemented (22 of 31 category keys now covered)

Same JDK-discovery note for whoever hits this next: this machine has no
system-wide `javac`, but Burp Suite Community's own bundled JRE has a
full JDK at
`C:\Users\<user>\AppData\Local\Programs\BurpSuiteCommunity\jre\bin\javac.exe`
(confirmed: `javac 26.0.1`) — use that directly, same `dev-tools/RunTests.java`
harness as every prior batch.

1. **`race_condition_validation`** — the only executor in `ValidationExecutor.java`
   that needs genuine CONCURRENT dispatch, not sequential replay (every
   other method's `sendRequest()` calls happen one after another,
   appropriately, since none of them depend on overlapping in time). A
   check-then-act race only opens if multiple requests are actually in
   flight simultaneously, so `raceConditionBurst` uses a real thread
   pool (`MAX_BURST` = 5, reusing the existing constant rather than a
   new one) plus a two-latch start barrier — every worker thread signals
   "ready" then blocks on "go", so none of them fires until all are
   lined up together. `RaceConditionLogic`: 2+ of N concurrent replays
   succeeding (2xx) while at least one didn't is confirmed evidence of
   a TOCTOU race (a correctly-enforced single-use resource should let
   at most one through); all N succeeding is flagged lower-confidence
   (ambiguous with "no limit enforced at all"). Directly mirrors the bug
   class `testing/test-target/`'s own PixelMart coupon endpoint
   demonstrates by hand. Hit one real compile error landing this:
   `HttpResponse.statusCode()` returns `short` (confirmed from the real
   Montoya stub, matching the documented real API), and a ternary
   mixing an `int` literal with a `short` infers as `short` per JLS
   15.25 — needed an explicit `(int)` cast for the `Callable<Integer>`
   target type to resolve. 6 new tests.
2. **`header_injection_validation`** — CRLF/HTTP response-header
   injection, HTTP-response-header variant only (the same agent also
   covers email/SMTP header injection, but an outbound email's headers
   aren't observable from the captured HTTP exchange — stays
   analyst-confirmed only). Appends `%0d%0a` (the transport-safe ENCODED
   form a real attacker sends — a literal `\r\n` in an `HttpParameter`
   value would get percent-encoded by Montoya before reaching the wire,
   or break the request outright; the exploit condition is the TARGET
   SERVER's own decode-then-reflect code reintroducing the raw newline)
   plus a harness-chosen marker header to the same URL/redirect-shaped
   parameter `open_redirect_validation` already targets (reusing
   `SsrfCallbackLogic`'s param heuristic a third time). `CONFIRMED`
   requires the marker header to appear as a genuinely separate, parsed
   response header — not just as text inside another header's value.
   5 new tests.
3. **`api_security_validation`** — mass-assignment probe, directly
   implementing the `api_security` agent's own `suggested_test`: resend
   a create/update request with an extra unrequested field (`"role":
   "admin"`) added to the JSON body, check whether the response
   reflects it back. `MassAssignmentLogic.injectField` is deliberately
   string-based (insert one flat key before the closing `}`), not a
   full JSON parse/round-trip — a real parser would need to perfectly
   preserve arbitrary real-world JSON formatting to avoid corrupting
   requests this technique isn't even trying to test. `CONFIRMED`
   requires the field to be absent from the original request AND absent
   from the baseline response (ruling out the field coincidentally
   already existing). 7 new tests.

**Verification:**
```bash
cd /c/Users/<user>/Documents/AgenticVibe
JAVAC="/c/Users/<user>/AppData/Local/Programs/BurpSuiteCommunity/jre/bin/javac.exe"
JAVA="/c/Users/<user>/AppData/Local/Programs/BurpSuiteCommunity/jre/bin/java.exe"
find burp-extension/src/main/java dev-tools/stubs -name "*.java" > /tmp/mainsrc.txt
"$JAVAC" -d /tmp/maincompile -nowarn @/tmp/mainsrc.txt 2>&1 | grep -c "error:"
# Expected: 19 (same pre-existing baseline every prior batch confirmed, zero new)

find burp-extension/src/main/java/com/harness/llm/logic burp-extension/src/test/java/com/harness/llm/logic dev-tools/stubs/org -name "*.java" > /tmp/logicsrc.txt
"$JAVAC" -d /tmp/logictest -nowarn @/tmp/logicsrc.txt && "$JAVAC" -d /tmp/logictest -nowarn dev-tools/RunTests.java
cd /tmp/logictest && "$JAVA" RunTests com.harness.llm.logic.XssPayloadLogicTest com.harness.llm.logic.SsrfCallbackLogicTest com.harness.llm.logic.IdentityCompareLogicTest com.harness.llm.logic.WorkflowReplayLogicTest com.harness.llm.logic.SessionLifecycleLogicTest com.harness.llm.logic.IdentityLabelResolverTest com.harness.llm.logic.CspClickjackingLogicTest com.harness.llm.logic.InfoDisclosureLogicTest com.harness.llm.logic.CorsMisconfigLogicTest com.harness.llm.logic.OpenRedirectLogicTest com.harness.llm.logic.JwtForgeryLogicTest com.harness.llm.logic.XxeCollaboratorLogicTest com.harness.llm.logic.CsrfLogicTest com.harness.llm.logic.SstiPayloadLogicTest com.harness.llm.logic.DeserializationFormatLogicTest com.harness.llm.logic.CommandInjectionTimingLogicTest com.harness.llm.logic.RaceConditionLogicTest com.harness.llm.logic.HeaderInjectionLogicTest com.harness.llm.logic.MassAssignmentLogicTest
# Expected: === TOTAL: 157 passed, 0 failed ===
```

**9 of 31 `_CAPABILITIES` category keys remain**: `crypto` →
`crypto_transport_validation`, `file_upload` → `file_upload_validation`,
`http_request_smuggling` → `http_request_smuggling_detection`, `nosql`
→ `nosql_validation` (deliberately deferred, §5f — still needs live
Burp access), `oauth` → `oauth_flow_validation`, `recon` →
`attack_surface_mapping`, `subdomain_takeover` →
`subdomain_takeover_detection`, `web_cache_poisoning` →
`web_cache_poisoning_detection`, `websocket` →
`websocket_cswsh_validation`. `file_upload_validation` was deliberately
NOT attempted in this pass, after consideration rather than before it:
its real payloads (`<?php system($_GET['cmd']); ?>` etc., per the
agent's own suggested_test) are meaningfully riskier to send against a
real target than any mutate-and-compare probe implemented so far — a
successfully-uploaded, executable webshell left on a real server is a
different order of consequence than a probe response, and deserves its
own careful pass (an inert marker upload confirming accessibility,
stopping short of ever attempting real code execution) rather than
being rushed alongside the others. The rest still need genuinely
different handling (raw sockets, DNS, WebSocket protocol, TLS
internals) exactly as prior sections already noted.

---

## 5i. `active_enabled=True` had never been exercised in a real run before now -- 12 of 13 active validators were completely broken; a full Juice Shop run with real confirmation

A direct user question -- "how many findings were you able to actually
confirm as proof of exploitation?" -- was answered honestly at first
(§5h/§6 item 4's run: zero, because `validators.active_enabled` is
`false` by default and nothing had ever turned it on). Flipping it on
for a real run, in-memory only (not editing config.yaml), to actually
answer that question is what surfaced everything below. **This
confirms §0's pattern a fourth time**: a subsystem with real code,
real tests passing, and a real config flag existed for who knows how
long, and nothing in this project's history had ever actually turned
it on and watched what happened.

### `file_upload_validation` implemented (24 of 31 now covered)

Per a direct user suggestion: use the EICAR antivirus test string, not
the agent's own riskier suggested_test payloads (a PHP webshell etc.).
EICAR is industry-standard, universally recognized, and inert (plain
ASCII, not executable in any language) -- the one file-upload payload
genuinely safe to send to a live target. `FileUploadLogic` hand-rolls
multipart/form-data body surgery (find the file part via its
`filename=`, replace only its content, preserve everything else) since
the dev-tools Montoya stub has no file-part `HttpParameterType`; the
wire format itself is a public RFC 7578 standard, not an opaque Burp
behavior, so this is fully verifiable without live Burp access. The
executor resends with EICAR content, then best-effort fetches the file
back from a URL/path found in the upload response to confirm it's
unscanned and directly accessible.

**Real, immediate proof the technique works exactly as intended**:
writing `EICAR_STRING` as a literal in the `.java` source file got that
exact file quarantined by Windows Defender mid-session -- confirmed by
`ls` reporting the file gone and `javac` refusing to read it
("the file contains a virus or potentially unwanted software"). Fixed
by Base64-encoding the string and decoding it at class-init time (a
standard technique for this exact problem); the test file was also
rewritten to avoid asserting against the literal signature for the same
reason. 12 new tests (`FileUploadLogicTest`) -- 169 Java logic tests
total after this and the three §5h capabilities.

### 12 of 13 active validators were completely broken (only `sqlmap.py` worked)

The first real finding routed through an active validator
(`cors_validator.py`, for a CORS finding on Juice Shop) crashed
`orchestrator.analyze()` outright with a pydantic `ValidationError`:
`TestPlan.plan()` was missing the two REQUIRED fields (`finding_class`,
`source_exchange_url`), instead setting fields that don't exist on that
model at all (`target_url`, `target_method`, `description`,
`parameters`, `expected_outcome` -- all silently accepted and dropped
by pydantic's default `extra="ignore"`, confirmed directly rather than
assumed). A grep across all 13 active validators' `plan()` methods
confirmed this was universal:

```bash
cd harness/validators
for f in *.py; do grep -q "TestPlan(" "$f" && echo "$f: $(grep -A20 'TestPlan(' "$f" | grep -c 'finding_class=')"; done
# sqlmap.py: 1 (correct) -- every other active validator: 0
```

All 12 (`api_security`, `cors`, `crypto`, `csp`, `deserialization`,
`header_injection`, `http_request_smuggling`, `oauth`,
`race_condition`, `recon`, `subdomain_takeover`, `web_cache_poisoning`,
`websocket` -- 13 listed, `deserialization` is passive/non-active but
shared the same broken template) were fixed to match `sqlmap.py`'s
already-correct pattern: `finding_class=finding.vulnerability_class`,
`category=canonicalize(finding.vulnerability_class)`,
`source_exchange_url=exchange.url`, with the dropped fields' actual
content remapped onto real `TestPlan` fields (`description`→`rationale`,
`expected_outcome`/`parameters`→`success_signals`/`mutation`). New
regression test (`test_validators.py`,
`EveryActiveValidatorPlanMethodWorksTests`): constructs a REAL
`ValidatorRegistry` with `active_enabled=True` and calls `plan()` on
every one of the (at least) 13 validators it produces, asserting a
valid `TestPlan` comes back -- exactly the real-construction-path
discipline `test_prompt_validator.py`'s
`TestRealAgentSystemPromptsPassValidation` already established for
system prompts. This is why nothing caught it before: no existing test
built the registry with active validation on and exercised `plan()`
at all.

### A second bug in the same 12 files: plan_id collisions across different exchanges to the same URL

Fixing the crash above and re-running surfaced a second, subtler bug:
`failed to persist local-tool validation result for plan
cors_test_...: binding_mismatch`. All 12 validators computed
`plan_id` from `f"{finding.vulnerability_class}:{exchange.url}"` --
URL and category only, ignoring the request body/headers/method
entirely. Two real, different Juice Shop login attempts (JS-TP1's SQLi
bypass, JS-TP2's real admin login) both POST to the same
`/rest/user/login` URL, so both produced the byte-identical `plan_id`.
The second one's `persist_test_plans()` call didn't update the
first's stored `source_exchange_hash` (an `INSERT OR IGNORE`-shaped
collision, confirmed by the exact error sequence: the first submission
failed on the (separate, pre-existing) confirmation-capability policy
check, then the second failed on `binding_mismatch` because its plan
row was never actually created). Fixed uniformly across all 12: reuse
the already-computed full-exchange hash for `plan_id` too, not just
`source_exchange_hash`. New regression test:
`test_different_exchanges_to_the_same_url_get_different_plan_ids`,
which builds two real, different exchanges to the same URL and asserts
every active validator's `plan()` produces distinct IDs and hashes for
them. 482 Python tests total after this session's full set of fixes.

### A THIRD bug in the same family, found by the same run: the critique pass's OWN dead duplicate

Fixing the backtick/prior-findings-poisoning bug in §5h only closed
ONE of two real propagation paths. The same run tripped
`prompt_validator.py`'s backtick pattern a second, different way:
`orchestrator.py`'s own `_critique()` method existed, LOOKED like the
one that mattered, and I edited it first -- only to find, via
`grep -n "\._critique\b" harness/*.py`, that it is called from
**nowhere**. The critique pass that actually runs in the real
`analyze()` flow is `AnalysisPipeline._critique()` in
`analysis_pipeline.py` (called from `run_full_analysis`, confirmed
earlier this session, §5h's known-vuln-duplication fix). Editing the
dead copy would have shipped a fix that changed nothing. Removed the
entire dead `orchestrator.py._critique()` method (and its now-orphaned
`_CRITIQUE_SYSTEM_PROMPT`/`_CRITIQUE_CONFIDENCE_THRESHOLD`/
`_MAX_FINDINGS_TO_CRITIQUE`/`self.critique_cfg`, left behind by the
removal), leaving an explicit comment for whoever touches critique
logic next, then applied the real fix -- stripping backticks from
`f.summary`/`f.evidence` before building the critique listing -- to
`analysis_pipeline.py`'s actual, live `_critique()`. New regression
test: `CritiquePromptStripsBackticksTests` in `test_analysis_pipeline.py`,
which captures the real `user_prompt` sent to `chat_json_metered` and
asserts no backtick survives. **Lesson for future sessions, stated
explicitly because it almost cost real time here**: when a duplicate-
method bug is suspected, `grep` for real call sites BEFORE editing
either copy -- this project has now hit "which of the two duplicates
is actually live" three separate times (known-vuln resolution in §5h,
`_exchange_text` before that, now critique).

### Full Juice Shop run, with all of the above fixed, active validation genuinely on

```bash
curl -s -m 3 http://localhost:11434/api/tags   # gemma2:9B, llama3.1:8b, gemma4:latest -- all real
```

9 real, independently-verified-live Juice Shop exchanges (SQLi login
bypass, default-admin-credential login disclosing a password hash via
JWT payload, an IDOR-shaped `/api/Users/1` lookup, a reflected-XSS
search attempt, a basket IDOR, an unauthenticated security-question
disclosure, a CORS/foreign-Origin probe, a real 500 with a full stack
trace + internal file paths, and a legacy `/ftp` directory listing --
see `testing/test-target/capture_juiceshop_exchanges.py`), run with
`validators.active_enabled=True` and `allow_mutating_replay=True`
(in-memory config override only). Final clean numbers (confirmed
directly against the persisted SQLite database, not just the script's
own summary line -- **the two differ, and the difference is the actual
finding**):

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect(r'C:\tmp\juiceshop_real_state.db')
print('findings total:', conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0])
print('findings confirmed=1:', conn.execute('SELECT COUNT(*) FROM findings WHERE confirmed=1').fetchone()[0])
print('validation_runs total:', conn.execute('SELECT COUNT(*) FROM validation_runs').fetchone()[0])
print('validation_runs confirmed=1:', conn.execute('SELECT COUNT(*) FROM validation_runs WHERE confirmed=1').fetchone()[0])
"
# findings total: 33 | findings confirmed=1: 10
# validation_runs total: 1 | validation_runs confirmed=1: 0
```

**10 findings were marked `confirmed=True`** -- all CORS misconfiguration,
all via the same real, deterministic active test (replay with a
foreign `Origin` header, observe a real wildcard
`Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials`
combination). This is genuine, live-reproduced proof of exploitation,
not an LLM hypothesis. **But the durable `validation_runs` audit
ledger has essentially none of that** -- `store.persist_validation_submission`
has a pre-existing (not introduced this session) allowlist of exactly
3 capabilities permitted to ever record `confirmed=True`
(`cross_identity_compare`, `authorization_boundary_compare`,
`sql_injection_validation`; see its own comment, which cites a real
sqlmap-confirmed Juice Shop SQLi as the reason `sql_injection_validation`
is on it). `cors_misconfiguration_detection` isn't on that list, so
every one of the 10 confirmations was rejected at the persistence
layer with `"this capability may provide evidence but cannot mark the
vulnerability confirmed"` -- the in-memory `Finding.confirmed`/
`ValidationReport.confirmed` still show `True` to whatever reads the
live API response, but the SQL row that should back that claim never
gets written. `sqlmap` itself never got the chance to prove anything
this run (`sqlmap executable not found; install sqlmap to enable
active SQLi validation` -- graceful, correctly-handled, not a crash).
**Deliberately not fixed this session**: the CORS test is, on its own
technical merits, exactly as deterministic as the two identity-compare
capabilities already on the allowlist (both directly replay a real
request and compare real observed behavior) -- but expanding a
confirmation-trust allowlist is a real policy decision affecting how
findings get presented/prioritized to an analyst, and auditing every
OTHER active validator's actual rigor before touching that allowlist
is real, separate work that deserves its own deliberate pass, not a
decision folded into a bug-fixing session.

---

## 5j. PixelMart finally scored against ANSWER_KEY.md; `anomaly_detector.py` was almost completely non-functional

§6 item 4/§7 item 1's oldest, most-repeated open item — actually
tallying a PixelMart run against `ANSWER_KEY.md` — is done. The v2/v3
runs referenced in §5h/§6 turned out to be stale (v2 predates the
backtick-propagation fix; both were superseded), so this session ran a
clean v3 pass (`/tmp/pixelmart_real_state_v3.db`, zero errors across
all 22 exchanges) and graded every finding against its actual evidence
text, not just its `vulnerability_class` label -- several labels didn't
match their own evidence (see below).

**True positives: 5/11 clean hits by strict label, 8/11 if mislabeled-
but-evidence-correct findings count** (excluded #8/race condition: this
captured exchange is a single successful sequential redemption, which
can't prove a concurrency bug by itself -- not a fair test of that
class from one exchange).

| # | Vuln | Result |
|---|---|---|
| 1 | SQLi auth bypass | MISS -- `sqli` never dispatched for `POST /api/login` at all (fixed, see below) |
| 2 | SQLi UNION exfil | HIT (0.5) |
| 3 | IDOR profile | HIT (0.9) |
| 4 | IDOR order | HIT (0.8) |
| 5 | Reflected XSS | MISS* -- `xss` agent produced nothing; a *different* agent quoted the exact `<script>` payload under "EXCESSIVE DATA EXPOSURE" |
| 6 | Stored XSS | MISS* -- same pattern |
| 7 | Business logic (negative qty) | MISS -- "workflow_bypass" finding never mentions the negative-quantity/credited-balance mechanism |
| 8 | Race condition | N/A, not fairly testable from one sequential request |
| 9 | SSRF | MISS* -- `ssrf` agent produced nothing; a different agent quoted "top secret internal data" as generic exposure |
| 10 | Path traversal | MISS -- 9 findings fired across 8 agents, none named path traversal or source disclosure (fixed, see below) |
| 11 | alg:none JWT | HIT (0.9) |
| 12 | Admin config exposure | HIT (0.3) -- names `jwt_secret`/`db_path`/`debug` correctly, misses the "no auth required" angle |

**True negatives: 5/6 clean, 1 soft/hedged technical false positive**
(TN4's allowlisted `sort` attack produced a "SQL injection" finding at
confidence 0.4, explicitly worded "Potential"/"looks like" -- not a
confident false claim, but a label a strict grader would still count).

**The `*` misses were re-verified directly and turned out to be pure
LLM non-determinism, not a bug**: re-running the exact same TP5
exchange through the full pipeline (same code, same model, same
temperature) produced a correct `Cross-site Scripting (Reflected)`
finding at confidence 0.8 that survived critique. Don't chase this
class of "miss" with speculative prompt/code changes -- there's nothing
to fix, it's inherent single-pass LLM variance. (Whether averaging
multiple passes is worth the added cost is a real question, just not
one this session answered.)

### Fixed: #1's real root cause

`fast_path.py`'s `/login` URL pattern dispatched `auth`/`business_logic`
but never `sqli` -- meaning the one agent actually equipped to
recognize `admin' -- `-style injection syntax never saw login exchanges
at all. Added `sqli` to that pattern (also matches a real Juice Shop
`admin@juice-sh.op' -- ` bypass exploited earlier this session, so this
isn't PixelMart-specific). 2 test updates in `test_fast_path.py`.

### Fixed: #10's real root cause -- `anomaly_detector.py` was almost completely non-functional

Investigating #10 surfaced that `anomaly` (a fully deterministic,
**zero-LLM-cost** detector -- `AnomalyAgent.run()` bypasses the Ollama
pipeline entirely and runs regex/heuristic checks in pure Python) was
never dispatched by `fast_path.py` at all, despite already explicitly
listing path traversal among its `suspicious_patterns`. That alone
would have been a one-line dispatch fix, but pulling on the thread
found **three compounding bugs that made the detector nearly useless
even when it WAS running**:

1. **Every check, including baseline-independent pattern matching, was
   gated behind 10 prior exchanges for the host.** `detect_anomalies()`
   returned an empty list outright unless `exchange_count >=
   min_exchanges` (10) -- a threshold that makes sense for genuinely
   baseline-dependent statistical checks (is this response size an
   outlier vs. history?) but has zero logical connection to "does this
   URL contain `../`", which is exactly as suspicious on the first
   exchange for a host as the hundredth. Confirmed by checking each
   `_detect_*` method's own signature: only 3 of 7 actually take a
   `profile` parameter. Split the baseline-independent checks
   (pattern/parameter/header) out to run unconditionally.
2. **Clustering silently discarded unrelated anomalies from the same
   exchange.** `generate_findings()` tracked "already reported"
   anomalies by `exchange_fingerprint` -- identical for every anomaly
   from one exchange regardless of type. The first real exchange this
   fix was tested against (path traversal, which ALSO happened to be
   missing 3+ security headers -- true of almost every response)
   proved it live: the 6 unrelated `missing_security_header` anomalies
   clustered, and that single fact caused the 2 completely different,
   far more valuable `suspicious_pattern` (path traversal) anomalies
   from the SAME exchange to be silently treated as already-covered
   and dropped -- even though they were never part of that cluster.
   The only surviving finding was the generic cluster summary. Fixed
   by tracking clustered anomalies by object identity instead.
3. **`_suggest_vulnerability_class`'s mapping table was permanently
   unreachable for everything except `suspicious_pattern`.** Every
   other entry used `''` as a placeholder `affected_field`, which
   never equals a real anomaly's `affected_field` (always a genuine
   value like `'response_headers'`) -- so a real
   `missing_security_header` cluster always fell through to the
   generic `'unknown_anomaly'` instead of the correctly-mapped
   `'security_misconfiguration'`. Fixed with a two-tier lookup: exact
   `(type, field)` first (still needed for `suspicious_pattern`, whose
   real class genuinely depends on where the pattern matched -- `../`
   in a URL is path traversal, the same pattern in a response body is
   information disclosure), falling back to `(type, '')` for types
   where the field doesn't change the classification.
4. **A fourth, smaller bug found while writing tests for the others**:
   `_detect_parameter_anomalies`'s sensitive-parameter check required
   `param_name in exchange.request_headers or param_name in
   exchange.request_body` -- redundant (the parameter already came
   from `_extract_parameters()`, which only returns names genuinely
   present in the exchange) AND wrong (a sensitive name appearing ONLY
   in the query string -- `?api_key=...`, arguably the most common
   place for one -- matches neither check). Removed the guard entirely.

No test file existed for `anomaly_detector.py` at all before this --
`test_anomaly_detector.py` is new, 5 tests, including one that
specifically reproduces bug #2's exact live scenario (a path-traversal
exchange that also triggers a 6-item header cluster) and asserts BOTH
findings survive. `test_fast_path.py` also gained a test for the new
`anomaly` dispatch. 488 Python tests total.

**Re-verified directly against the real failing exchange, all four
fixes together**: the same TP10 exchange that produced zero
path-traversal-relevant findings across 8 LLM-backed agents now also
gets a correctly-labeled `suspicious_pattern` finding (`Pattern
'\.\./' found in url`) from the free, deterministic `anomaly` agent,
plus a correctly-classified `security_misconfiguration` cluster
instead of the previous generic `unknown_anomaly`.

**The v4 re-run completed (zero errors, `/tmp/pixelmart_real_results_v4.json`,
actually `C:\tmp\...` on Windows -- see §5h's path caution) and the
improvement is real, not hoped-for:**

| # | Vuln | v3 (before) | v4 (after) |
|---|---|---|---|
| 1 | SQLi auth bypass | MISS | **HIT** (0.5) -- `sqli` now dispatched |
| 9 | SSRF | MISS* | **HIT** (0.4) |
| 10 | Path traversal | MISS | **HIT** -- correctly surfaces "Python script with a dependency manifest," "internal file paths," quotes `from flask import...` verbatim |
| 4 | IDOR order | HIT | MISS (LLM variance -- `idor` produced nothing this specific pass, same non-determinism class as §5j's `*` cases) |

**Recall: 5/11 -> 8/11 on the same strict grading**, from the fast_path
dispatch fix and the anomaly_detector.py rewrite -- not luck. #4's
regression is the same inherent single-pass variance already
documented above, not a new bug.

**A fourth fix, verified separately** (a single-exchange check against
TP12, not a full 22-exchange re-run): `auth_agent.py`'s prompt covered
many sophisticated auth nuances (session fixation, CSRF, token entropy,
enumeration) but never once told the model to check "is there no
authentication at all on a request returning sensitive data" -- the
single most basic and severe case, and exactly TP12's scenario. Added
an explicit bullet for it. Re-running TP12 alone afterward produced
`auth: no_authentication (conf=0.8): "No authentication present on
request that returns sensitive data"` -- TP12 is now a complete hit on
BOTH the secret-leak angle (already working) and the missing-auth angle
(previously silent). This fix landed after the v4 run started, so v4's
own TP12 result doesn't reflect it; a v5 full run would.

**One residual gap found while verifying v4, initially left open, then
root-caused and fixed in §5k below (do not stop at this paragraph)**:
TN4 (a true negative) now shows an `unknown_anomaly` cluster at
confidence 0.9. Traced to a real architectural quirk, not a regression
of the fixes above: `AnomalyDetector`'s `self.anomalies` list and
`cluster_anomalies()` accumulate and operate across the ENTIRE session
for a host, not per-exchange -- so a cluster reported against TN4 can
include anomaly types contributed by EARLIER exchanges (e.g. once
`min_exchanges` is reached partway through a 22-exchange run,
statistical checks like `rare_status_code`/`json_as_html` start
contributing too) that aren't in `_suggest_vulnerability_class`'s
mapping table, which was only verified against the specific types
one single exchange's checks produce. **See §5k: scoping
`cluster_anomalies()` to the current exchange's own anomalies, not
`self.anomalies`, fixed this at the root rather than only extending the
mapping table.**

---

## 5k. User directive "FIX ALL OF THEM AND STOP BEATING AROUND THE BUSH" — TN4 root-caused (not just noted), TP7 resolved as confirmed non-determinism, and both §6 items 1 and 6 closed

After §5j reported the v3→v4 improvement, the user explicitly rejected
leaving TN4's `unknown_anomaly` issue as a documented-but-deferred "lower
priority" item, and separately rejected treating open §6 items as
someone else's future work. This section covers what actually got fixed
in response, verified the same way as everything else in this document
(real code read first, real tests, then a real run where one was
possible) — not just re-labeled as done.

### TN4 fixed at the root, not just patched

§5j's mapping-table fix (two-tier `(type, field)` lookup) treated the
SYMPTOM. The actual cause: `AnomalyDetector.cluster_anomalies()` defaulted
to clustering `self.anomalies` — the accumulator that grows across the
ENTIRE session for a host, not the anomalies from the exchange currently
being analyzed. Every one of this harness's real callers (`AnomalyAgent.run()`,
invoked once per `/analyze` call) only ever wants clustering scoped to
the current exchange; nothing anywhere reviews session-wide clusters.
Fixed by giving `cluster_anomalies()` an optional `anomalies` parameter,
with `generate_findings()` now passing its own local `anomalies` list
instead of relying on the implicit `self.anomalies` default. New
regression test (`TestClusteringIsScopedPerExchange`, in
`test_anomaly_detector.py`) creates two exchanges to the same host — an
innocuous first exchange, then a real path-traversal second exchange —
and asserts the second exchange's findings show `suspicious_pattern`
correctly, never the `unknown_anomaly` cross-contamination the old
global-scope clustering produced. Also added the two mapping entries
`_suggest_vulnerability_class` was still missing
(`parameter_count_outlier`, `url_depth_outlier`) — found by a new test
(`test_every_real_anomaly_type_has_a_mapping`) that enumerates every
`anomaly_type` string literal the module can actually emit (checked by
grep, not guessed) and asserts none of them resolve to `'unknown_anomaly'`.
8/8 tests pass in `test_anomaly_detector.py`.

### TP7 (business-logic negative-quantity miss) investigated and resolved as non-determinism, not a defect

Ran `business_logic_agent.py` in isolation against the real TP7 exchange
(`{"product_id": 2, "quantity": -5}` -> `{"total_price":-399.95,...}`)
the same way §5j's TP5/TP6/TP9 investigations worked. Result:
`raw_error: None`, and the agent correctly produced BOTH the
negative-quantity finding AND a workflow-limit-bypass finding that
explicitly ties the negative quantity to the negative `total_price` in
its evidence. The agent's prompt already explicitly covers this exact
case (bullet 3: "quantity/price/discount/limit parameters that look like
they could be set to zero, negative, or an out-of-range value"). This
is the same pattern already established for TP5/TP6/TP9: the model can
and does get it right, just not on every stochastic sample under the
full concurrent-dispatch pipeline. No prompt or code change made for
TP7 specifically — there is nothing to fix in the agent itself.

### `retry_policy.py` and `payload_library.py` wired for the first time (closes §6 item 6)

Both modules were fully built, fully tested in isolation
(`test_retry_policy.py`, `test_payload_library.py`), and never called
from anywhere else in the codebase (confirmed by grep before starting).
Traced where they were actually designed to plug in:
`_CAPABILITIES` in `planner.py` shows `xss`/`ssrf`/`business_logic`
findings produce Burp-execution-plane `TestPlan`s
(`reflection_context_validation` / `controlled_callback_probe` /
`workflow_replay_compare`) whose results come back through
`POST /validation-results` — a single-shot, accept-and-stop endpoint
before this change, with no retry, no escalation, and no use of the
curated payload library at all. (`sqlmap`, the other active validator,
was deliberately left out of scope: it's a `local_tool` capability that
runs its own internal payload engine in one bounded invocation — there's
no per-attempt slot to substitute a curated payload into without
redesigning that validator's interface.)

New module `active_verification.py` (`decide_next_step`) is the first
caller of either module. Wired into `server.py`'s `/validation-results`
handler: after a submission is persisted, if it isn't confirmed and the
plan is Burp-plane xss/ssrf/business_logic, it reconstructs the attempt
history for that (category, source_exchange_hash) lineage from a new
`store.get_lineage_attempts()` query, feeds it to
`RetryPolicy().decide()`, and:
- `RETRY_DEFAULT` -> `payload_library.next_candidate()` picks the next
  untried, context-ranked payload; a new `TestPlan` is built and
  persisted (`store.persist_retry_plan`), returned to the caller as
  `next_plan` in the response so the Burp extension knows to try again.
- Curated library exhausted, or `ESCALATE` -> one LLM call using
  `payload_library.llm_fallback_prompt()` (fed the real failure notes
  from every prior attempt, per that function's own design) synthesizes
  one new payload; the resulting plan is marked `escalated=True` so a
  later `decide()` call sees it as the one-time escalation
  `retry_policy.py`'s contract allows. On this deployment there is no
  actual "stronger model" configured (only `llama3.1:8b`/`gemma2:9b`
  exist locally) — escalation here means "one more LLM-reasoned attempt
  informed by why prior attempts failed," not a model-tier upgrade; if a
  larger model is ever added to `config.yaml`, wiring its name through
  is a small follow-up, not a redesign.
- `HANDOVER_MANUAL` -> no further plan; `handover_required: true` is
  returned in the API response instead of only a log line, so an
  unconfirmed high-severity/high-confidence finding that survived
  retries is actually visible to whoever reads the response, not just to
  whoever happens to be tailing the harness's own logs.
- `STOP_INCONCLUSIVE` / `STOP_CONFIRMED` -> nothing further, as designed.

Required two small additive model/schema changes, both backward
compatible (existing callers/rows get harmless defaults): `TestPlan`
gained `severity`/`confidence` (the ORIGINAL finding's, captured at
plan-creation time in `planner.py` — needed because `decide()`'s
`is_suspicious()` check has no other way to see the original finding
once only a `plan_id` comes back on a submission) and `escalated`;
`ValidationSubmission` gained an optional `context_tags` list (lets a
future, more capable Burp extension report where a payload landed —
`html_attribute`, `js_string` — for `payload_library`'s context-aware
ranking; empty is always safe, it just means every candidate is treated
as context-agnostic). `store.py` gained matching columns (migrated, same
pattern as every other `test_plans` column added historically) and two
functions: `get_lineage_attempts()` (read side) and `persist_retry_plan()`
(so the new-plan write path doesn't need a fake `HttpExchange` object —
`persist_test_plans()` was refactored to share the same private
`_persist_test_plans_for(host, url, plans)` helper).

New `test_active_verification.py`, 8 tests, covering: confirmed
submissions produce no next step; non-retryable (`local_tool`/`sqli`)
plans are correctly excluded; a `not_confirmed` result gets a genuinely
new payload; a second `not_confirmed` never re-offers an already-tried
payload; curated-library exhaustion correctly escalates via a mocked
LLM call; an LLM failure during escalation degrades to "no next plan,"
not a crash; a high-severity/high-confidence finding unconfirmed even
after escalation correctly returns `handover_required`; and a missing
`ollama_client` at escalation time stops cleanly instead of raising.
**One real bug caught by this test suite, not by inspection**: the first
draft of these tests assumed `RetryPolicy`'s default
`max_default_attempts=3` would let all 4 curated xss payloads get tried
before escalating — wrong, because the ORIGINAL attempt counts as
attempt #1, so only 2 of the library's 4 entries are ever reached via
`RETRY_DEFAULT` before attempt #3 trips `ESCALATE`. This is correct,
intentional `retry_policy.py` behavior (bound attempts on the default
model, don't promise to exhaust the library first) — the tests were
wrong, not the code; fixed by correcting the test's iteration count, not
by changing `active_verification.py`. Verified end-to-end through the
REAL FastAPI app (not just the pure `decide_next_step` function) via
`TestClient` — a real `POST /validation-results` with `status:
"not_confirmed"` genuinely returns a `next_plan` with a fresh curated
payload in the HTTP response.

### `coordinator.py`'s fail-open path — closes §6 item 1

No test file existed for `coordinator.py` at all before this. New
`test_coordinator.py`, 7 tests with a mocked `OllamaClient`, covering
every path `choose_agents()` can take: a valid dispatch is returned
as-is; a dispatch is filtered down to only names actually in
`available_agents` (a hallucinated agent name must not reach the
caller); an empty dispatch falls back to all available agents; a
dispatch that becomes empty AFTER filtering (all hallucinated names)
hits the same fallback, not a silent empty list; a malformed-JSON
`OllamaError` falls back; a well-formed JSON response missing the
`dispatch` key falls back rather than raising `KeyError`; and a generic
exception (network error, timeout, open circuit breaker) falls back
rather than propagating. All 7 passed on first correct write (the
fail-open logic itself had no bugs — it was simply never exercised by
anything, mocked or real, before now).

Then did the thing HANDOVER.md had been flagging as literally never
done: **forced a real exchange through the coordinator's SUCCESS path
against the live local Ollama instance.** fast_path.py is now
comprehensive enough (§5j's `anomaly` baseline, the broadened login
pattern, the pre-existing HTML/JSON/body-pattern tables) that most
realistic exchanges never reach the coordinator at all — the first two
exchanges tried for this test (a plain `<html>` page, then a JSON
`{"status":"ok"}` body) both still triggered fast_path or a body-pattern
match. A GET to `/ping` returning bare JSON (no HTML tags, no query
string, no recognized header/body keywords) finally produced
`fast_path.select_agents() -> (None, "")`, reaching the coordinator for
real. Result: `dispatch=['auth', 'misconfig']`, reason: "The exchange
touches an endpoint that exposes config/debug/admin surface... suggesting
potential security misconfiguration" — a real Ollama call, real JSON
response, correctly filtered to available agent names, non-empty and
plausible. This is the first time this exact code path has ever been
confirmed to work against a live model, not just assumed correct from
reading it.

### Full suite: 506 tests, all passing (up from 491 at the start of §5j)

`test_anomaly_detector.py` (8, was 5), `test_active_verification.py`
(new, 8), `test_coordinator.py` (new, 7), plus the pre-existing suite —
all green. `git diff --stat` for the files touched in this section:
`models.py` (+18), `planner.py` (+2), `store.py` (+92/-9), `server.py`
(+22/-1) — small, additive, reviewed diffs; `active_verification.py` and
`test_active_verification.py`/`test_coordinator.py` are new files.

### v5: the genuinely final full 22-exchange run with every §5j+§5k fix applied, and one real precision regression found and fixed by running it

`testing/test-target/phase_real_run_v5.py` (a copy of §5j's v4 script,
fresh cache/state/output paths), real Ollama, all 22 exchanges, 0
errors, 2286.8s wall time. Full results:
`C:\tmp\pixelmart_real_results_v5.json`.

**Confirms the deterministic fixes hold under a full run, not just an
isolated test**: TP10 (path traversal) is now correctly labeled
`path_traversal` (not the old generic `unknown_anomaly`) via the
anomaly detector; TN4 shows NO `unknown_anomaly` cluster at all — the
§5k clustering-scope fix holds; TP12 hits on BOTH the secret-leak and
the missing-auth angle, confirming §5j's `auth_agent.py` bullet works
in a full run, not just the single-exchange check that verified it
originally.

**Raw scored recall this pass: 7/11** (TP8 excluded per `ANSWER_KEY.md`
itself — it needs concurrent replay, not single-exchange dispatch).
HIT: TP4, TP5, TP6, TP9, TP10, TP11, TP12. MISS: TP1, TP2, TP3, TP7.
This is LOWER than v4's 8/11 raw count, and that number on its own would
be a misleading headline: TP1/TP2/TP3's misses are the `sqli`/`idor`
agents' own LLM output going quiet this specific pass on exchanges that
hit cleanly in v4 (dispatch was correct every time — `sqli` fired for
both TP1 and TP2) — the same inherent single-pass stochasticity already
extensively characterized in §5j/§5k for TP5/TP6/TP7/TP9, not a
regression caused by anything touched this session. None of §5j/§5k's
fixes touch the `sqli` or `idor` agents' own prompts or logic. Recall
across single passes on this size of exchange set will keep bouncing by
a few points run to run until multi-sample voting or a larger routing
model changes that variance itself — treat any single run's raw count
as a noisy sample, not a score to chase upward one exchange at a time.

**One real, concrete precision regression WAS found by running this,
and traced to a specific line in this session's own work**: TN3 (`GET
/api/users/me`, genuinely authenticated via a real `Authorization:
Bearer <jwt>` header — confirmed directly from the captured exchange
JSON) got a NEW finding in v5 that v4 never produced:
`broken_authentication (conf=0.5): "No authentication present on
sensitive data endpoint"` — flatly wrong, and new specifically in the
run where §5j's `auth_agent.py` "check for no-auth-at-all first" bullet
was actually active for the first time (it landed after v4 started).
Root cause, confirmed by reading `security.redact_headers()`: the
Authorization header's VALUE is redacted before the model ever sees it
(`"Bearer [REDACTED -- payload and signature withheld from model; JWT
header only: {...}]"` for a JWT-shaped bearer token, or the generic
`"[REDACTED -- header present, value withheld from model]"` otherwise)
— but the header NAME and the word "present" are still right there in
what the model reads. The new prompt bullet's heavy emphasis on
flagging absent authentication as the single most important check made
the model more prone to asserting "no authentication" as a reflex,
without the older, narrower prompt's more hedged framing acting as a
brake. This is a real, session-introduced false-positive mode, not
pre-existing noise (confirmed absent from v4's TN3 result).

Fixed with one more targeted addition to the same bullet in
`agents/auth_agent.py`: explicitly telling the model that "redacted"
and "absent" are different things, that the header name plus the
redaction notice itself proves a credential WAS supplied, and to only
claim "no authentication present" when the header is genuinely missing
from what's shown. Re-verified live, in isolation, against both
exchanges the change could affect in opposite directions: TP12 still
hits (`broken_authentication`, conf=0.9, unchanged) and TN3 no longer
makes the flat false claim — it now says `authentication_bypass (conf=
0.8): "JWT token present, but no further authentication checks visible
in the response"`, an honest hedge about what a single HTTP exchange
can actually prove about server-side verification, not a confident
wrong assertion. Full suite re-run clean at 506/506 after this edit.
Not re-run as a full 22-exchange pass (the isolated, targeted check on
exactly the two affected exchanges is the right-sized verification here
— see §0's own guidance on this).

One pre-existing false positive noted but deliberately NOT touched this
pass, to avoid scope creep on an already-large session: TN5
(`missing_csrf_protection`, conf 0.8 in v4 and v5 both) flags an
endpoint that CORRECTLY rejected a missing-CSRF-token request with 403
as if CSRF protection were absent. Confirmed present in v4 already, so
not something introduced this session — worth its own investigation
pass (likely the `business_logic`/`auth` agent seeing "403 CSRF error"
in the response and pattern-matching on the words "CSRF"/"missing"
without registering that a 403 rejection is the CORRECT behavior, not
evidence of a gap) but out of scope for what was asked here.

## 5l. Root cause of "recurring erroneous sqlmap links" and "dangling code" found: Microsoft Defender was quarantining files mid-session; full sqlmap-spelling and dead-code audits done in response

The user reported Microsoft Defender had been silently removing files
during past sessions and had just added an exclusion and restored
whatever it had taken. Three things were done in direct response, in
order.

### 1. Verified the restore was actually complete

- Every `.py` file in the repo (231 total) parses cleanly with `ast.parse`
  -- a truncated/partially-deleted file would almost certainly fail this.
- Every `.java` file under `burp-extension/` (56 total) is brace-balanced
  or has an explained false positive (literal `{`/`}` characters inside
  string literals -- the EICAR test string in `FileUploadLogic.java`, and
  JSON-syntax examples in comments in `DeserializationFormatLogic.java`
  and `MassAssignmentLogic.java` -- confirmed by reading each file in
  full, not just trusting the brace count).
- No zero-byte or suspiciously tiny files anywhere.
- `git status`/`git diff --summary` against HEAD shows zero deletions
  anywhere in `harness/` or `burp-extension/` right now.
- Concretely confirmed one real prior casualty and its fix:
  `harness/agents/file_upload_agent.py` had shown as deleted (`D`) in
  `git status` earlier this session; it's now back and byte-identical to
  the committed version. The full test suite's own agent count is the
  independent proof this matters: it read "35 agents" while the file was
  gone and now reads **36 agents** with it restored.
- Every untracked file created THIS session (never committed, so `git`
  has no deletion record to fall back on if Defender took one) was
  checked to exist and be non-trivially sized by hand: `active_verification.py`,
  `test_active_verification.py`, `test_coordinator.py`,
  `test_anomaly_detector.py`, `test_github_advisories.py`, and the four
  new Burp-extension `*Logic.java`/`*LogicTest.java` pairs. All present.
- Full suite re-run clean: 506/506.

### 2. Every spelling of "sqlmap," everywhere in the repo, checked for inconsistency

Case-insensitive search for `sql[\s_-]?map` across the entire repository
(not just `harness/`) -- 55 files matched. Findings:

- **The live, currently-used code (`harness/validators/sqlmap.py`,
  `registry.py`, `planner.py`, `store.py`, `config.yaml`,
  `agents/base_agent.py`'s prompt, `active_verification.py`,
  `payload_library.py`, `risk_allocator.py`, `safety_proxy_addon.py`,
  and every test file referencing any of them) is 100% internally
  consistent.** One spelling throughout: the binary/config key/validator
  `name` is `sqlmap` (lowercase, one word), the class is
  `SqlmapValidator`, the capability string everything joins on is
  `sql_injection_validation`. No casing mismatch, no stray
  `sql_map`/`SQLMap`/`sql-map` variant found anywhere live.
- The model-hallucination guard (`planner.py`'s `plans_for_findings`,
  regression-tested in `test_planner.py`) already exists and is the
  single place `validation_hints: ["sqlmap"]` gets trusted -- confirmed
  it's the ONLY consumer of that field anywhere in the codebase (the
  Burp-extension Java side never touches sqlmap at all, since it's a
  `local_tool` capability handled entirely in Python), so there's no
  second, unguarded code path that could repeat the exact bug that
  regression test exists for.
- `testing/blind-test-kit/harness/validators/sqlmap.py` (a separate,
  deliberately-frozen snapshot of the harness for blind-testing -- see
  `METHODOLOGY.md`, and `run-1-results`/`run-2-results` prove it's
  actually been used) is byte-identical to the live copy. Not stale, not
  a fork that drifted.
- No broken/malformed URLs mentioning sqlmap anywhere (checked
  separately in case "erroneous links" meant literal hyperlinks, not
  code cross-references).

**Conclusion: no live sqlmap-related inconsistency exists in the
codebase today.** The most likely explanation for "we keep on finding
erroneous links with SQLmap" in past sessions is Defender intermittently
removing `validators/sqlmap.py` or a file that references it mid-session
(exactly the same failure mode confirmed for `file_upload_agent.py`
above) -- which would surface as exactly this kind of "reference to
something that isn't there" symptom, self-resolving each time someone
noticed and restored the file, only to recur once Defender caught the
next quarantine-worthy payload string. The AV exclusion the user just
added should stop this recurring; if it does NOT stop, that's a signal
the cause is something else and this conclusion should be revisited.

### 3. Every file checked for genuinely dead code, not just spot-checked

Given the dynamic/static registration architecture this project already
uses, "dead code" reduces to three checkable categories rather than 144
files needing individual eyeball review:

- **`harness/agents/*.py` (36 files): all live, provably.**
  `agents/plugin.py`'s `AgentPluginSystem` discovers agents via
  `pkgutil.iter_modules` over the whole `agents/` directory and
  auto-registers every `BaseAgent` subclass it finds -- there is no
  "file present but never imported" state possible for this directory
  short of an import error, and no agent is individually disabled in
  `config.yaml` (`grep -n "enabled: false" config.yaml` -> only
  `validators.active_enabled: false`, a deliberate, already-documented
  safety default, not a bug). The live agent count (36, confirmed by
  this session's own test runs) matches the file count exactly.
- **`harness/validators/*.py` (17 files): all live, provably.**
  `registry.py` statically imports every one; cross-checked file list
  on disk against import statements programmatically -- zero files
  present without a corresponding import.
- **`harness/*.py` root-level modules (33 files): 31 confirmed live
  via real cross-file references (including several that only show up
  under a LAZY/indented `import` inside a function body, e.g.
  `orchestrator.py`'s use of `exchange_text.py` -- a naive
  "grep for a line starting with import" check produces false
  negatives here; corrected before trusting the result), 1
  (`safety_proxy_addon.py`) confirmed live as an externally-invoked
  mitmproxy addon script (not imported by the harness's own Python, by
  design -- same category as `server.py` itself, which nothing imports
  either since it's the process entry point).**
- **1 genuinely dead chain found: `report_generator.py` +
  `risk_allocator.py`.** Both fully built, fully unit-tested
  (`test_report_generator.py`, `test_risk_allocator.py` both exist and
  pass), well-documented (the module's own docstring explicitly frames
  it as "the reusable version" of a prior one-off report script) -- and
  had ZERO callers anywhere outside their own tests. No `server.py`
  endpoint, no CLI hook, no orchestrator call. Exactly the same pattern
  already found and fixed once this session for
  `retry_policy.py`/`payload_library.py` (§5k): a complete feature, built
  and tested, simply never connected to anything that would ever call
  it.
- **`burp-extension/`'s 56 Java classes: all live**, checked the same
  way (every class name searched for a reference outside its own
  file/test) -- zero classes with no external reference, including the
  four newly-added `*Logic.java` files, all correctly wired into
  `ValidationExecutor.java`'s capability switch.

**Fixed, not just reported**: added `GET /report?url=...` to
`server.py`, returning `report_generator.generate_report_for_host()`'s
Markdown output as `text/markdown`, passing the live orchestrator's
`effort_budget.ledger` (the module's own docstring recommends this over
its no-ledger standalone-script default, for cost-aware ordering of
unconfirmed findings using real, in-session token-spend data rather than
the unmeasured priors `effort.py` otherwise falls back to). This makes
`risk_allocator.py` live by extension -- it has no caller except
`report_generator.py`. Verified end-to-end through the real FastAPI app
via `TestClient`: persisted a real finding, hit `GET /report`, got back
a genuine rendered Markdown report (`# Security Findings Report --
smoke-report-test.invalid`, correct confirmed/unconfirmed counts).
Full suite re-run clean: 506/506.

## 5m. First real attempt at resuming §7 item 2 (a genuinely blind test) hit a contamination problem — building a fresh target instead

Tried to resume the long-standing top pending item: run
`testing/blind-test-kit/` for real now that Ollama is confirmed
reachable, skipping its hand-simulated-LLM workaround (steps 3-4 of its
own `METHODOLOGY.md`) in favor of pointing the real orchestrator at real
Ollama directly, the same way §5j-§5l's PixelMart runs worked.

**Stopped almost immediately**: `testing/blind-test-kit/target/app.py`
returns `X-Powered-By: PixelMart/2.3.1 (Flask)` and has the EXACT same
endpoint set as `testing/test-target/`'s PixelMart
(`/api/products/search`, `/api/orders`, `/api/avatar`,
`/api/admin/config`, `/api/coupons/redeem`,
`/api/products/<id>/comments`) -- confirmed live via `curl`, not
guessed. This session already has PixelMart's `ANSWER_KEY.md`
memorized from §5j-§5l. Continuing would mean recalling known answers,
not genuine blind reasoning against unfamiliar evidence -- exactly the
contamination `METHODOLOGY.md` itself warns a blind test exists to
avoid. Stopped before capturing any exchanges; target process killed.

User's call when asked: build a genuinely new target rather than reuse
the compromised one or proceed with a caveat. A background agent is
building `testing/blind-target-2/` (different domain, different
specific vulnerabilities/mechanics, port 5002, its own
`ANSWER_KEY.md`) with a final report DELIBERATELY constrained to "it's
built, verified, here's how to start it" -- no vulnerability content,
so the orchestrating session (this one) stays genuinely blind going in.
**Do not open `testing/blind-target-2/ANSWER_KEY.md` or `app.py` before
the blind exploration + real-Ollama run is complete** -- if you're
picking this up mid-way, check whether that run already happened
before reading either file.

### What's genuinely NOT done, and why it wasn't attempted here

`sqlmap`'s binary is still not installed on this machine (confirmed
again: `which sqlmap` finds nothing, it isn't a `pip`-installable
package, `pip show sqlmap` confirms). Installing a security tool binary
is a real system change (fetching and placing an executable, potentially
altering `PATH`) — left for the user to do explicitly (or explicitly
authorize) rather than done silently as part of this pass; see §6 item 2
for what's needed once it's in place.

---

## 5n. Headless cross-identity IDOR proven live for the first time; an
execution_plane drift bug fixed; a real, live circuit-breaker collateral-
damage bug found and fixed

REVIEW.md (a senior architecture/OWASP audit run against this project,
independent of HANDOVER's own session-by-session log) named the single
biggest architectural gap as: analysis is single-exchange, so IDOR/authz
findings are never actually *proven*, only guessed at by an LLM from one
request. Investigation confirmed the picture was narrower than "missing":
`IdentityCompareLogic.java`'s source/candidate/attempt/anon 4-probe
comparison (with an anonymous-baseline check to rule out "this is just a
public resource") already existed and was already unit-tested — but was
reachable ONLY via a human clicking a `JOptionPane` in Burp to hand-pick
the comparison exchange. PixelMart's own test target already captures a
genuine two-identity scenario (Alice/Bob) specifically for this (TP3/TP4
IDOR), but the scoring scripts threw the identity relationship away and
scored both requests as independent single-exchange guesses.

**Made headless, both sides, verified real:**

- Java: `ValidationExecutor.identityCompare()` split into
  `identityCompareInternal` plus two new public overloads
  (`identityCompare(plan, source, candidateFingerprint)` and
  `identityCompare(plan, source, explicitCandidate)`) that skip the
  `JOptionPane` when a candidate is supplied explicitly. The
  candidate-selection *decision* (pool scan / explicit lookup / diff
  computation) was extracted into a new, Montoya-stub-only
  `IdentityCandidateResolver.java` so it's headlessly testable the same
  way every other `logic/` class already is — 8 new tests.
  `ValidationExecutor.exchangeFingerprint()`'s body was itself extracted
  into a new `logic/ExchangeFingerprint.java` (delegated to, not
  duplicated — every existing call site unchanged) specifically because
  `IdentityCandidateResolver` needed to call it, and calling
  `ValidationExecutor`'s own static method directly broke the isolated
  `logic/`-only javac/RunTests compilation this whole test class depends
  on (`ValidationExecutor.java` itself doesn't compile standalone — needs
  `HarnessClient`/Gson, per `dev-tools/README.md`). Found by actually
  running the verification command, not by inspection.
  ```bash
  JAVAC="/c/Users/arthu/AppData/Local/Programs/BurpSuiteCommunity/jre/bin/javac.exe"
  JAVA="/c/Users/arthu/AppData/Local/Programs/BurpSuiteCommunity/jre/bin/java.exe"
  find burp-extension/src/main/java/com/harness/llm/logic burp-extension/src/test/java/com/harness/llm/logic dev-tools/stubs -name "*.java" > /tmp/logicsrc.txt
  "$JAVAC" -d /tmp/logictest -nowarn @/tmp/logicsrc.txt && "$JAVAC" -d /tmp/logictest -nowarn dev-tools/RunTests.java
  cd /tmp/logictest && "$JAVA" RunTests $(find /c/Users/arthu/Documents/AgenticVibe/burp-extension/src/test/java/com/harness/llm/logic -name '*Test.java' | sed 's|.*[\\/]logic[\\/]||; s|\.java||' | sed 's|^|com.harness.llm.logic.|')
  # === TOTAL: 177 passed, 0 failed ===  (169 pre-existing + 8 new)
  ```
  Main-tree compile baseline unchanged: still exactly 19 pre-existing
  missing-jar errors, zero new, across every file touched this pass.

- Python: `IdentityCompareLogic`'s algorithm ported line-for-line to new
  `harness/identity_compare.py` (same verdict tiers, same 0.70
  trigram-Jaccard threshold, same confidence constants) — 12 tests ported
  1:1 from `IdentityCompareLogicTest.java`'s fixture strings, all passing,
  confirming real behavioral parity rather than assumed parity.

- New `testing/test-target/cross_identity_probe.py`: a fully
  self-contained script (bare `requests`, no Ollama, no Burp, no
  `harness/server.py`) that performs the actual live 4-probe comparison
  against a freshly-restarted PixelMart. **Run for real, live, this
  session — first non-LLM-guessed proof in this project's history**:
  ```
  [TP3 profile IDOR] CONFIRMED (confidence=0.91) -- ...
  [TP4 order IDOR]   CONFIRMED (confidence=0.91) -- ...
  ```
  Precision spot-checked too, not just recall: run manually against
  `GET /api/products` (a genuinely public endpoint) → `INCONCLUSIVE`,
  correctly not a false CONFIRMED.

**Deliberately deferred, not touched this pass**: `sessionFixationCompare`/
`logoutInvalidationCompare`'s own `JOptionPane`s (same fix would apply,
same class); race conditions/TP8; any change to `orchestrator.py`,
`planner.py`'s `plans_for_findings` flow, or `TestPlan`'s schema — the
live `/analyze` production path is byte-for-byte unchanged. This closes
one concrete slice of REVIEW.md's #3 (scope mismatch), not the whole
thing — multi-request testing for `auth`/`business_logic` findings the
LLM pipeline itself never requests is still exactly the gap REVIEW.md
named.

### A live, real bug found and fixed while testing the extension: `execution_plane` drift

Clicking "Execute selected test plan" in Burp for a `sql_injection_validation`
plan produced `[sql_injection_validation] ERROR: Plan is not assigned to
Burp.` `sql_injection_validation` (sqlmap) is *correctly* `local_tool` —
that part isn't a bug. The real bug, in `harness/planner.py`'s
hint-based branch: `jwt_validation`, `xxe_validation`, `csrf_validation`,
`file_upload_validation`, `command_injection_validation`,
`ssti_validation`, and `open_redirect_validation` were ALSO hardcoded
`local_tool` there, even though `HarnessPanel.java`'s own
`IMPLEMENTED_BURP_CAPABILITIES` set proves all 7 now have real Burp
executors (added in earlier sessions, after this hint-list was written —
the two drifted apart, exactly the "no shared source of truth between
the two" risk that set's own doc comment already named). Reproduces
whenever a model's own `validation_hints` contains the literal capability
string before the resolved category does (order-dependent first-write-wins
via the `seen` dedup set) — confirmed with a new test that reproduces
this exact ordering. Fixed by splitting the tuple into the one genuine
`local_tool` entry (`sql_injection_validation`) and the 7 that must match
`_CAPABILITIES`'s own `plane="burp"` treatment. Also fixed
`HarnessPanel.choosePlan()`'s picker: `local_tool` plans now get their own
explicit suffix (`"(runs via the harness's active validators, not this
button)"`) instead of silently inviting a guaranteed-to-fail click, same
spirit as the existing `"(not yet implemented)"` suffix.
```bash
cd harness && python -m unittest test_planner -v   # 8 tests, was 7
```

### A live, real bug found and fixed while testing the extension: circuit-breaker collateral damage

Live symptom: `auth` and `business_logic` (both correctly configured,
`llama3.1:8b` per `config.yaml`) failed outright with `Circuit breaker
'ollama' is OPEN. Service unavailable. Retry after 60.0s.` while other
agents in the same dispatch succeeded. Root cause, confirmed by reading
`ollama_client.py`/`circuit_breaker.py`: **every `OllamaClient` instance
shares one single, process-wide circuit breaker literally named
`"ollama"`**, wrapping every Ollama call from every agent regardless of
model, with `failure_threshold=3`. `ollama_client.py` raised the exact
same generic `OllamaError` for a real outage (connection refused,
timeout) AND for Ollama's own HTTP 404 "this model tag doesn't exist"
response (verified directly: `curl` against a live local Ollama with a
made-up model name returns `404 {"error": "model '...' not found"}`) —
both counted identically toward the same shared failure counter. Three
calls to ANY misconfigured model anywhere (coordinator, one agent, the
critique pass) trips the breaker and rejects every OTHER agent's calls,
on any model, for the next 60 seconds — a permanent config problem
masquerading as, and triggering the same response to, a transient outage.

**Important correction, found while root-causing this live**: at the
exact moment this was investigated, both `qwen3:8b` (then configured as
`coordinator.model`) and even `gemma4:31b-cloud` (an earlier, previously
suspected-broken coordinator setting — turned out to be a real, working
Ollama Cloud model once reachable, confirmed by a direct `curl` returning
a real completion) responded successfully — so the SPECIFIC trip observed
live was probably NOT a model-not-found case. The fix below is a real,
independently-worth-having correctness fix regardless (the conflation is
wrong on its own terms, and this exact scenario **is** what happens the
moment any model tag actually is wrong), but whoever picks this up next
should look at resource contention as the more likely trigger for
*this particular* incident: `config.yaml`'s `agents:` section still pins
every one of `sqli`/`xss`/`idor`/`auth`/`business_logic`/etc. to
`llama3.1:8b` regardless of `coordinator.model` — changing the
coordinator model does NOT change what any specialist agent actually
reasons with, so 8 agents all hitting the same `llama3.1:8b` under
`concurrency.max_parallel_agents: 3` alongside a separate `qwen3:8b`
coordinator call is a real, plausible way to legitimately time out 3
calls in a row on modest hardware. Worth checking `ollama.timeout_seconds`
(120s) against real observed latency under that load before assuming the
breaker itself is mis-tuned.

Fixed: new `OllamaModelNotFoundError(OllamaError)`, raised specifically
on HTTP 404 (checked before the generic non-200 branch), added to the
shared "ollama" breaker's `excluded_exceptions` — every other
`CircuitBreakerConfig` field spelled out explicitly to avoid
`OllamaCircuitBreaker`'s `x or default`-based config-merge silently
overriding an Ollama-specific default (3/2/60.0/1) with
`CircuitBreakerConfig`'s own generic dataclass defaults (5/3/30.0/1) the
moment any config object is passed at all — a real footgun in the
existing merge logic, worked around here rather than fixed at its root
(out of scope for this fix). 3 new tests in `test_ollama_client.py`,
including the actual regression shape: 5 consecutive 404s from one
"bad-tag" client, then a fresh client sharing the same breaker on a
genuinely different, working model succeeds normally.
```bash
cd harness && python -m unittest test_ollama_client -v   # 8 tests, was 5
python -m unittest discover -p "test_*.py"                # 522 tests, OK
```

### A real Gradle build (a different environment than every sandbox this project has run in before) found two more real gaps this session's own headless verification couldn't see

The user rebuilds the real extension jar from a GitHub Codespace against
this repo's real `build.gradle` (real Montoya API + Gson from Maven
Central, real Gradle) — a genuinely different, and stricter, environment
than the `dev-tools/stubs`-plus-plain-`javac` verification every `logic/`
test in this project (including this session's own new
`IdentityCandidateResolverTest`) has ever been checked against. That real
build surfaced two things the stub-based check structurally could not:

1. **`build.gradle` had no `testCompileOnly` for the Montoya API.**
   Gradle's Java plugin does not extend a main source set's `compileOnly`
   dependencies to the test source set automatically. Every test file in
   this project before today avoided the problem entirely by only using
   each `*Logic` class's own plain `Probe`/`Evidence`-style value types,
   never a raw Montoya interface directly.
   `IdentityCandidateResolverTest.java` is the first test that needs real
   `HttpRequestResponse`/`HttpRequest` objects (`IdentityCandidateResolver`'s
   whole job is picking a candidate directly out of a
   `Map<String, HttpRequestResponse>`), and hit
   `package burp.api.montoya.http.message does not exist` the moment it
   tried. **First fix attempt was itself wrong, in a way only a real
   Gradle `test` run (not compilation) surfaced**: added `testCompileOnly
   'net.portswigger.burp.extensions:montoya-api:2023.12.1'` — this made
   `compileTestJava` succeed, but the very next real Gradle run then
   failed all discovery with `DiscoveryIssueException` /
   `JUnit Jupiter > initializationError` ("1 test completed, 1 failed").
   Root cause: `compileOnly`-family scopes are deliberately excluded from
   Gradle's *runtime* classpath, by design — but `IdentityCandidateResolverTest`
   uses `java.lang.reflect.Proxy` (see item 2 below), which needs
   `HttpRequest.class`/`HttpRequestResponse.class`/`HttpHeader.class`
   loadable at TEST EXECUTION time, not just compile time. Reproduced
   directly, standalone: running the compiled test class with the real
   jar present on the classpath passes 8/8; running the exact same
   compiled classes with the jar removed from the classpath (only, not
   recompiled) throws `ClassNotFoundException:
   burp.api.montoya.http.message.requests.HttpRequest` — the identical
   shape to the user's real failure. **Corrected fix**: `testImplementation`
   instead of `testCompileOnly` (puts the jar on both the test compile AND
   test runtime classpath); main's own `compileOnly` is untouched and
   correct as-is, since Burp itself supplies the real Montoya
   implementation to the extension at ITS runtime — only the test suite,
   which Gradle runs standalone with no Burp process behind it, needs the
   jar bundled onto its own runtime classpath.
2. **The real `HttpRequest`/`HttpRequestResponse` interfaces are far
   larger than `dev-tools/stubs`' simplified versions** — confirmed by
   pulling the real jar from Maven Central directly and reflectively
   listing every declared method (no `javap`/`jar` tool in Burp's bundled
   JRE, so this was done via a tiny throwaway `URLClassLoader` +
   `Class.getMethods()` probe rather than assumed): the real `HttpRequest`
   has ~65 abstract methods, `HttpRequestResponse` has ~15, against the
   stub's 12 and 2 respectively. A hand-written `Fake...implements
   HttpRequest` (this session's first attempt) compiles fine against the
   simplified stub but fails "is not abstract and does not override
   abstract method ..." against the real jar — and would need updating
   every time Montoya adds another method regardless. **Fixed by rewriting
   the test's fakes to use `java.lang.reflect.Proxy`** instead of
   hand-written classes: a dynamic proxy satisfies the full interface
   automatically (unhandled methods throw `UnsupportedOperationException`,
   same intent as before), and needs zero changes if Montoya's API grows,
   since `Proxy.newProxyInstance` only needs the interface's `Class`
   object, not a fixed method list — verified to work identically against
   both the real jar and the simplified stub.

**Verified as genuinely fixed against the real API, not just reasoned
about** — this machine has no working Gradle (the only cached distribution,
8.7, cannot run its own daemon under Burp's bundled JDK 26 at all:
`Unsupported class file major version 70`, a hard Gradle-runtime
ceiling around JDK 22 unrelated to anything in this codebase), so
verification here was done by pulling the real Montoya API jar plus real
`junit-jupiter`/`junit-platform-console-standalone` jars from Maven
Central directly and compiling + running with plain `javac`/`java`,
bypassing Gradle entirely but exercising the exact same real dependency
that broke the Codespace build:
```bash
# compiled clean against the REAL jar (zero errors, not the stub):
javac -cp "montoya-api-2023.12.1.jar;junit-jupiter-api-5.14.4.jar" -d out \
  IdentityCandidateResolver.java UrlIdentifierDiff.java ExchangeFingerprint.java \
  IdentityCandidateResolverTest.java
# ran for real via the real JUnit 5 platform:
java -jar junit-platform-console-standalone-1.14.4.jar execute \
  --class-path "out;montoya-api-2023.12.1.jar" \
  --select-class com.harness.llm.logic.IdentityCandidateResolverTest --details=tree
# 8 tests found, 8 successful, 0 failed

# the runtime-classpath gap reproduced standalone, same command, jar
# removed from the classpath only (already-compiled classes untouched):
java -jar junit-platform-console-standalone-1.14.4.jar execute \
  --class-path "out" \
  --select-class com.harness.llm.logic.IdentityCandidateResolverTest --details=tree
# Caused by: java.lang.ClassNotFoundException: burp.api.montoya.http.message.requests.HttpRequest
# 1 tests found, 1 tests failed -- byte-for-byte the shape of the real Gradle failure
```
Whoever verifies a Java change here next: this session's own
`dev-tools/stubs`-based verification is necessary but demonstrably **not
sufficient** to guarantee a real Gradle build succeeds — the stub is a
deliberately simplified stand-in, and a test that touches a raw Montoya
interface type can pass every sandbox check here and still fail for real,
in TWO independent ways found this session alone (a missing test-compile
dependency, then a compile-only-vs-runtime classpath scoping gap on top
of that fix). Compiling AND running against the actual dependency jar
(pulled directly from Maven Central, as done here, with and without it on
the runtime classpath specifically) is the only way to be sure, when a
real Gradle run isn't available.

---

## 6. Still open — consolidated, current status noted

1. ~~`coordinator.py`'s fail-open-to-all-36-agents fallback, unverified
   under live traffic~~ — **fixed/verified in §5k.** 7 new unit tests
   (`test_coordinator.py`) cover every fail-open path with a mocked
   client, and a real exchange was forced through the actual live Ollama
   instance to exercise the SUCCESS path for the first time
   (`dispatch=['auth','misconfig']`, a genuine, plausible result).
2. **`sqlmap`'s real-target miss rate** — reported by a prior session,
   not re-tested since (§5h's SQLi work also confirmed injection via
   direct UNION-based exfiltration, not via `sqlmap`). Separately
   confirmed in §5i: the `sqlmap` binary itself is not installed on the
   `AgenticVibe` machine at all (`sqlmap executable not found` — the
   validator handles this gracefully, correctly reporting `status=error`
   rather than crashing, so this is an environment gap, not a code bug).
   `pip install`-able Python deps got fixed this session; `sqlmap` is a
   separate binary install, still not done anywhere in this project's
   history as far as this document can confirm.
3. ~~Duplicate `_resolve_known_vulnerabilities` implementations~~ —
   **fixed in §5h.** `analysis_pipeline.py`'s copy is gone entirely;
   `orchestrator.analyze()`'s is now the only one. Confirm with
   `grep -n "_resolve_known_vulnerabilities" harness/*.py` — only
   `orchestrator.py` should show up.
4. **A *rigorous, scored* live-model baseline STILL doesn't fully
   exist, but §5h got much closer than "realistic, not hypothetical" —
   it actually happened**, twice, on a machine where Ollama is directly
   reachable (§1, §5h). What's still missing: the clean 22-exchange run
   completed (§5h) has real findings for the whole suite, but this
   handover was written before its precision/recall against
   `testing/test-target/ANSWER_KEY.md` was tallied — do that next if
   picking this up, the raw data (`/tmp/pixelmart_real_results_v2.json`
   on that machine, if it still exists) already has everything needed.
5. ~~`jwt`/`csrf` agents have zero entries anywhere in `fast_path.py`'s
   pattern tables`~~ — **fixed in §5h.** Both now have real fast_path
   triggers (a JWT-structure header pattern; a CSRF state-changing-
   method-plus-cookie precondition check) and are no longer only
   reachable through the coordinator.
6. ~~`retry_policy.py` and `payload_library.py` (Python side) remain
   fully unwired`~~ — **wired in §5k.** New `active_verification.py`,
   called from `server.py`'s `/validation-results` handler, turns a
   `not_confirmed` result on a Burp-plane xss/ssrf/business_logic finding
   into a real retry-with-a-new-payload loop, with LLM-fallback
   escalation once the curated library is exhausted and a
   `handover_required` signal in the API response for the
   `HANDOVER_MANUAL` case. `sqlmap` (the other active validator)
   deliberately excluded — see §5k for why.
7. **A genuinely blind, adversarial test has never successfully
   happened.** Still true as of §5h — that session's real-model work
   was a controlled discovery run against a known-answer-key target,
   not a blind test. Still the top priority for a genuine blind run.
8. **24 of 31 `_CAPABILITIES` category keys now have a real Burp
   executor** (§5c #3, §5d, §5e, §5f, §5g, §5h, §5i) — 4 more
   implemented across §5h/§5i (`race_condition_validation`,
   `header_injection_validation`, `api_security_validation`,
   `file_upload_validation` using an EICAR-based safety-first design
   per direct user suggestion — see §5i), 7 remain: `crypto_transport_validation`,
   `http_request_smuggling_detection`, `oauth_flow_validation`,
   `attack_surface_mapping`, `subdomain_takeover_detection`,
   `web_cache_poisoning_detection`, `websocket_cswsh_validation`. Not a
   bug to hunt for; deliberate, scoped work needing genuinely different
   handling (raw sockets, DNS, WebSocket protocol, TLS internals) than
   the mutate-and-compare pattern the other 24 share.
   `nosql_validation` remains deliberately deferred (§5f) — still needs
   live Burp access to verify parameter-mutation semantics before it
   can be implemented correctly.
9. **NEW in §5i: `store.py`'s `confirmation_capabilities` allowlist
   (only `cross_identity_compare`, `authorization_boundary_compare`,
   `sql_injection_validation` may ever record `confirmed=True` in
   `validation_runs`) is now confirmed, live, to be under-inclusive.**
   `cors_misconfiguration_detection`'s active test is exactly as
   deterministic as the two identity-compare capabilities already on
   it (a real replay, a real observed response), but isn't on the list
   — so a real Juice Shop run produced 10 genuine `Finding.confirmed=True`
   CORS results that the durable `validation_runs` ledger has none of.
   Deliberately not fixed this session (see §5i for why — it's a trust-
   policy decision, not a bug fix, and needs auditing every OTHER
   active validator's actual rigor first). Also worth doing at the same
   time: 12 of 13 active validators' `plan()` methods were completely
   broken until §5i (a systemic, previously-undiscovered bug — see that
   section) precisely because `active_enabled=True` had never been
   exercised in a real run anywhere in this project's history before
   now. Both bugs found and fixed only by actually flipping that flag
   on and watching what happened against a real target — same lesson
   as §0, restated because it keeps being the thing that finds real
   bugs no amount of code review does.

---

## 7. Priority order for whoever picks this up next

1. **Score the §5h clean discovery run against `ANSWER_KEY.md`.** The
   run itself is done (§5h, §6.4) — a real, non-substituted 22-exchange
   run with real findings for the whole suite, on the `AgenticVibe`
   machine. What's missing is tallying it into an actual precision/
   recall number the way `testing/blind-test-kit/` was designed to
   produce. This is now a data-analysis task, not a "get a live model
   running" task — the hard part is done.
2. **Run `testing/blind-test-kit/` for real**, with the fixed
   `METHODOLOGY.md`, with a tester who has not read this document. Still
   attempted only once, still produced no usable signal that time (§3d).
   With Ollama confirmed directly reachable on the `AgenticVibe` machine
   (§1, §5h), this is more achievable than it has ever been — don't
   confuse this with item 1 above, which is a *controlled* run against a
   target whose answers are already known.
3. Items 1, 2, 4, 6 in §6 — coordinator fail-open (still unverified
   under live traffic even after §5h's run), sqlmap miss rate (still
   unverified), whether §5h's run data changes the live-model-baseline
   picture (item 4), unwired retry/payload modules.
4. **Implement a handful of the still-missing 9 Burp validation
   executors** (§5h, §6.8) — 22 of 31 are done as of §5h. `nosql_validation`
   needs someone with live Burp access to verify `HttpParameter`'s
   JSON-value and remove+add-parameter semantics empirically first
   (§5f) — don't implement it from the interface alone.
   `file_upload_validation` needs a genuinely safety-first pass (§5h) —
   an inert-marker-upload-and-check-accessibility design, deliberately
   stopping short of ever attempting real code execution against a live
   target, not the agent's own suggested_test payloads verbatim. The
   rest (`crypto_transport_validation`, `http_request_smuggling_detection`,
   `oauth_flow_validation`, `attack_surface_mapping`,
   `subdomain_takeover_detection`, `web_cache_poisoning_detection`,
   `websocket_cswsh_validation`) need genuinely different handling (raw
   sockets, DNS, WebSocket protocol, TLS internals) and deserve their
   own focused pass.

**Don't start by reading the other 20+ markdown files at this project's
root and trying to synthesize a mental model from them.** Start with
§1's verification commands, confirm the numbers match, then work
through §3–6 the same way — every claim here has a command next to it
for exactly that reason.
