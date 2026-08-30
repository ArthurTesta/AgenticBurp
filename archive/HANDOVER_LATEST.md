# HANDOVER — read this before touching anything

Written at the end of a long session. Every claim below was verified by actually running something in this exact sandbox, not recalled from memory — the same standard this project holds itself to elsewhere. Where a claim couldn't be verified, it's labeled as such. **Re-verify the load-bearing facts yourself before relying on them** — commands to do that are given inline. Don't trust this document's prose over the code; that's not false modesty, it's this project's own house rule (see `HANDOVER.md`'s own opening line, which says the same thing).

---

## 0. The one thing to internalize before anything else

**This session found that the entire specialist-agent pipeline had never once worked, in this project's history, until a bug fixed partway through this session.** A green 400+ test suite coexisted with that for an unknown length of time. The lesson isn't "check the tests" — the tests were fine. The lesson is: **a claim is only as strong as the thing that would have caught it being false, and unit tests structurally cannot catch a bug that only manifests when the real, full, live call path runs.** Every fix below was found by actually running the harness against a real target, not by reading code more carefully. If you're auditing this project further, running it live against something real will find more of these. Reading it harder won't.

---

## 1. Current environment state — verify before assuming

```bash
# Test suite (Python side)
cd /home/claude/project/harness && python3 -m unittest discover -p "test_*.py"
# Expected: Ran 410 tests, OK

python3 -m pytest test_plugin_system.py -q
# Expected: 26 passed

# Counts
ls agents/*.py | grep -vc -E "__init__|base_agent|plugin.py"    # expect 36
ls validators/*.py | grep -vc -E "__init__|base.py"              # expect 15

# Java side (stub-compiled, not a real build — see §6)
cd /home/claude/project
find dev-tools/stubs burp-extension/src/main/java -name "*.java" > /tmp/src.txt
javac -d /tmp/out -nowarn @/tmp/src.txt 2>&1 | grep -c "error:"
# Expected: 19 (all traced to missing gson/Montoya jars in this sandbox -- see §6, not real defects)
```

**If any of these numbers differ from what's stated, something changed since this was written — trust the command output, not this document.**

### 1a. Juice Shop is DOWN right now, and nothing about its state persists

A live OWASP Juice Shop instance was stood up and run against extensively this session (see §5). **As of the end of this session, that process is dead** (confirmed: `curl http://localhost:3000/` returns connection refused). This has happened twice in this session already — it's fragile under sustained test traffic, likely SQLite lock contention (see the restart note in §5).

**Nothing about the Juice Shop instance, its filesystem clone, or the harness's own SQLite databases used during testing survives between sessions.** Specifically:
- `/home/claude/work/juice-shop-live/` — the cloned+built Juice Shop instance. Gone in a new session.
- `/tmp/live_assessment/assessment.db` — the harness findings DB from the "as-if-unknown" assessment (§5). Gone in a new session. **This is the only place those 13 findings ever lived as structured data** — the markdown reports in the repo are the only surviving record.
- Every other temp DB used during earlier phases of this session (`tempfile.mkdtemp()`-based, used for the hand-verified SQLi/IDOR/business-logic findings before the "as-if-unknown" framing) — also gone, also never was in a persistent location.

**If you need the live-target findings, read the markdown reports** (`JUICE_SHOP_FINAL_CONSOLIDATED_REPORT.md`, `JUICE_SHOP_A_TO_Z_ASSESSMENT.md`, `LIVE_TARGET_VERIFICATION_REPORT.md`) — don't go looking for a database that has the raw data, because none survives. If you need to re-verify a finding, you'll need to re-run Juice Shop and re-derive it (recipe below).

### 1b. Re-standing up Juice Shop — corrected recipe

`HANDOVER.md`'s existing recipe (search for "Recipe: getting a live OWASP Juice Shop instance running") is **95% correct and was followed successfully this session** — clone, `CYPRESS_INSTALL_BINARY=0 npm install`, `npm run build:server`, placeholder frontend files, `setsid node build/app.js`. **One correction found this session**: the exact placeholder image filenames that document lists (`JuicyChatBot.png`, `JuicyBot.png`, `JuiceShop_Logo.png`) were **stale for the checkout cloned this session** (still version 20.2.0, same as before — the source moved under the same version tag, or the doc was wrong from the start). The actual required files, re-derived from the build output rather than assumed:

```bash
cd /home/claude/work/juice-shop-live  # after following HANDOVER.md's recipe through the placeholder-files step
grep -rhoE "frontend/dist/frontend/[a-zA-Z0-9_/.\-]+\.(js|css|html|ico|png|vtt)" build/*.js build/lib/**/*.js 2>/dev/null | sort -u
```

Run this **every time**, don't copy either list blindly — it changes across checkouts of the same version tag for reasons not fully understood. This session it returned `ChatbotAvatar.png` and `hackingInstructor.png`, not the names in `HANDOVER.md`.

**If the process dies mid-session (SQLite errors in `/tmp/juice-shop.log`):**
```bash
cd /home/claude/work/juice-shop-live
rm -f data/juiceshop.sqlite data/juiceshop.sqlite-journal data/juiceshop.sqlite-wal data/juiceshop.sqlite-shm
setsid node build/app.js > /tmp/juice-shop.log 2>&1 < /dev/null &
sleep 10
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/rest/products/search?q=apple  # expect 200
```
This wipes all data (registered identities, basket contents, orders) — you'll need to re-register test identities. It happened twice this session under moderate concurrent-request load; budget for it happening again.

**Ollama is not reachable in this sandbox** (network policy blocks `ollama.com`; nothing listens on `localhost:11434`). This is environmental, not a bug — don't spend time trying to work around it. Every finding in this session's live-target work came from a human-in-the-loop-style substitution: constructing the harness's *real* prompts via its own code, then having the acting agent (Claude, in that session) genuinely reason through them and produce the JSON response a real LLM call would need to. See `LIVE_TARGET_VERIFICATION_REPORT.md` and `JUICE_SHOP_A_TO_Z_ASSESSMENT.md` for exactly how, and their own honesty sections for what that does and doesn't prove about the actually-configured `llama3.1:8b` model.

---

## 2. Bugs found and FIXED this session — verified, not just believed

Each of these has a regression test; run the named test file to reconfirm before trusting the "fixed" label.

| # | File | Bug | Fix | Test |
|---|---|---|---|---|
| 1 | `harness/safety_gate.py` | Hard-deny pattern check never URL-decoded before matching — `rm+-rf+/` and `rm%20-rf%20/` classified as SAFE where `rm -rf /` correctly didn't | Decode-then-check pass, both raw and decoded forms checked | `test_safety_gate.py` (5 new tests) |
| 2 | `harness/analysis_pipeline.py` | `_resolve_known_vulnerabilities` imported `Component` from `models` and `github_advisories` — **neither name exists anywhere in the codebase** | Fixed to `ComponentCandidate`, the real class | No dedicated new test — caught live, fixed, confirmed by direct call. **A duplicate, non-identical implementation of this same method still exists in `orchestrator.py` and is also live-reachable — see §4, item 1, NOT resolved.** |
| 3 | `harness/prompt_validator.py` | **Severest bug this session.** `validate_system_prompt()` applied the user-content injection check to the harness's own trusted, hardcoded system prompt. Every one of the 36 specialist agents' system prompts contains `_COMMON_RULES`, which contains the literal text `"; so"`, which matched the shell-chaining pattern. **Every single agent dispatch failed before any LLM call was attempted, for the pipeline's entire prior history.** | Blocked-pattern check now applies to user prompts only | `test_prompt_validator.py::TestRealAgentSystemPromptsPassValidation` — constructs a real `AgentManager` and validates every real agent's actual system prompt, not a hand-written stand-in |
| 4 | `harness/prompt_validator.py` | The same pattern, once correctly scoped to user prompts, was **broken in both directions simultaneously**: rejected ordinary HTTP syntax (`Content-Type: application/json; charset=utf-8` — a `\b` anchor fires on a semicolon directly after a word char with no space) while **missing** realistic attacks with a space before the operator (`x=1 && curl evil.com` — no `\b` fires there, since a space is also non-word). Confirmed both directions with 13 direct test cases before fixing. | Replaced with a pattern requiring the operator to be followed by a specific, recognized dangerous command name, not just any word | `test_prompt_validator.py::TestShellChainingPatternPrecision` (10 tests) |
| 5 | `harness/prompt_validator.py` | Separately, 2 of 36 agents (`http_request_smuggling` at 306 lines, `recon` at 221) failed a shared `max_prompt_lines=200` line-count limit meant for user content, purely for having verbose, legitimate specialty prompts | Split into `max_system_prompt_lines=500` / `max_user_prompt_lines=200`, matching an existing char-limit precedent in the same config class | Same test file as #3 |
| 6 | `harness/validators/sqlmap.py` | `subprocess.TimeoutExpired`'s `.stdout`/`.stderr` can be `bytes` even when the call passed `text=True` — confirmed by triggering a **genuine** sqlmap timeout against the real Juice Shop search endpoint (a `level=2` scan legitimately took over 90s). The old exception handler did `(exc.stdout or "") + "\n" + (exc.stderr or "")`, which crashes with `TypeError` the instant either side is bytes. No prior test exercised this path — every earlier real sqlmap run either completed in time or hit a different exception. | Added a small type-normalizing helper | `test_validators.py::test_timeout_with_bytes_partial_output_does_not_crash` + 2 companion tests |

**All six were found by running the harness against a real target, not by re-reading the code.** #3 and #4 in particular were invisible to the full pre-existing test suite for an unknown length of time — treat "the tests pass" as necessary, not sufficient, going forward.

---

## 3. Also fixed this session — infrastructure, not live-target-discovered bugs

These were found by direct code audit (grep, tracing call graphs) rather than live testing, and are lower-risk but real:

- **M2**: Forced-egress safety proxy (`harness/safety_proxy_addon.py`, a real mitmproxy addon) — fail-closed by design, 22 tests using mitmproxy's own real test fixtures. Setup doc: `PROXY_SETUP.md`. **Never run against a real client/target** — only unit-tested against mocked mitmproxy objects. `PROXY_SETUP.md` §5 lists exactly what a real run needs to confirm.
- **M3**: Java-side Identity wiring — `ValidationExecutor.identityCompare()`'s picker now shows registered identity names instead of bare fingerprints, plus a write-side context-menu action to register sessions. New Montoya-free class `IdentityLabelResolver.java`, 11 tests, run via the project's existing reflection-based `dev-tools/RunTests.java` (not real JUnit — this sandbox has no Maven Central access). **Never run against real Burp** — compile-verified and logic-unit-tested only.
- **M4**: Cross-run finding suppression — `store.suppress_finding()`/`unsuppress_finding()`/`list_suppressions()`, new `finding_suppressions` table, three new server.py endpoints, verified via a **new `test_server.py`** using FastAPI's real `TestClient` (previously no test file exercised any server.py endpoint via real HTTP at all).
- **M5**: `risk_allocator.py` wired into `report_generator.py` for cost-aware ranking of unconfirmed findings. **Real scope note**: `risk_allocator.rank()` had *zero* callers anywhere before this fix — bigger gap than initially assumed.
- Small item: `recon_validator.py` now redacts sensitive header *values* at collection time (4 separate sites found and fixed, not just 1) via the existing `security.redact_headers()`. New `test_recon_validator.py` (this validator had zero direct test coverage before).

Full technical detail for all of the above: `CHANGELOG_AUDIT_FOLLOWUP.md` (has a dated addendum per milestone).

---

## 4. Found, but explicitly NOT fixed — don't assume these are resolved

1. **Duplicate `_resolve_known_vulnerabilities` implementations.** `analysis_pipeline.py`'s copy (fixed for the import crash, §2 item 2) and `orchestrator.py`'s separate, non-identical copy are **both live-reachable on the same call path** (`AnalysisPipeline.run_full_analysis()` calls its own internally; `Orchestrator.analyze()` calls its own again afterward, on the same `reports` list). Real behavioral differences exist between them (different KEV-null guards, different unverified/skipped error reporting) — this is *not* a safe find-and-delete-one-copy fix; it needs the two reconciled deliberately. Likely causes known-vulnerability lookups (GitHub Advisory + CISA KEV API calls) to run twice per exchange.

2. **`sqlmap` missed two-for-two real, hand-confirmed SQL injections** in this session — once via a heuristic dismissal ("parameter does not appear to be dynamic") against the login endpoint, once via a genuine timeout against the search endpoint. This is not a code bug (see fix #6 above for the crash that timeout exposed) — sqlmap ran, and simply didn't find what was demonstrably there both times. Worth investigating (higher `--level`/`--risk`, or a harness-native differential-response fallback that doesn't depend on sqlmap's own heuristics) before trusting this validator's "not_confirmed" result as meaningful evidence of absence.

3. **`fast_path.py`'s URL-pattern dispatch is promiscuous.** Confirmed directly: any URL containing the substring "user" triggers `idor`/`auth`/`misconfig` regardless of actual relevance (e.g., `/rest/user/login` and `/rest/products/search?q=test` both got an identical 6-agent dispatch this session). Not incorrect — the agents genuinely returned empty findings when irrelevant — but it's a real compute-cost problem (see the compute estimate in `JUICE_SHOP_FINAL_CONSOLIDATED_REPORT.md` Part 3, which is directly inflated by this).

4. **`coordinator.py`'s fail-open-to-all-36-agents fallback.** Confirmed directly in source (`coordinator.py` line ~155): any exchange where the coordinator's own routing call fails or returns nothing usable dispatches **every** agent. A single malformed LLM response on an ambiguous exchange can spike compute 6-7x with zero warning to the operator. Not fixed, not even flagged to the user anywhere in the running system — only in this document and the consolidated report.

5. **`recon_validator.py` produces heavy false positives against any SPA-fallback route.** Confirmed directly this session: 45 of 46 "discovered" endpoints in one run were an artifact of Juice Shop's placeholder-frontend catch-all route returning byte-identical content to the homepage for any unmatched path (`/admin`, `/.git/HEAD`, `/login` all returned the literal same placeholder HTML). Caught only by diffing response bodies, not status codes. A real deployment with any SPA-style fallback route (which is most modern single-page apps, including Juice Shop's real, correctly-built frontend) would show the same failure mode. `recon_validator.py` was not changed to address this — only worked around by hand this session.

6. **No real precision/recall baseline exists for this tool against anything.** Every "confirmed" finding in this session's live-target work came from a human/Claude-driven substitution for the LLM, not the actually-configured `llama3.1:8b`. There is no data anywhere in this project's history — before or after this session — establishing what the real, deployed model actually finds when pointed at a target. Don't let any prose (including this document, including `JUICE_SHOP_FINAL_CONSOLIDATED_REPORT.md`) imply otherwise; that report is explicit about this in its own Part 2, and it's worth restating here because it's the single easiest thing for a new agent to accidentally overstate.

---

## 5. Live-target findings this session — pointers, not restated

Full detail lives in three files, don't restate their content from memory — re-read them:
- **`LIVE_TARGET_VERIFICATION_REPORT.md`** — the first live-target session: SQLi login bypass, IDOR on `/rest/basket/{id}` (independently confirmed by running the real `IdentityCompareLogic.java` against real captured probes), CORS misconfig, negative-quantity checkout (confirmed end-to-end with a real server-computed `totalPrice: -190.03`).
- **`JUICE_SHOP_A_TO_Z_ASSESSMENT.md`** — the "as-if-unknown" organic assessment: `/ftp` unauthenticated listing exposing a real KeePass DB (downloaded and byte-verified), a filter bypass (double-encoded null byte) generalized across multiple files in that listing, admin-config exposure, search SQLi with demonstrated impact (56 vs 46 results), registration mass-assignment to admin role (confirmed via real JWT decode), a security-question disclosure, and one deliberately-hedged, unconfirmed stored-XSS candidate (couldn't verify actual browser execution — no real Angular frontend in this sandbox).
- **`JUICE_SHOP_FINAL_CONSOLIDATED_REPORT.md`** — brings both together, plus the confidence assessment (§Part 2) and compute-requirement estimate (§Part 3) for a working-day run, both explicitly labeled as reasoned estimates, not measurements.

**13 confirmed findings, 2 deliberately-hedged unconfirmed notes, 1 correctly suppressed as superseded — across those two live sessions combined.** None of this is re-derivable without standing Juice Shop back up (§1b) — the underlying request/response data is gone.

---

## 6. Java build state — unchanged this session, don't re-litigate

16 of the stub-compile's 19 errors (see §1's exact command) are the same 5 categories documented since before this session (missing Montoya API classes, missing `com.google.gson`). The 3 *new* errors (19 vs. the previously-documented 16) come from `HarnessClient.java`'s new `listIdentities()`/`sessionsForHost()` methods needing `com.google.gson.reflect.TypeToken` — same root cause (no real gson jar in this stub-only sandbox), not a new defect category. `ValidationExecutor.java` and the new `IdentityLabelResolver.java` compile with **zero errors**. None of this has ever been verified against a real Gradle build with real Maven Central access — that remains entirely untested, as it has been for this project's whole history in this sandbox.

---

## 7. Priority order for whoever picks this up next

Highest value, in order:

1. **Reconcile the duplicate `_resolve_known_vulnerabilities`** (§4.1). Concrete, bounded, safety-relevant.
2. **Investigate the `sqlmap` 0-for-2 miss rate** (§4.2). A confirmation layer that doesn't confirm real vulnerabilities undermines the whole "confirmed vs. unconfirmed" distinction this project's reports are built around.
3. **Audit the rest of `prompt_validator.py`'s `blocked_patterns` list against real traffic.** Only the one pattern that actually broke (§2.4) got the same scrutiny — given how wrong it turned out to be, assume the others deserve it too rather than assuming they're fine because nothing's crashed yet.
4. **Get a real Ollama instance reachable and run the fixed pipeline end-to-end at least once.** Every claim in §4.6 stands until this happens. This is the single biggest remaining gap between "the pipeline works" (now true, verified) and "the product works" (still unmeasured).
5. Everything else in `JUICE_SHOP_FINAL_CONSOLIDATED_REPORT.md`'s Part 5.

**Don't start by re-reading old handovers and building a mental model from prose.** Start with §1's verification commands, confirm the numbers match, and go from there. That's the whole point of this document existing.
