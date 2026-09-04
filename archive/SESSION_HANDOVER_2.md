> **HISTORICAL (session 2).** For the current project state read
> **SESSION_HANDOVER_3.md** first — it is the authoritative handover. This file
> covers the session-2 backlog (A1/F2–F6, cloud coordinator) that session 3 built
> out; its "remaining backlog" is largely done now (see HANDOVER_3 §1).

# Session handover 2 — detection fixes, cloud coordinator, active-agent feature build

Discipline (same as SESSION_HANDOVER.md): every claim is either (a) **verified**
this session by the exact command/test shown, or (b) marked **reported/not-run**.
Don't blur them. When something says "+N tests" it means N unit tests were added
and the suite was green after.

---

## 0. Read first — state, environment, and hazards

- **Branch:** `WorkingSunday`. **HEAD:** `ab9f5f6`. **`main` and `WorkingSunday`
  are both at the same line of history** and were last reconciled deliberately
  (see §5). Remote `origin` is in sync with local for both. Push target is
  `origin/WorkingSunday`.
- **Test suite green.** From `harness/`: `python -m unittest discover -p "test_*.py"`
  → OK (~677 tests). Run this before trusting anything and after every change.
- **Everything I built this session is committed and pushed.** No source work is
  uncommitted. Uncommitted items in `git status` are only: the built
  `*.jar` (artifact) and untracked `testing/blind-target-2/*` kit files that were
  restored from commit `bdbd9e6` (recoverable there; they were untracked at
  session start too).
- **Ollama is real and local.** `qwen3:8b`, `gemma2:9B`, `gemma4:latest`,
  `llama3.1:8b` in `/api/tags`. **Cloud models `gemma4:31b-cloud` and
  `gpt-oss:120b-cloud` are reachable but do NOT appear in `/api/tags`** — probe
  them with a direct `/api/chat` call, not by listing tags. Single consumer GPU;
  `concurrency.max_parallel_agents: 1`. **Never run two LLM benchmarks at once.**
- **HAZARD — a parallel/"side" coding-agent session edits this same working tree.**
  Mid-session it committed `bdbd9e6 "MondayWork"`, which **deleted most of the
  harness source** (non-importable) and, when it moved local HEAD, **wiped
  `harness/*.py` on disk live while I was working**. We restored to `d57bcd4`
  (§5). If the tree looks gutted or imports fail, suspect this. `bdbd9e6` is
  recoverable in git objects if any of it was wanted.
- **HAZARD — the harness caches whole analyses.** Reusing a warm
  `*_cache.db` makes a "run" replay old results in ~0.1s (looks instant, 0
  per-exchange time). For a real re-run, delete/rename the cache DB so it's cold.
  Found the hard way (§3).
- **`harness/config.yaml` is armed for live Juice Shop testing:**
  `validators.active_enabled: true`, `allow_mutating_replay: true`,
  `autonomous_discovery.enabled: true`, `allowed_hosts: ["localhost","127.0.0.1"]`.
  The config's own comments say revert to false/[] when done. Not mine to change
  without the user.
- **Targets currently running:** Juice Shop v20.2.0 on `localhost:3000`;
  blind-target-2 (a Flask "helpdesk") on `127.0.0.1:5002`. **Do NOT read
  `testing/blind-target-2/app.py` or any `*answerkey*` / `ANSWER_KEY.md`** — it's
  a deliberately-blind target; reading its source invalidates the eval.

---

## 1. What was built this session (all committed, all tested)

Chronological, newest last. Each is a commit on `WorkingSunday`.

1. **Cloud-coordinator routing + first detection fixes** (`d6c62ce`, in `main` too)
   - CORS: bare `Access-Control-Allow-Origin: *` w/o credentials → informational
     (was the 58/60 false-"confirmed" driver). `harness/validators/cors_validator.py`.
   - fast_path: `/rest/track-order/<id>`→idor, `/ftp`→misconfig/recon/info_disclosure.
     `harness/fast_path.py`.
   - **Anonymized feature projection** `harness/feature_projection.py` — off-prem-safe
     view of an exchange (method/path-with-ids-redacted/param NAMES/status/shape/
     presence booleans; NEVER bodies/header values/query values/ids).
   - **`coordinator.cloud_primary`** (default off): cloud model routes first on the
     projection, fast_path becomes a union floor. `harness/coordinator.py`,
     `harness/orchestrator.py` `_choose_agents` / `_choose_agents_cloud_primary`.
   - **`adaptive_respin`** (default off): challenge/re-spin loop bounded by
     max_rounds + effort budget. `harness/orchestrator.py` `_maybe_adaptive_respin`.
2. **anomaly/ollama/Burp + handover** (`d57bcd4`, in `main`) — parallel session's
   FP-reduction, ollama JSON fix, Burp UX; plus `SESSION_HANDOVER.md` (session 1).
3. **CORS Vary gate + blind harness** (`6d7364a`) — the wildcard fix was
   INCOMPLETE: `_test_vary_origin` also flagged "Missing Vary: Origin" as
   vulnerable on static-wildcard endpoints, keeping CORS confirmed via
   `any(t.vulnerable)`. Now gated on actual origin reflection. **Verified live:
   CORS 58→0** across the 50 Juice Shop exchanges.
4. **IDOR response-status gate + JS endpoint extractor** (`3c21088`)
   - `harness/access_control_gate.py` — **"B"**. Deterministic: caps
     access-control findings (idor/authz/BOLA) to 0.15 when the response is a
     denial (401/403/405) — the control demonstrably worked. Runs before critique.
     Found by the blind eval (§4). Wired in `analysis_pipeline.run_full_analysis`.
   - `harness/js_endpoint_extractor.py` — **F1**. Mines JS/HTML for endpoint paths.
     Live: 34 /api|/rest from Juice Shop `main.js`.
5. **Global request throttle** (`31107ba`) — **F6**. `harness/global_throttle.py`,
   a process-wide async token-bucket ceiling on outbound target requests. Wired
   into every outbound validator send + scope_discovery (race_condition and
   http_request_smuggling exempt — they need intentional concurrency).
   `config.throttle.max_requests_per_second` (0=off), configured at orchestrator
   init. Verified live pacing.
6. **Crawler + `/crawl`** (`7d40575`) — **F3 Python half**. `harness/crawler.py`
   fetches pages + JS bundles, runs F1, scope-gated + throttled + bounded +
   session-aware. `server.py` `POST /crawl`. Live: 80 endpoints from Juice Shop.
7. **Iterative agent** (`ff6c931`, `ac4641c`) — **F4 keystone**.
   `harness/iterative_agent.py`. Bounded send→observe→adapt loop. LLM emits a
   CONSTRAINED action (mutate named param / set header / stop) → harness builds a
   request DERIVED from the captured exchange (reuses sqlmap's mutation helpers) →
   scope-check + safety_gate (mutating) + throttle → send. Bounded by
   step_budget(~250) + effort_budget + throttle. Returns findings + a **handoff
   note** (for F2). Off by default, NOT yet wired into the orchestrator.
   `ac4641c` added: **abort-on-target-distress** (3 consecutive 429/5xx/transport
   fails → stop) and an **`on_step` live-activity callback** (the feed a UI shows).
8. **JS call-shape extraction** (`ab9f5f6`) — **A1 part 1**.
   `extract_call_shapes()` in `js_endpoint_extractor.py` recovers (method, path)
   from axios/$.verb/xhr.open/fetch-with-method so a request can be reconstructed.

---

## 2. The remaining backlog (what the next agent should build)

User-agreed order was F6→F3→F4→F2→F5; F6/F3(py)/F4 done. New ideas (A1–A4, V1)
arrived mid-session. **Last user priority: A1 next.** Then their earlier order.

- **A1 part 2 — missing-authentication probe (IN PROGRESS, do this next).**
  Build `harness/missing_auth_probe.py`. Given a `CallShape` (from
  `extract_call_shapes`) or any discovered endpoint, reconstruct the request and
  **fire it with auth stripped** (no Authorization/Cookie), through the throttle +
  `allowed_hosts` scope. Classify **missing_auth** when the unauth request returns
  2xx with substantive content (not a login redirect/401/403/empty). Recommended:
  also send with a garbage token to distinguish "no auth needed" from "any token
  works". Emit a `Finding(vulnerability_class="missing_authentication", ...)`.
  This is the Aikido "generateReport unauthenticated" capability. Test against
  blind-target-2 (`/api/tickets` unauth = 401 = secure TN) and Juice Shop.
  Then optionally wire it as a validator or an F4 specialty.
- **F2 — pause → validate → remember (pivot/combine).** After an agent finds
  something, hold, ask the orchestrator to validate, and store it for pivoting +
  combination. Machinery already exists to build on: `harness/knowledge.py`
  (retrieve/remember), `harness/chaining.py` (combination — 20KB, has `detect()`),
  `harness/active_verification.py` (validation). Consumes F4's `handoff_note`.
- **F5 — retry-agent count.** A tester setting: "spin up N agents of class X
  consecutively, stop when found." Python: an orchestrator loop that re-dispatches
  the same class up to N times (or the iterative agent N runs) until a finding.
  Note `adaptive_respin` already spins a DIFFERENT agent; F5 spins the SAME one.
- **A2 — browser-driven XSS validation.** Execute an XSS payload in a real
  headless browser, observe `console.log`/alert to confirm execution (Aikido used
  Selenium). New validator; heavier dependency.
- **A3 — ffuf-style content discovery.** Wordlist/fuzzing endpoint discovery to
  enrich the site map, alongside the JS-based F1/F3.
- **A4 — confidential-info response detector.** Deterministic scanner for private
  routes, internal storage paths, tenant identifiers, secrets in responses.
  Overlaps the existing `info_disclosure` agent + `anomaly_detector.py` but as a
  deterministic response pass. Self-contained, testable.
- **V1 — "view what each agent is doing".** F4 already emits transcript + on_step;
  the visual feed is Java. Single-shot agents have `AnalysisTracker`/`ProgressPanel`.
- **THE JAVA BATCH (do all at once — user compiles via Gradle in Codespace; I
  cannot compile/test Burp here).** Contains: F3 **Crawl button** (POST /crawl,
  show discovered endpoints, add to site map), F6 **throttle setting**, F5
  **retry-count setting**, V1 **live agent-activity view**. Extension entry points:
  `burp-extension/src/main/java/com/harness/llm/` — `HarnessClient.java` (HTTP to
  the Python server at localhost), `ui/HarnessPanel.java`, `ui/AttackSurfacePanel.java`,
  `ui/ProgressPanel.java`, `ui/AnalysisTracker.java`. The Python server endpoints
  they call are FastAPI in `harness/server.py` (loopback bearer auth optional).

---

## 3. Juice Shop re-run result (context for the fixes) — VERIFIED

Cold run (fresh cache+state), 50 exchanges, 4.0h wall. Compared vs
`testing/juiceshop-full-run/results_PREV_run.jsonl` (the prior baseline; **keep
it — the cold run overwrites `results.jsonl`**). Report artifact:
"Juice Shop Re-Run" (https://claude.ai/code/artifact/324aa60a-af8b-4e44-bd2f-1670169d9145).
- **CORS confirmed 58 → 0** (the run itself logs a STALE 56 because its process
  loaded pre-Vary-fix code; the corrected 0 was re-measured live and is what to
  report). **sqlmap 0 → 15** — the 2 hand-verified login bypasses now confirm
  (0/2→2/2), BUT all 15 are the same injectable `/rest/user/login` endpoint hit
  by many captured requests → **per-endpoint dedup opportunity**, and JS02b
  (default-creds) is mislabeled sqli. Routing gaps closed.
- Recall 12/13→12/13 (keyword-graded; artifact's manual grade was 10/13):
  +JS23 (routing fix), −JS02b (LLM nondeterminism, identical dispatch, not a
  regression).

## 4. Blind-target-2 result (why "B" exists) — VERIFIED

Curated eval on an uncontaminated target (`testing/blind-target-2/run_blind_eval.py`,
`blind_eval_exchanges.json`; results `C:\tmp\blind_eval_results.json`).
- **Recall 2/2 by genuine reasoning:** IDOR on `GET /api/tickets/{id}` @0.85 +
  excessive-data-exposure (leaked staff `internal_notes`) @0.90; department
  mass-assignment @0.60. Real capability, not memorization.
- **Precision gap (→ "B"):** the idor/auth agents flagged IDOR @0.90 on a
  403-enforced request and authz @0.80 on a 405-blocked one — HIGHER than the
  real IDOR. They key on request SHAPE, not response OUTCOME. `access_control_gate.py`
  caps these deterministically. (Prompt-level improvement is still open follow-up.)

## 5. The git incident (so it isn't repeated) — VERIFIED

The parallel session's `bdbd9e6 "MondayWork"` deleted the harness source. Earlier
in the session the user asked to "replace main" with the work, and `main` was
force-moved through `d57bcd4`→`bdbd9e6` and then **restored to `d57bcd4`** (harness
intact, 638 tests green) at the user's instruction; `WorkingSunday` was force-set
to `d57bcd4` too. Old pre-replace main tip was `900c9cb` (recoverable). Since then
all work stacked cleanly to `ab9f5f6`. Lesson: verify `harness/*.py` exists and the
suite imports before/after any git op, and never `git pull` `WorkingSunday` without
checking it hasn't been force-moved under you.

## 6. How to verify key things quickly

```bash
cd harness
python -m unittest discover -p "test_*.py"                     # full suite (~677, OK)
python -m unittest test_access_control_gate test_global_throttle \
  test_js_endpoint_extractor test_crawler test_iterative_agent  # this session's units
# live sanity (targets must be up):
python -c "import asyncio,global_throttle,crawler; global_throttle.configure(0); \
print(len(asyncio.run(crawler.crawl('http://localhost:3000/',allowed_hosts=['localhost'],max_pages=8)).endpoints))"
```
Config flags that gate the new capabilities (all default OFF):
`coordinator.cloud_primary`, `adaptive_respin.enabled`, `throttle.max_requests_per_second`.
The iterative agent (F4) is a module, not yet wired to the orchestrator or config.
