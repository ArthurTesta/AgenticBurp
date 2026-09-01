# Session 4 plan — close the teardown's gaps behind one scored number

**For the next coding agent.** This is an *executable* plan, not a status doc. It
reconciles the review artifact "Where the Harness Stands" (a **session-2** view —
it cites `SESSION_HANDOVER_2.md`) with the **real post-session-3 state** verified
against the working tree on 2026-09-01. Read `SESSION_HANDOVER_3.md` first for
current-state detail; read this for what to *do*.

The one thing to internalize: **the review was right about the goal and out of date
on the state.** Four of its five demands are already partial or built-but-off. The
job is *consolidate and prove*, not *rebuild*. Everything below serves one
deliverable: **one reproducible precision/recall-per-OWASP-category number, gated
in CI.** Until it exists, every "N found" is unvalidated.

---

## 0. Operating rules — READ BEFORE TOUCHING ANYTHING

These each cost prior sessions real time. Violating them wastes yours.

- **Branch `WorkingSunday`.** Run the suite before you trust anything and after
  every change: from `harness/`, `python -m unittest discover -p "test_*.py"` →
  expect **OK, 889 tests**. Keep it green; a task isn't done if the suite is red.
- **CONFIG-TOGGLE TRAP.** `harness/config.yaml` in the working tree has two toggles
  ON that are OFF in the repo (`iterative_agent.enabled`, `engagement.auto_escalate`).
  **Any `git add harness/config.yaml` sweeps those ON toggles into your commit.**
  Task **T0.1** removes this trap permanently — do it first. Until then: set both to
  `false`, commit, re-set to `true` locally.
- **Never read** any `*ANSWER_KEY*` file, `testing/blind-target-2/app.py`, or
  `testing/blind-test-kit/target/app.py`. Reading them **invalidates the blind
  eval** — the only uncontaminated signal this project has.
- **Restart the server after ANY Python change** (`server.py` runs uvicorn with
  `reload=False`). Symptom of forgetting: a new endpoint 404s while `/health`
  works. Restart procedure is in `SESSION_HANDOVER_3.md` §6.
- **Warm `*_cache.db` replays old analyses in ~0.1s.** For a *real* re-run,
  delete/rename the cache DB first, or you're scoring stale output.
- **Java can't compile here** (no JDK/Gradle/Montoya). Self-review Java against
  existing patterns; the real signal is the user's `gradle shadowJar` in Codespace.
  No task below is blocked on Java.
- **Commit discipline:** one logical commit per task, real messages, never squash.
  The green suite is the gate.

---

## Task overview (do in order; 0 and 1 first, together)

| ID | Task | Serves | Effort | Needs |
|---|---|---|---|---|
| T0.1 | Kill the config-toggle trap (config.local.yaml overlay) | #4 + hazard | S | — |
| T0.2 | Untrack the jar + 2 DBs, add `.gitignore` | #4 | S | — |
| T0.3 | Pin + complete dependencies | #4, reproducibility | S | — |
| T1.1 | The one end-to-end smoke test (stub Ollama) | #2 | S | — |
| T2.1 | `score.py` — one command, P/R/F1 per OWASP category | #1 | L | T0.3 |
| T2.2 | Run `blind-target-2` to completion; record scorecard | #1 | M | T2.1 |
| T2.3 | Publish the scorecard + reproduce command | #1 | S | T2.1–2.2 |
| T3.1 | Flip multi-request on for high-value classes, measured | #3 | M | T2.1 |
| T4.1 | Make coordinator fail-open loud + counted | #5 | M | T1.1 |
| T4.2 | Audit ~26 broad `except`; first-class routing model | #5 | M | T4.1 |
| T5.1 | CI: fast tier (suite + smoke) + scored tier with floor | #4 locks #1 | M | T1.1, T2.1 |
| TB.1 | Campaign report (engagement-aware) — parallel, lower prio | backlog | L | T0.* |

S ≈ ½ day · M ≈ 1–2 days · L ≈ 2–4 days.

---

## Phase 0 — Stop the bleeding (do first, ~½ day total)

### T0.1 — Kill the config-toggle trap
- **Goal:** make it *impossible* to leak the live ON toggles into a commit.
- **Files:** `harness/config.yaml`, the config loader (find it:
  `grep -rn "config.yaml\|yaml.safe_load\|safe_load" harness/*.py`), `.gitignore`.
- **Steps:**
  1. Locate where `config.yaml` is loaded into the orchestrator.
  2. After loading `config.yaml`, if `harness/config.local.yaml` exists, deep-merge
     it over the base (local wins). Keep the merge small and defensive.
  3. Move the two live toggles out of `config.yaml` (leave them `false` there) into a
     new `harness/config.local.yaml` holding only the overrides
     (`iterative_agent.enabled: true`, `engagement.auto_escalate: true`).
  4. Add `config.local.yaml` to `.gitignore`.
- **Acceptance:** `config.yaml` has safe defaults (all active modes `false`);
  `config.local.yaml` is gitignored and carries the local overrides; the running
  server still reports the ON flags (verify command in HANDOVER_3 §6).
- **Verify:** `git status` never shows `config.yaml` as modified after a normal run;
  the flag-check one-liner still prints `True True False`.
- **Commit:** `Config: overlay config.local.yaml so live toggles can't leak into commits`

### T0.2 — Untrack tracked binaries
- **Goal:** stop tracking build output and runtime DBs.
- **Files:** `.gitignore`; untrack `burp-llm-harness-extension-0.1.0-all.jar`,
  `harness/harness_cache.db`, `harness/harness_state.db`.
- **Steps:** `git rm --cached <each>` (keep them on disk); add glob rules
  (`*.jar`, `harness/*.db`) to `.gitignore`. Confirm no code hard-depends on the
  DBs being present at those paths at import time (they're created on demand).
- **Acceptance:** `git ls-files | grep -Ei '\.(jar|db)$'` returns nothing; the suite
  still passes; the server still starts (DBs re-created).
- **Commit:** `Repo: untrack built jar and runtime SQLite DBs`

### T0.3 — Pin and complete dependencies
- **Goal:** a reproducible environment so the score is reproducible.
- **Files:** `harness/requirements.txt` (currently `>=` floors: fastapi, uvicorn,
  httpx, pydantic, pyyaml), `harness/requirements-proxy.txt`, new
  `harness/requirements-dev.txt`, new `harness/requirements.lock` (or `-lock.txt`).
- **Steps:**
  1. Add the missing runtime dep **playwright** (the A2 browser XSS validator needs
     it) plus anything else imported-but-unlisted (grep top-level imports in
     `harness/*.py` and `harness/validators/*.py` against the requirements).
  2. Pin exact versions (`==`) and generate a lock (`pip freeze` in a clean venv, or
     `pip-compile`). Keep `requirements.txt` human-readable, add the fully-pinned lock.
  3. `requirements-dev.txt`: test/lint deps used by CI (e.g. the unittest run needs
     nothing extra today — list what T5.1 will actually invoke).
- **Acceptance:** a fresh venv from the lock runs the full suite green; playwright is
  present so the browser validator imports.
- **Commit:** `Deps: pin versions + lock, add playwright and dev requirements`

---

## Phase 1 — The one smoke test (do first, alongside Phase 0, ~½ day)

### T1.1 — End-to-end detection smoke test against a stub Ollama
- **Goal:** the single test that catches "detection silently zero" — the failure
  that hit **three times** while 889 mocked tests stayed green.
- **Why here and not in the 889:** those mock at the wrong layer (plumbing). This one
  runs the **real `analyze()` pipeline** and asserts a *known finding on a known
  fixture*, with only the LLM boundary stubbed.
- **Files:** new `harness/test_smoke_detection.py`; reuse the canned-JSON pattern
  from `testing/test-target/detection_fixture.py` (it already caches real agent
  output keyed by `(exchange, agent, model, prompt_version)`).
- **Steps:**
  1. Build a stub Ollama client that returns canned JSON per agent (borrow real
     cached outputs from the detection fixture so the canned answers are realistic).
  2. Feed one known-vulnerable exchange (e.g. a SQLi exchange already labeled in the
     test-target corpus) through the real `analyze()` with the stub injected.
  3. Assert the expected vuln class appears in the response findings at/above the
     confidence gate — and assert the **fail-open counter did not fire** (ties to
     T4.1; if that metric doesn't exist yet, assert on findings only and add the
     counter assertion in T4.1).
  4. Make it fast (no network, no GPU) so CI runs it on every push.
- **Acceptance:** test passes now; **flip one agent's canned output to empty and it
  goes red** (prove it actually guards detection, not plumbing).
- **Verify:** `cd harness && python -m unittest test_smoke_detection`
- **Commit:** `Test: end-to-end detection smoke test vs stubbed Ollama (kills green-tests-dead-pipeline)`

---

## Phase 2 — The scored number (THE deliverable, ~2–4 days)

> Reality check on environment: a *full* fresh scored run needs a local Ollama +
> GPU (~2h) and the target apps running — that may be the **user's box**, not here.
> Structure the work so `score.py` produces a **real per-category score from the
> existing cached fixture without a GPU**, and the full/blind runs are a documented
> command the user (or a GPU runner) executes. Don't fake a number; build the thing
> that computes it and run what the environment allows.

### T2.1 — `score.py`: one command → precision/recall/F1 per OWASP category
- **Goal:** collapse the scattered eval runners into one scorer with a stable output.
- **Existing runners to unify (reuse, don't rewrite their harness logic):**
  `testing/test-target/bench.py` + `detection_fixture.py` (cached, TP-recall/TN-FP),
  `testing/blind-target-2/run_real_analysis_v2.py`, `testing/juiceshop-full-run/run_harness.py`.
- **Files:** new `testing/score.py` (or `harness/score.py` if it should ship);
  a small `corpus` abstraction so a run is `(corpus, model)`.
- **Steps:**
  1. Define a corpus record: exchange(s) + gold label(s) mapped to an **OWASP
     category** (A01…A10). Adapt the existing `TP*/TN*` labels into this schema.
  2. Emit per-category **precision, recall, F1, and n**, plus an overall line, as
     JSON + a readable table. Record the **model id + digest** and **corpus hash** in
     the output header so a number is always attributable.
  3. Pin the model (read from config; fail loudly if the pinned model isn't the one
     serving). Reuse the fixture cache so re-runs are fast.
- **Acceptance:** `python testing/score.py --corpus test-target --from-cache` prints a
  per-OWASP-category table from the existing fixture, with model+corpus provenance,
  reproducibly (same input → same number).
- **Commit:** `Eval: score.py — unified precision/recall/F1 per OWASP category`

### T2.2 — Run `blind-target-2` to completion
- **Goal:** a second *uncontaminated* data point (Juice Shop is training-contaminated
  — the repo's own `testing/README.md` says so — so it can't be the headline).
- **State:** `blind-target-2` is barely run (its `exports/` holds one 80-byte CSV).
- **Steps (respect the blind rules — do NOT read the app or answer key):**
  1. Start the target (`cd testing/blind-target-2 && python app.py`, :5002) — start
     it, don't read it.
  2. Enumerate over HTTP only (`discover_endpoints.py`), capture exchanges, run the
     harness (`run_real_analysis_v2.py`) with a **cold** cache.
  3. Score the output with `score.py` against the held-out key **without opening the
     key file** — score.py loads it, you don't read it.
- **Acceptance:** a per-category scorecard exists for blind-target-2 from a cold run
  on the pinned model; the blind rules were not violated.
- **Commit:** `Eval: complete blind-target-2 scored run (cold cache, pinned model)`

### T2.3 — Publish the scorecard
- **Goal:** the defensible number, with caveats, that the field comparison hinges on.
- **Files:** `testing/SCORECARD.md` (or extend `DETECTION_BENCH_METHODOLOGY.md`).
- **Steps:** table of P/R/F1 per OWASP category for each corpus (test-target,
  blind-kit run-2, blind-target-2); model id+digest; n per cell; honest caveats
  (small n, single-pass variance, contamination note for Juice Shop); the exact
  one-line reproduce command.
- **Acceptance:** a reader can regenerate every number from the command shown.
- **Commit:** `Docs: publish scorecard with per-category P/R/F1 and reproduce command`

---

## Phase 3 — Prove multi-request earns its default (~1–2 days) · needs T2.1

### T3.1 — Flip engagement mode on for high-value classes, measured
- **Goal:** turn the *built-but-off* multi-request capability into the **default for
  IDOR / authz / business-logic**, and keep only what the score justifies.
- **Files:** `harness/config.yaml` defaults (via the T0.1 overlay), the routing that
  decides single-exchange vs engagement path.
- **Steps:**
  1. Baseline: `score.py` with engagement modes OFF (current default).
  2. Turn on `iterative_agent` / role-crawl / cross-identity for the high-value
     classes; re-score.
  3. Keep a flip **only if recall rises without unacceptable FP/cost regression**;
     record Δrecall and Δcost in the commit.
- **Acceptance:** a documented before/after per-category delta; new defaults reflect
  the measured winners; suite green.
- **Commit:** `Engagement: default multi-request for IDOR/authz/logic (Δrecall +X, FP bounded)`

---

## Phase 4 — Make silent failure loud (~1–2 days) · needs T1.1

### T4.1 — Count and surface the coordinator fail-open path
- **Goal:** "quietly finding nothing" is this project's signature failure. The
  coordinator "fails open to all 36 agents" on a bad routing response — safe for
  recall but silent, unmetered, and the most expensive path.
- **Files:** the coordinator/routing module; `harness/activity_feed.py`.
- **Steps:** increment a named counter and publish an activity event every time the
  fail-open path fires; expose it on `GET /activity` and/or a metrics field; add the
  assertion back into T1.1's smoke test.
- **Acceptance:** a forced bad routing response produces a visible, counted event;
  the smoke test asserts the counter.
- **Commit:** `Observability: make coordinator fail-open loud and counted`

### T4.2 — Audit broad excepts; first-class routing model
- **Goal:** convert log-and-drop swallowing into counted/surfaced; let routing use a
  stronger/cloud model where privacy allows.
- **Steps:** grep `except Exception` in `harness/` (~26 sites); for each, either
  narrow it, count it, or surface it — no silent drops on the detection path.
  Make routing-model selection first-class (config + `/settings`), building on the
  existing `cloud_primary` and `set_coordinator_model`.
- **Acceptance:** no silent `log-and-drop` remains on the analyze/route path; routing
  model is switchable at runtime and recorded in output provenance.
- **Commit:** `Robustness: surface swallowed exceptions; first-class routing model choice`

---

## Phase 5 — Lock the number in CI (~1–2 days) · needs T1.1, T2.1

### T5.1 — GitHub Actions: fast tier + scored tier with a floor
- **Goal:** the number can't silently regress.
- **Files:** new `.github/workflows/ci.yml`; `pyproject.toml` (packaging).
- **Steps:**
  1. **Fast tier** (every push/PR): install from the T0.3 lock, run the 889 suite +
     the T1.1 smoke test. Fails on any red.
  2. **Scored tier** (manual `workflow_dispatch` / nightly — it needs a model runner;
     document the self-hosted/GPU requirement): run `score.py`, **fail if recall
     drops below the published floor** from T2.3.
  3. Add `pyproject.toml` so the harness is installable; pinned deps make it
     deterministic.
- **Acceptance:** fast tier green on push; deliberately breaking detection turns the
  scored tier red.
- **Commit:** `CI: fast tier (suite+smoke) on push, scored tier with recall floor`

---

## Track B (parallel, lower priority) — Campaign report · needs T0.*

### TB.1 — Engagement-aware report
- **Goal:** `report_generator.py` predates the session-3 engagement arc and is
  per-exchange. Build the report that renders the *engagement*: surface coverage, the
  role×URL access matrix, the escalation/task-graph chain (finding → identity gained
  → new surface → finding), results grouped by identity. It is the natural renderer
  of `task_graph.py` + `engagement.py`.
- **Not on the critical path to the score** — anyone *not* on the scoring work can do
  this in parallel; it waits behind Phase 0.
- **Acceptance:** given a persisted `EngagementState`, produces a report showing
  coverage + access matrix + at least one escalation chain, grouped by identity.
- **Commit:** `Report: engagement-aware campaign report (renders task graph + access matrix)`

---

## Definition of done for this plan
1. `git ls-files` shows no jar/DB; committing `config.yaml` cannot flip a mode.
2. `python -m unittest test_smoke_detection` guards real detection (goes red if a
   detector returns nothing).
3. `python testing/score.py …` prints per-OWASP-category P/R/F1 with model+corpus
   provenance, reproducibly; `SCORECARD.md` publishes it.
4. Multi-request defaults reflect a **measured** recall gain.
5. The coordinator fail-open path is loud and counted.
6. CI is green on push and red when recall drops below the floor.

## First sitting (recommended)
Do **T0.1 → T0.2 → T0.3 → T1.1** in one sitting — all small, all pure de-risking,
all independent of a GPU. Then commit the week to **T2.1–T2.3**; Phases 3–5 fall out
of the number existing.
