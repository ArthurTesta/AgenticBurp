# Session handover 4 — scored evaluation, FP reduction, and the Autorize-style cross-identity validator

Same discipline as SESSION_HANDOVER_3.md: every claim is either **verified** this
session by the command/test shown, or marked **reported/not-run**. This is the
**authoritative current-state doc**; SESSION_4_PLAN.md is the task plan (its
progress log covers only Phases 0–2, this file supersedes it for everything after).
Read this first.

---

## 0. Read first — state, environment, hazards

- **Branch:** `WorkingSunday`. **HEAD:** `dc35071`, **pushed** to `origin/WorkingSunday`
  (`git rev-parse origin/WorkingSunday` == HEAD, verified). `main` untouched.
- **PR into `main`:** open it at
  `https://github.com/ArthurTesta/AgenticBurp/compare/main...WorkingSunday?expand=1`
  (`gh` is not installed here and no token is in-env, so it was not opened
  programmatically).
- **Suite green:** from `harness/`, `python -m unittest discover -p "test_*.py"`
  → **OK, 901 tests** (verified). Run before trusting anything, after every change.
- **Started at `ac302bd`** (end of session 3). 19 commits added (`git log --oneline
  ac302bd..HEAD`).

### HAZARDS

1. **Config-toggle trap — now STRUCTURALLY FIXED (commit `1d3c3cd`).**
   `server.load_config()` deep-merges an optional **git-ignored**
   `harness/config.local.yaml` over `config.yaml` (local wins). Live active-mode
   toggles (`iterative_agent.enabled`, `engagement.auto_escalate`, and now
   `validators.cross_identity.enabled` if you run it) live in `config.local.yaml`;
   `config.yaml` stays at safe defaults. A `git add harness/config.yaml` can no
   longer leak them. **Do not commit `config.local.yaml`** (it's gitignored).
2. **Cross-identity credentials are IN-MEMORY ONLY** (`identity_headers.py`).
   Supplied via `POST /identities/session-headers`; never persisted/logged. A
   restart clears them (by design — the harness never stores tokens).
3. **Live test apps:** PixelMart (test-target) on `:5001`, helpdesk (blind-target-2)
   on `:5002`. PixelMart rebuilds its DB on start; restart it fresh for order-based
   tests (order ids reset).
4. **Do NOT read** `*ANSWER_KEY*` or a blind target's `app.py` (invalidates the
   blind eval). test-target labels are embedded in each exchange's `label` field
   (`TP3: safe self-profile…`), so you rarely need the answer key.
5. **Java can't compile here** (no JDK/Gradle). The **Burp UI toggle for
   cross_identity** is the main un-done Java piece (see §4).
6. **Server restart after any Python change** (`reload=False`); warm `*_cache.db`
   replays old analyses.
7. **The detection fixture is AGENTS-ONLY** (`detection_fixture.py` calls
   `agent.run` directly). It BYPASSES the pipeline gates + validators. `score.py`
   now replicates the `access_control_gate` on the fixture (commit `e07a6c6`), but
   NOT the validators/cross-identity. A full-pipeline number needs a live
   `analyze()` run — see the pattern used this session (scratch `full_retest.py`).

---

## 1. What was built (all committed + pushed)

- **Phase 0 — release discipline.** config.local overlay + untrack jar/DBs (`1d3c3cd`);
  pin deps + `requirements.lock` + `requirements-dev.txt` (`becabd2`).
- **T1.1 — end-to-end detection smoke test** vs a stubbed Ollama, with a negative
  control (`5650aae`). Class-scoped DB isolation (do NOT mutate `store._DB_PATH` at
  import — it leaks into the whole suite; use setUpClass/tearDownClass).
- **T4.1 — coordinator fail-open counted** (`coordinator.fail_open_stats`) + activity
  feed (`f68054a`).
- **T5.1 — CI fast tier** (suite + smoke + score self-test) + `pyproject.toml`
  (`6648690`). Scored tier is stubbed/disabled (needs a GPU runner).
- **T2.1 — `testing/score.py`**: per-OWASP precision/recall/F1, `--conf`/`--min-severity`
  operating-point gates, `--fail-under-recall` (`851eefc`, `90d3074`).
- **T2.2/T2.3 — SCORECARD.md** from a real fixture run (`81df8d1`).
- **FP reduction:** severity operating point (`90d3074`); `misconfig`/`supply_chain`
  precision fixes (`03bd785`); **lane discipline TRIED and REVERTED — measured worse**
  (`6e5733f`, see §6); Fix A: gate caps severity + score.py applies the gate (`e07a6c6`).
- **Cross-identity (Autorize-style) validator** — the centerpiece (`1feb1a7`, `dc35071`):
  `validators/cross_identity_validator.py`, `identity_headers.py`,
  `POST /identities/session-headers`, registry + orchestrator reject-downgrade,
  `validators.cross_identity` config toggle (default off).
- **Full re-test + corrections** (`fb77577`): fixed a `score.classify` taxonomy bug
  (IDOR→None) that understated recall; corrected earlier claims (see §6).
- **#2 blind-target-2** full-pipeline run recorded (`b6866be`).

---

## 2. Current metrics (see `testing/SCORECARD.md` for the full breakdown)

- **test-target (agents-only fixture + gate, sev≥medium):** precision **0.476**,
  recall **0.909**, A01 recall **1.0** (verified: `cd testing && python score.py
  --corpus test-target --from-cache --min-severity medium`).
- **Cross-identity (live PixelMart):** CONFIRMS real IDOR (TP3/TP4/TP11 @ 0.91,
  `finding.confirmed=True`); the TN3 self-profile FP is fixed (skips token-relative
  endpoints). Verified live + 8 unit tests (`test_cross_identity_validator`).
- **blind-target-2 (full pipeline, PRE-fixes, `b6866be`):** recall 2/2, but precision
  collapses on hard negatives and **validators confirmed 0/10** — the confirmation
  leg did not backstop precision. NOT re-run with cross_identity on (see §4).
- **Caveats:** small n (11 TPs), single-pass variance; the full-pipeline fresh run
  (precision 0.286) vs cached fixture (0.476) gap is run-to-run agent variance, not
  a regression.

---

## 3. The cross-identity validator — how to use it

1. **Enable:** `validators.cross_identity.enabled: true` + `validators.active_enabled:
   true` (in `config.local.yaml` locally). GET-only, scoped to `server.allowed_hosts`.
2. **Supply identities** (per host, in-memory): `POST /identities/session-headers`
   with `{host, name, headers, role}` — another identity's real session headers.
3. **Behavior:** fires on access-control findings whose URL has an **object
   identifier** (`has_object_identifier`; token-relative endpoints like `/me` skip).
   Replays as each identity + anon, runs `identity_compare.evaluate`
   (`authorization_boundary_compare`). CONFIRMED → `finding.confirmed` + confidence
   boost; deterministic REJECT → downgrade (a validator may lower a finding ONLY on
   this active, non-LLM rejection — see `orchestrator._validate_findings`).

---

## 4. Remaining work (ranked)

- **Burp UI toggle (Java — you compile).** Add to `HarnessToolsPanel`: a checkbox
  for `cross_identity` and a small form to paste another identity's session headers,
  POSTing to `/identities/session-headers`. The config toggle + endpoint exist; only
  the panel wiring is missing. THIS is the main Java follow-up.
- **Clean A/B** for cross-identity's net precision effect: same corpus, same run,
  cross_identity on vs off (the full-pipeline vs fixture comparison this session was
  muddied by fresh-run variance).
- **Re-run blind-target-2 with cross_identity on** to show the REJECT→downgrade
  (precision) benefit on real secure controls — needs fresh helpdesk creds for
  `:5002` (the captured tokens may be stale).
- **Scored-tier CI** on a GPU runner (the disabled job in `.github/workflows/ci.yml`).
- **`has_object_identifier` slug edge:** non-numeric/non-uuid ids (e.g. `/users/alice`)
  are not recognized and skip. Rare; the tester can drive `role_crawl` there.
- **The broader precision problem is agent over-firing** (many agents fire per
  exchange). See SCORECARD "remaining FPs" — a per-component advisory cap for the
  Werkzeug-style dep noise, and agent-level precision work, are the next levers.

---

## 5. How to verify / operate

```bash
cd harness && python -m unittest discover -p "test_*.py"     # full suite (901, OK)
cd harness && python -m unittest test_cross_identity_validator test_smoke_detection
cd testing && python score.py --corpus test-target --from-cache --min-severity medium
```
Rebuild the detection fixture after editing an agent's prompt (prompt-hash-keyed —
only the changed agent re-runs; ~model time on the GPU box):
```bash
cd testing/test-target && python detection_fixture.py build
```
Live cross-identity check: start PixelMart (`cd testing/test-target && python app.py`),
log in two users, `identity_headers.set_identity(...)`, construct an `HttpExchange`
for an object-scoped GET, call the validator (see this session's demo pattern).

---

## 6. Corrections made this session (so the next agent does NOT repeat them)

- **`score.classify` had a taxonomy bug** — `"Insecure Direct Object Reference"`
  mapped to `None`, understating recall. Fixed (`fb77577`). Consequence: earlier
  claims that "single-exchange MISSES TP4 IDOR" and "cross-identity lifts A01 recall
  1/3→2/3" were **scoring artifacts** — the agents DID detect those IDORs.
  Cross-identity's real, demonstrated value is **CONFIRMATION (guess→proof)**, not
  raw recall.
- **Lane discipline** (a shared `base_agent` "report only your own class" rule) was
  built, measured (full rebuild), and **REVERTED — it made FPs worse** (11→15) and
  the 8B model didn't follow it. Do not retry (`6e5733f`).
- **"Validators kill FPs in the real pipeline" was WRONG.** Validators CONFIRM but do
  not SUPPRESS unconfirmed findings; the blind run confirmed 0/10. The "deterministic
  confirmation leg" does not currently backstop precision (matches the teardown).
- **The detection fixture ≠ the shipped pipeline** (agents-only, bypasses gates +
  validators). Fixture scores understate the pipeline's precision on access-control
  (the gate is now replicated in score.py, the validators/cross-identity are not).
