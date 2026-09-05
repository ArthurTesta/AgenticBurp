# Current state

The single rolling per-session delta. Stable context (architecture, hazards, environment,
file map) is in [`CLAUDE.md`](CLAUDE.md) — read that first, then this.

**Update this file in place at session end. Do not create a new numbered handover.**

---

## State (as of session 13)

- **Branch:** `WorkingSunday`. **HEAD:** `233eab9` (session-12 handover). Session 13 has
  **one uncommitted code fix staged in the working tree** (see below) — not yet committed
  (the user drove a run, not a commit).
- **What session 13 did:** ran the roadmap's outstanding **fresh live max-coverage run** end
  to end against VulnCorp (2.46 h, Ollama + Docker + sqlmap-in-container, all active legs on),
  re-measured recall with the new `recall_benchmark`, and — in the process — **found and fixed
  a real pipeline crash** the mocked suite had hidden.
- **PIPELINE BUG FIXED (the #0 failure mode, again):** `attribution.py` (Phase 3.5, added
  *after* the session-11 run) writes `finding.shape_inconsistent` and
  `finding.original_vulnerability_class`, but the `Finding` pydantic model declared **neither**
  field, so **every `analyze()` call that hit a shape-inconsistent (or leg-relabelled) finding
  raised `ValueError: "Finding" object has no field …`** and lost that exchange's findings.
  `test_attribution` passed only because it exercised **dicts**, never a real `Finding`. Fix:
  added both fields to the model (`harness/models.py`) + a new `PydanticFindingTests` class in
  `test_attribution.py` that runs both attribution passes against real `Finding` objects (the
  negative control that was missing). **Suite now 1161 OK** (1159 → 1161). This bug was live in
  the pipeline from session 12 until now; the session-11 run predates Phase 3.5 so its numbers
  are unaffected. **This one-file model change is the only uncommitted harness code** — ready to
  commit; not committed pending the user's go-ahead.
- **Config untouched:** `harness/config.yaml` still at safe defaults; `config.local.yaml`
  unchanged. The run built its config **in memory** (never touched on-disk config) — hazard #1
  intact.
- **browser_xss NOT promoted.** The run exercised the leg; XSS was *detected* on 5 endpoints
  but all non-HTML sinks (JSON comment API, uploads, XML import), so browser_xss correctly
  confirmed **0** — it stays `smoke_only`. `LIVE_VERIFIED_MARKERS` unchanged. (The task was
  "promote where a run confirms it"; this run did not, so no promotion — honest outcome.)
- **Environment verified:** Ollama `qwen3:8b`, Docker + `harness/sqlmap:1.10.9`, host Chromium
  all live this session. VulnCorp was found in a **DB-polluted** state from prior mutating-replay
  runs (alice resolving to admin; a stored `curl` OOB payload in a JWT `org_id`) and was
  restarted to a clean seed before the run (hazard #5). It is left running (and re-dirtied by
  this run's PASS-2 mutating replay) — restart it for the next clean run.

### Session-13 measured run (VERIFIED) — the new empirical truth

2.46 h run vs VulnCorp, fresh cache/state DBs, all active features. Runner + ground truth +
offline scorer live in `testing/vulncorp-helpdesk/maxrun/` (`run_maxcov_recall.py`,
`vulncorp_ground_truth.py`, `score_recall.py`; outputs `maxcov_results_recall_full.json`,
`recall_final_recall_full.md`). Exhaustive: PASS 1 over **all 37** captured exchanges (session
11 used 17); PASS 2 `investigate_engagement` with wider budgets (max_nodes 40→60, step_budget
8→10, probes 6000→12000, chains 2→3).

- **394 fused findings → 32 raw confirmed → 22 unique confirmed.** vs session-11's
  **17 confirmed** — up, and the pipeline ran crash-free across all 37 + PASS 2.
- **Confirmed classes (6):** SQLi (`/api/login` + `/api/tickets/search`, sqlmap), IDOR /
  broken-object-access (`/api/tickets/{id}`, `/api/reports/{id}`, `/api/tickets/{id}/comments`,
  cross_identity), JWT alg:none forgery (jwt_forge, across 5 authed endpoints), XXE
  (`/api/tickets/import`), path_traversal (`/uploads/{id}`), **+ NEW: JWT signing-key disclosure
  on `/api/admin/debug` CONFIRMED via the Phase-3.1 `secret_disclosure` leg (critical)** — this
  was the top *unconfirmed* item in session 11 (conf-1.00, no leg); now proven.
- **Path-matched recall vs the 13 documented endpoint-known planted vulns:** **8/13 confirmed
  (7 earned via the intended leg, 1 "lucky"), 4 detected-unconfirmed, 1 missed.** (Effectively
  9/13 — GT12 `/api/admin/debug` disclosure is confirmed but under the `jwt` class, not the
  `information_disclosure` class the ground truth anchored it to, so it scored "detected".)
- **Discovery breadth improved: 12 → 21 endpoints** in the PASS-2 worklist (now finds `/.env`
  via the Phase-0.2c sensitive-file wordlist, `/uploads`, `/api/tickets/{id}/attachments`,
  `/api/tickets/{id}/assign`). But the **cmd-inj / ssti / open-redirect (V23/V24/V30) and the
  SSRF integrations feature are STILL not reached** — the one `missed` (SSRF) and the three
  frontier classes remain a discovery gap on agent-role feature surface, exactly as session 11.
- **Detected-but-not-confirmed:** mass-assignment on `/api/account/profile` + `/register` (the
  Phase-3 **`sequence` leg RAN and returned `not_confirmed`** — the injected fields did not
  persist across an independent re-read; either the endpoints aren't mass-assignable that way or
  the re-read path needs work — a real follow-up, not a crash); BFLA `/api/admin/users`.

### Session-13 leg build-out (committed on `WorkingSunday`, suite 1178 OK)

Operator-directed push to close the missing-class gaps found by the run. Each new/
changed leg ships with a disposable fixture TP + a matched negative control + a
`test_leg_live_verification` case in the same commit (the freeze-policy discipline,
see `LEG_VERIFICATION.md`). Commits on top of `233eab9`:

- `0e237f7` — the attribution/`Finding` crash fix (was uncommitted; now in).
- `3d37935` — **sequence/mass-assignment generalised**: recursive nested-response
  detection + authority-named schema-derived candidate fields (the session-13 miss
  was top-level-only + fixed-name-only).
- `110f71a` — **active deserialization leg** (`deserialization_oob`): benign OOB
  pickle beacon proving RCE on a `pickle.loads` sink; no gadget chain.
- `f920d5d` — **auth-mechanism legs** (`auth_sequence`): session-fixation /
  weak-password / username-enumeration multi-request flows.
- `be1c5b9` — **stored/second-order XSS leg** (`stored_xss`): plant→independent-
  HTML-render; the plant→observe primitive for second-order flows (task 4 + 6).
- `5334549` — **discovery breadth (task 2b)**: sweep active discovery AS each
  distinct-feature role (union routes) so agent/manager-only endpoints are reached,
  + injection-prone feature vocabulary. This is the lever for the frontier legs.
- `3088d70` — **JWT `kid` key-confusion** (V9) added to `jwt_forge`.

All wired into the graph `_confirm` dispatcher, shape-preconditions where
applicable, the `ValidatorRegistry`, and `confirmation_gate` CONFIRMABLE +
LIVE_VERIFIED markers; safety-gate greps updated for each new gate-routed validator.

**Deferred (architectural decision needed) — see `LEG_DECISIONS.md`:** verb-tamper
(V15), CSRF (V32), file-upload (V33), rate-limit (V4), reset-token entropy (V3),
and explicit second-order-SQLi chain composition (V22). Each is blocked on a
safety/precision CHOICE, not effort; the doc gives the oracle, the decision, and a
recommended safe implementation for each.

**Pending:** the fresh max-coverage RE-RUN with all the above (in progress at
handover) to measure the recall delta vs the 9-confirmed / 6-class baseline.

## State (as of session 12)

- **Branch:** `WorkingSunday`. **HEAD:** `e313db0` (session-12; this handover commits on top).
  Session-12 landed **the entire improvement roadmap that is doable on this box**: Phase 0
  (all) + Phase 1 (1.1–1.4) + Phase 2 (+ all remaining smoke_only legs live-verified) + Phase 3
  (all) + Phase 3.5 + Phase 4 (cloud-coordinator seam) + Phase 5 (discovery soft-404 hardening).
  `harness/config.yaml` still carries safe defaults — session 12 flipped **no** toggle (Phase 4
  added `coordinator.cloud_reasoning: false`, default-off); `config.local.yaml` (git-ignored)
  still holds the live-ON toggles.
- **Pushed state:** `origin/main` and `origin/WorkingSunday` kept fast-forwarded to session-12
  work (clean FF, no merge commit; the untracked `testing/` answer-key artifacts stayed local).
  `main` == `WorkingSunday`.
- **Suite green (Python):** from `harness/`, `python -m unittest discover -p "test_*.py"` →
  **OK, 1159 tests** (1049 → 1159 across the session; every new test carries a negative
  control). NOTE: `test_hardening.py` is **pytest-only** (module-level `def test_*`, outside
  the `unittest discover` gate) — run `python -m pytest test_hardening.py` separately; it is
  green (7 passed), and session 12 fixed a pre-existing breakage in it (see 1.2 below).
- **Still uncommitted (deliberately left):** this file's session-11 edits (now folded into
  session 12), and the untracked `testing/` run artifacts. Everything in `harness/` that
  session 12 touched is committed.
- **Java compiles + jar built:** the #7 Burp changes were compiled clean and packaged into
  `burp-llm-harness-extension-0.1.0-all.jar` at the maintainer's `gradle` build (confirmed
  off-machine; no JDK here — hazard #6). The jar is git-ignored (`.gitignore` `*.jar`), so it
  lives at root for Burp to load and is not committed.
- **Environment verified:** Ollama `qwen3:8b` reachable; Docker up with `harness/sqlmap:1.10.9`;
  host chromium/playwright present. No host `javac` anywhere. (See CLAUDE.md § Environment.)

## What shipped this session (12) — roadmap Phase 0 + Phase 1 quick wins + Phase 3.5

Worked the improvement roadmap top-down, one item per commit, full suite green at each. All
verified by hermetic tests with negative controls (no live run this session).

- **Phase 0.1 — recall of discarded discovery hits** (`a752172`): `role_crawl` now RETAINS
  every substantive 2xx as an `HttpExchange` (`RoleCrawlResult.captured`, deduped by response
  content); `orchestrator.review_captured_exchanges` routes each through the full `analyze()`
  (chosen: full agent review, always on), folding findings into the engagement state. A body
  correctly access-scoped but itself leaking (secret/PII) is no longer dropped. Smoke test
  with the confidential-info negative control. NOTE: this commit also bundled pre-existing
  uncommitted work that was entangled in `orchestrator.py` — `confirmation_gate.py`(+test) and
  the `models.py`/`analyze()` `telemetry` field — to stay green on a clean checkout.
- **Phase 0.2 — discovery breadth** (`a9afc8f` a, `04ab6bf` b, `ba20ec4` c, `3b36206` d):
  (a) derive+sweep the namespaces an app actually exposes (crawler seeds threaded in), not a
  fixed prefix set; (b) generated action-suffixes (verb vocabulary + verbs harvested from the
  app and generalized); (c) sensitive-file wordlist (`.env`/configs/VCS/dumps + `*.bak`
  generation) distinct from REST nouns; (d) mine 2xx BODIES for path-like strings/URLs fed
  back as candidates (generalizing `js_endpoint_extractor`), re-deriving prefixes after.
- **Phase 0.3 — recall benchmark harness** (`5a80e09`): new `recall_benchmark.py` scores a run
  vs hand-authored ground truth as X/N confirmed / detected-unconfirmed / missed, with an
  earned-vs-lucky provenance verdict per confirmation. Adapters pull findings from an
  `AnalysisResponse` / `investigate_engagement` result. Never reads a blind answer key.
- **Phase 1.4 — fail-open telemetry** (`dc59593`): `/health` + new `/telemetry` expose the
  coordinator fail-open counters; tests assert they actually record on error/empty-dispatch
  and stay untouched on a clean route.
- **Phase 1.3 — blind-negative regression** (`182fd5e`): the 6 confirmed_secure controls ship
  ZERO medium+ findings through the real `apply_confirmation_suppression` gate (the precision
  floor). Fixture `testing/blind-target-2/blind_eval_exchanges.json` already tracked.
- **Phase 1.2 — host-dep passive-banner policy** (`8034b2d`): extracted `is_passive_banner` +
  `cap_passive_banner_severity` into testable `host_dep_dedup.py` (orchestrator calls them,
  behavior-identical); fixed a pre-existing pytest-only breakage in `test_hardening`.
- **Phase 3.5 — attribution reliability** (`24414ce`): new `attribution.py` — (a) relabel a
  CONFIRMED finding's class from the leg that proved it; (b) shape-consistency prior flags an
  unconfirmed label that contradicts the endpoint shape; (c) `chaining.detect` tags chains
  built on speculative (assumed/recalled, unconfirmed) inputs. Paired-fixture precision tests.
- **Phase 3 — stateful sequence leg** (`df038b2`): `validators/sequence_validator.py` — the
  missing A→verify-B shape. baseline GET → mutate (inject privileged fields) → verify GET;
  confirms only when a field persists across an INDEPENDENT re-read (catches silent
  mass-assignment the single-shot echo check misses). Registered + wired into the graph
  `_confirm`; gate-routed (needs allow_mutating_replay); on the safety-gate allowlist.
- **Phase 3.1 — secret-disclosure confirmation** (`8a2f6ba`): `secret_disclosure.py` — if a
  string in a response HMAC-verifies the signature of a JWT the client presents, that string
  IS the signing key (proof, not a guess; zero false positives). Emits a CONFIRMED critical
  finding, secret redacted; deterministic + offline. Wired into `analyze()` beside
  confidential_info.
- **Phase 3.3 — offline advisory snapshot** (`0b264f0`): `advisory_snapshot.py` — a file-backed
  known-vuln source (`github_advisories.snapshot_path`/`offline`) the client falls back to when
  the live GitHub lookup rate-limits/errors, or uses solely in offline mode. Token-less /
  air-gapped runs now get matches instead of only "error: rate_limited".
- **Phase 1.1 — leg-aware 3-state gate** (`4c25008`): `confirmation_gate` rebuilt. An
  unconfirmed finding is CONFIRMED / REFUTED (class has a LIVE-verified leg → low) / UNPROVEN
  (leg only smoke-verified → capped at medium, recall-preserving) / untouched (no leg).
  `LIVE_VERIFIED_MARKERS` is the seam; `apply_confirmation_suppression(live_verified_markers=…)`
  lets Phase 2 promote legs. Back-compat call site; blind-negative floor still green.
- **Phase 2 — leg live-verification** (`39c3f06`): `testing/leg-verification/vuln_fixture.py`
  (disposable vulnerable app) + `test_leg_live_verification` (real socket, real HTTP, no stubs)
  live-verify **ssti + open_redirect** → promoted into `LIVE_VERIFIED_MARKERS`. Operator runner
  `run_leg_verification.py` (all four in-band legs CONFIRMED on this machine, incl. browser_xss
  with real Chromium + path_traversal). `LEG_VERIFICATION.md` = the live-vs-smoke split (2.4) +
  freeze policy (2.1: no new legs until existing smoke_only ones are live-verified).
- **Remaining smoke_only legs live-verified** (`7cc6752`): the fixture gained real OOB + mass-
  assign endpoints; `test_leg_live_verification` now confirms **ssrf** (real server-side fetch →
  in-process collaborator), **command_injection** (real shell runs the injected `curl`; skipped
  when curl absent) and **sequence/mass_assignment** (real write → independent re-read). All
  promoted into `LIVE_VERIFIED_MARKERS`. Only **xss** stays smoke_only-by-default (browser_xss
  needs Chromium ON the harness; promote via the override where present).
- **Phase 4 — cloud-coordinator reasoning seam** (`78bb26e`): `coordinator.reasoning_model(config)`
  returns the cloud model for the iterative agent + critique when `coordinator.cloud_reasoning`
  is toggled on (else local). Distinct from `cloud_primary` (anonymized routing) — this sends
  REAL content off-host, so default-off, flipped via `POST /settings {"coordinator":
  {"cloud_reasoning": true}}`. In-memory toggle, shared config with the pipeline.
- **Phase 5 — discovery soft-404 hardening** (`e313db0`): `SurfaceDiscovery` calibrates a
  soft-404 signature from known-bogus paths and suppresses shape-matching responses whatever
  their status — so a 404→500 / catch-all no longer makes every probe look like a route. Keys
  off content/shape, not "not-404". Honest-404 and genuinely-varying apps calibrate nothing.

### Roadmap status / what's left
- **Done:** Phase 0 (all), Phase 1 (1.1–1.4), Phase 2 (**every confirmation leg live-verified
  except xss-by-default**), Phase 3 (all), Phase 3.5, Phase 4, Phase 5 (discovery hardening).
- **Remaining (needs off-box work, not code on this machine):**
  - **Burp panel** — the Cross-Identity + Discovery tabs need a JDK to compile (hazard #6);
    Java changes here are self-review only. Owner builds via `gradle shadowJar`.
  - **Target 404→500 catch-all patch** — the target owner's one-line fix (external dependency);
    re-baseline recall only after it lands. The harness side (soft-404 calibration) is done.
  - **Fresh live max-coverage run** — ✅ **DONE session 13** (see "Session-13 measured run"
    above): 22 confirmed / 6 classes (adds secret_disclosure), recall 8–9/13 on the documented
    endpoint-known set, discovery 12→21 endpoints. `browser_xss` was exercised but confirmed
    nothing live (XSS only on non-HTML sinks) so it **stayed `smoke_only`** — re-attempt the
    promotion only if a future run reaches an HTML-sink reflected XSS.
  - Optional: OOB re-check of `xxe` and a live-collaborator `browser_xss` promotion.
  - **Discovery still cannot reach the agent-role feature surface** (cmd-inj/ssti/open-redirect
    V23/V24/V30 + the SSRF integrations endpoint) — the recurring frontier gap; next lever is
    discovery of authenticated agent-role features, not another leg.
  - **`sequence` (mass-assignment) leg did not bite on VulnCorp** (ran, `not_confirmed` on
    profile/settings) — investigate whether those endpoints persist injected fields across an
    independent re-read, or whether the leg's verify path needs adjusting.
- **New modules this session:** `recall_benchmark.py`, `host_dep_dedup.py`, `attribution.py`,
  `validators/sequence_validator.py`, `secret_disclosure.py`, `advisory_snapshot.py`,
  `testing/leg-verification/*` + `test_leg_live_verification.py`, plus
  `orchestrator.review_captured_exchanges`. `LEG_VERIFICATION.md` is new top-level doc.
- **New modules this session:** `recall_benchmark.py`, `host_dep_dedup.py`, `attribution.py`,
  plus `orchestrator.review_captured_exchanges`. New tests: `test_smoke_phase0_capture_review`,
  `test_recall_benchmark`, `test_host_dep_dedup`, `test_attribution` (+ additions to
  `test_role_crawl`, `test_api_surface_discovery`, `test_coordinator`, `test_server`,
  `test_blind_negatives`).

## What shipped this session (11) — four new confirmation legs + graph-loop wiring

Closing the "confirmation as broad as detection" gap for six of the classes that had a
detector but no confirmation leg. All committed; suite 1049 OK; verified live vs VulnCorp.

- **Two OOB/differential injection legs** (`835ac52`): `command_injection_validator.py`
  (shell payload → OOB collaborator callback, blind-safe) and `ssti_validator.py`
  (nonce-wrapped arithmetic `89*97` → evaluated product in the response; proves template
  evaluation, not RCE). New shared `validators/injection_targets.py` (enumerate + mutate one
  param, factored out of the ssrf leg). Both gate-routed (added to `test_safety_gate.py`'s
  allowlist + route-through check).
- **Two GET-family legs + the missing category** (`3ecda46`): `path_traversal_validator.py`
  (canonical `/etc/passwd`/`win.ini` contents) and `open_redirect_validator.py` (off-origin
  sentinel in `Location`). **`path_traversal` was not even a category** before — added to
  `categories.py` (+ synonyms), `report_generator.py` remediation, `test_chaining.py`
  KNOWN_UNCOVERED. This was the one *detection* hole.
- **Wired all four into the graph loop + analyze shape-preconditions** (`f627872`): they ran
  only via `analyze()`'s per-finding `for_finding` before, so `investigate_engagement`
  (the discovery loop) never reached them. Now shape-routed like xxe/ssrf in
  `shape_precondition_legs` + `shape_precondition_findings` + the `_confirm` dispatcher.
  **`path_traversal` now also targets the last PATH SEGMENT** (`/uploads/<id>` →
  `/uploads/..\..\windows\win.ini`), not just query/body params — `FILEISH_PATH_SEGMENTS`
  is the single source of truth, imported by the orchestrator.

### Full max-coverage run this session (VERIFIED) — the new empirical truth

1.07h run vs VulnCorp (Docker up, sqlmap-in-container, fresh cache/state DBs, all features):
**162 raw → 17 confirmed (51 dupes collapsed) / 92 unconfirmed / 2 chains.** Runner +
outputs in `testing/vulncorp-helpdesk/maxrun/` (`report_full.md`, `maxcov_results_full.json`).

**Confirmed breadth 3 → 5 classes.** Baseline (session 8) was JWT alg:none + cross-identity
IDOR + SQLi. This run adds:
- **XXE** — `/api/tickets/import`, confirmed live (was the top *pending* item since session 9;
  now measured).
- **Path traversal** — `/uploads/1`, win.ini via the path-segment leg. A class the harness
  **could not detect or confirm at all** before this session.

**command_injection / ssti / open_redirect: wired, ran clean, 0 confirmed.** 18+ analyze
attempts, **zero false positives**; PASS-2 discovery reached 12 nodes (incl. `/uploads/{id}`,
`/api/tickets/search`, `/api/tickets/{id}/attachments`) but **none were cmd-inj/SSTI/redirect
endpoints** — VulnCorp's V23/V24/V30 live on surface the current discovery doesn't reach.
This is a **discovery/coverage gap, not a leg defect** (path_traversal confirmed via the same
shape-routing path; `/uploads/{id}` was a PASS-2 node too).

- **Efficiency note (not correctness):** the confirmation leg re-runs once per agent finding
  on the same exchange (xxe fired 10×, path_traversal 6× on one endpoint each). The report
  collapses these; a future optimisation is to memoise per (validator, endpoint) within a run.

## What shipped this session (10) — doc-vs-code reconciliation

A verification pass: read the code, corrected the docs that had drifted, no pipeline logic
touched. Committed this session as the single "session-10" reconciliation commit (the 5
tracked files; `config.local.yaml` stays git-ignored).

- **Config toggles moved back to safe defaults (hazard #1).** `harness/config.yaml` had
  `validators.active_enabled`, `validators.allow_mutating_replay`, and
  `autonomous_discovery.enabled` all committed as `true` — a live hazard-#1 violation. Flipped
  all three to `false` in the committed file; the live-local ON values now live in git-ignored
  `harness/config.local.yaml` (verified: `server.load_config()` deep-merges them back to `true`,
  validators block intact). **NOTE: `origin/main` still carries the same three toggles ON** —
  fix it there when `WorkingSunday` merges.
- **CLAUDE.md confirmation section corrected.** The 6-leg table is the graph loop's `_confirm`
  set; `analyze()` actually runs the *full* `ValidatorRegistry` (~20 validators via
  `for_finding`, `orchestrator.py:1450`). Added the ~13 previously-undocumented validators and
  the `active`-flag gating. File map's Confirmation row now lists them (source of truth =
  `validators/registry.py`).
- **README.md de-staled:** shipped model is `qwen3:8b` (was `llama3.1:8b`/`gemma2:9b`); the "no
  measured accuracy baseline" claim removed (SCORECARD + session-8 run exist); `archive/HANDOVER.md`
  references reframed as spelunking-only, not a "companion."
- **validators/README.md:** "SqlmapValidator is the first adapter" → now ~20 adapters.
- **Verified accurate, left alone:** `investigate_engagement` + all named entry points exist;
  the `analyze()` shape-leg wiring; 1021 tests OK; 36 agents; `xxe`/`ssrf` really do need
  `allow_mutating_replay`. `COMPETITIVE_LANDSCAPE.md` is current (recently corrected).

## What shipped this session (9)

- **Docs restructure** (`ab40745`) — replaced the numbered `SESSION_HANDOVER_*` chain (which
  cost ~100k tokens/session to reconstruct) with `CLAUDE.md` (stable, auto-loaded) +
  `CURRENT_STATE.md` (this file). Old handovers archived under `archive/`.
- **#1 cross_identity honors config** (`8e21bfa`) — `investigate_engagement` no longer
  hard-codes `max_identities=3`; reads `validators.cross_identity.{max_identities,timeout}`
  so the graph pass covers all seed identities incl. cross-org. (This was session 8's
  uncommitted fix; now committed.)
- **#2 proactive XXE/SSRF in `analyze()`** (`9996ac4`) — closes the prior top lever. New
  module-level `orchestrator.shape_precondition_findings(exchange)` synthesises XXE (XML body)
  / SSRF (URL param) legs, appended as a rule-based report BEFORE `_validate_findings` (like
  `credential_endpoint_detector`), pruned to CONFIRMED-only after. **Verified in the pipeline**
  by a new hermetic smoke test `test_smoke_shape_precondition` (real `analyze()`, silent model,
  vulnerable + negative-control OOB). **NOT yet re-measured in a live run** — see §Next.
- **#5 browser_xss over CDP** (`98b0c03`) — opt-in `validators.browser_xss.cdp_endpoint` drives
  a containerised Chromium over CDP instead of launching on the host (mirrors
  sqlmap-in-container). Seam-mocked unit test (`test_browser_driver`, 6). Live verification vs
  a real browser container still pending.
- **#7 the 8 missing Burp typed executors** (`a9476d2`) — `crypto_transport`,
  `http_request_smuggling`, `nosql`, `oauth_flow`, `sql_injection`, `subdomain_takeover`,
  `web_cache_poisoning`, `websocket_cswsh`, each with a Montoya-free `*Logic` class + JUnit5
  test. **Compiled clean** at the maintainer's `gradle` build and packaged into the root jar —
  resolves the earlier blind/no-JDK caveat. Authored + static-consistency-checked here. If the
  build ran the `test` task the new `*LogicTest`s are covered; otherwise run them to gate the
  verdict logic (compilation alone doesn't exercise it). Live target testing of the executors
  is the usual next step.

## Latest measured run (session 13, VERIFIED) — supersedes session 11

See "Session-13 measured run" near the top: **394 fused → 32 raw / 22 unique confirmed,
6 confirmed classes** (adds `secret_disclosure` — the `/api/admin/debug` JWT-key leak — over
the session-11 5-class baseline), on a **crash-free** pipeline after the attribution/`Finding`
fix. Recall 8–9/13 on the documented endpoint-known ground truth; discovery 12→21 endpoints.
Prior datapoints: session 11 = 162 raw → 17 confirmed / 5 classes; session 8 = 151 raw → 13 /
3 classes. Tuning lesson still holds: `autonomous_discovery` + `critique` off for the analyze
pass; config built in memory over `config.yaml`.

## Known gaps (the honest column)

- **command_injection / ssti / open_redirect confirm nothing on VulnCorp yet** — the legs are
  built, wired, and false-positive-clean, but VulnCorp's V23/V24/V30 endpoints aren't in the
  captured analyze set nor surfaced by PASS-2 discovery. This is a **discovery** gap: the graph
  loop's active discovery needs to reach those endpoints (agent-role features / non-API routes)
  before the legs can bite. Next lever is discovery breadth, not another leg.
- **Still no confirmation leg for several classes with a detector** (the remaining half of the
  original gap analysis): V22 second-order SQLi, V9 JWT `kid` key-confusion (jwt_forge does
  alg:none + reused-sig only), V26 deserialization RCE (validator is passive-only), V15
  verb-tamper, and the stateful auth family V3/V4/V5/V6/V7 (reset-token entropy, rate-limit,
  username enum, session fixation, weak password policy — all need a multi-request "sequence +
  diff" leg pattern; only race_condition bursts today). V33 file-upload, V32 CSRF also open.
- **High-value unconfirmed bugs** still need a disclosure/mass-assignment leg: `admin/debug`
  leaks the JWT signing secret to anonymous (conf 1.00, hand-verified), mass-assignment on
  `account/{profile,settings}`/`register`.

## Next (ranked)

1. **Discovery breadth so cmd-inj/SSTI/open-redirect can bite** — the legs are wired and clean;
   they just never reach V23/V24/V30. Extend `api_surface_discovery`/`role_crawl` (esp. the
   agent-role integration/webhook features) so those endpoints enter the worklist, then re-run.
2. **Build the remaining legs** (the other half of the gap analysis): the stateful auth family
   (shared "sequence + diff" pattern → V3/V4/V5/V6/V7), V9 kid key-confusion (extend
   jwt_forge), V26 active deserialization (the pickle-cookie RCE VulnCorp plants), V22
   second-order SQLi, V15 verb-tamper, V32 CSRF, V33 file-upload.
3. **Memoise confirmation per (validator, endpoint) within a run** — xxe fired 10× / path_trav
   6× on one endpoint each; the report dedups but the wall-clock cost is real.
4. **Push `WorkingSunday` + open the PR into `main`.**
5. **Update the report artifact** (`a56d56f5-…`) — fold in the session-11 result (17 confirmed /
   5 classes; path_traversal + XXE newly confirmed).
6. **Live-verify browser_xss CDP** (#5) against a real `browserless/chrome` container.
6. **Add a disclosure/mass-assignment confirmation leg** — the `admin/debug` JWT-secret-leak
   (highest severity) is unconfirmed only for lack of one.
7. **Burp panel:** compile + wire the Cross-Identity + Discovery tabs (needs a JDK).

## Notes

- This session touched no `config.local.yaml`, no `main`, and no answer-key/target-source files.
  `config.yaml` gained only a documented, default-off `browser_xss.cdp_endpoint: ""` (no toggle flipped).
- Deep history for sessions 1–7 is in `archive/SESSION_HANDOVER_*.md` — for spelunking, not onboarding.
