# Current state

The single rolling per-session delta. Stable context (architecture, hazards, environment,
file map) is in [`CLAUDE.md`](CLAUDE.md) — read that first, then this.

**Update this file in place at session end. Do not create a new numbered handover.**

---

## State (as of session 9)

- **Branch:** `WorkingSunday`. **HEAD:** `a9476d2`. Working tree: only untracked `testing/`
  artifacts; tracked tree clean. **NOT pushed** (local only); `main` untouched.
- **Suite green (Python):** from `harness/`, `python -m unittest discover -p "test_*.py"` →
  **OK, 1021 tests** (verified this session).
- **Java compiles + jar built:** the #7 Burp changes were compiled clean and packaged into
  `burp-llm-harness-extension-0.1.0-all.jar` at the maintainer's `gradle` build (confirmed
  off-machine; no JDK here — hazard #6). The jar is git-ignored (`.gitignore` `*.jar`), so it
  lives at root for Burp to load and is not committed.
- **Environment verified:** Ollama `qwen3:8b` reachable; Docker up with `harness/sqlmap:1.10.9`;
  host chromium/playwright present. No host `javac` anywhere. (See CLAUDE.md § Environment.)

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

## Latest measured run (session 8, VERIFIED) — still the current empirical truth

50-min max-coverage run vs VulnCorp: **151 raw → 13 confirmed / 104 unconfirmed / 1 chain**
(33 dupes collapsed). **Confirmed breadth 1 class → 3**: JWT alg:none (7 endpoints, conf 0.90),
cross-identity IDOR (`reports/1` incl. cross-org, `tickets/1`, `tickets/1/comments`), SQLi
`/api/login` (sqlmap). Runner + outputs in `testing/vulncorp-helpdesk/maxrun/` (`report_full.md`
etc., untracked). Tuning lesson: for a tractable run turn `autonomous_discovery` **and**
`critique` off in the analyze pass (they fan out unboundedly — one exchange → 50+ model calls).

## Known gaps (the honest column)

- **XXE/SSRF now WIRED into `analyze()` (#2) but not yet re-measured live.** The
  `/api/tickets/import` XXE should now confirm proactively on a real run (it didn't before);
  that empirical proof is the top Next item. Smoke-tested only so far.
- **High-value bugs with no confirmation leg** still sit in the unconfirmed pile:
  `admin/debug` leaks the **JWT signing secret to anonymous** (conf 1.00, hand-verified),
  mass-assignment on `account/{profile,settings}`/`register`, CSRF on `change-password`. These
  need a disclosure/mass-assignment confirmation leg (none exists) — same coupling, one class wider.

## Next (ranked)

1. **Re-run max-coverage to measure #2** — does the `/api/tickets/import` XXE now confirm via
   the analyze() shape leg? Also confirms the #1 cross-org coverage. Use a FRESH cache DB; turn
   `autonomous_discovery`+`critique` off for the analyze pass (session-8 tuning lesson).
2. **#7 follow-through:** compilation is confirmed and the jar is built. Confirm the JUnit5
   `*LogicTest`s ran green (if the build was `shadowJar`-only they didn't), then live-test the
   8 new executors against a target — compile-clean ≠ behaviour-correct.
3. **Push `WorkingSunday` + open the PR into `main`** (17+ commits unpushed across sessions).
4. **Update the report artifact** (`a56d56f5-…`) — still shows the first run's 228/32; fold in
   the session-8 measured result (13 confirmed / 3 classes) + the coupling framing.
5. **Live-verify browser_xss CDP** (#5) against a real `browserless/chrome` container.
6. **Add a disclosure/mass-assignment confirmation leg** — the `admin/debug` JWT-secret-leak
   (highest severity) is unconfirmed only for lack of one.
7. **Burp panel:** compile + wire the Cross-Identity + Discovery tabs (needs a JDK).

## Notes

- This session touched no `config.local.yaml`, no `main`, and no answer-key/target-source files.
  `config.yaml` gained only a documented, default-off `browser_xss.cdp_endpoint: ""` (no toggle flipped).
- Deep history for sessions 1–7 is in `archive/SESSION_HANDOVER_*.md` — for spelunking, not onboarding.
