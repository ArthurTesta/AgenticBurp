# Current state

The single rolling per-session delta. Stable context (architecture, hazards, environment,
file map) is in [`CLAUDE.md`](CLAUDE.md) — read that first, then this.

**Update this file in place at session end. Do not create a new numbered handover.**
Older session narratives are in git history / `archive/`; this file is deliberately short
(review weakness #18: it had become the archived chain again).

---

## ►► SESSION-17 STATE (READ FIRST) ◄◄

**2026-09-10 astra-t05-t08 review:** Reviewed `e1ac8e9` in
`.worktrees/astra-t05-t08` against `e24ca7f`. 128 focused coverage/export/storage/
inventory tests passed; offline diagnostics confirmed uncovered accounting,
redaction, issue-ID, proof-reference, and retest-history defects. T05/T06 request
changes; T08 remains inventory-only. See
[`T05–T08 review`](reviews/review-Astra-Medium-10-09-06-30/IMPLEMENTATION_REVIEW_T05_T08.md).
No implementation code changed; full suite and engagement behavior not reverified.

**2026-09-10 fresh live max-coverage result (session 18, VERIFIED):** The full
VulnCorp Helpdesk run completed using a fresh target plus fresh `s18` state/cache DBs.
Preflight was 1,509 tests OK in 296.102 s. The live run took **29,303.4 s
(8.14 h)**, of which `investigate_engagement` took **22,266.7 s (6.19 h)**.
Artifacts are under `testing/vulncorp-helpdesk/maxrun/` with the `s18_full` tag.
Recall was **9/13 confirmed, 3/13 detected-unconfirmed, 1/13 missed**; the remaining
miss was SSRF at `/api/integrations`. Six confirmations have UNKNOWN provenance,
so they must not be credited to their intended deterministic legs. Compared with
the verified `s16_full` baseline: confirmed recall improved 8→9, misses fell 2→1,
but runtime regressed 10,085.7→29,303.3 s (**2.91× / +190.5%**), fused findings
rose 712→1,921 and confirmations 71→687. Coverage reported 11,137 cells: 319
attempted/conclusive (103 confirmed, 126 detected, 90 not detected), 7,122 N/A,
3,696 skipped, 0 pending/running/error; all 150 coverage-driven leg budget slots
were used. Investigation returned 11 outcomes, 0 chains, 3 IDOR findings, no
reported errors, and `degraded=false`; 41/43 endpoints were validated. Browser-XSS
had zero confirmations. No discovery-frontier class was confirmed. Treat the huge
finding/confirmation inflation, zero chains, 6 UNKNOWN-provenance confirms, 3,696
skips, and 8.14 h runtime as the main performance/correctness follow-ups.

**2026-09-10 review-only addendum:** Source inspected at HEAD `8b5c6e1`;
implementation handoff saved to
[`reviews/review-Astra-Medium-10-09-06-30/IMPLEMENTATION_HANDOFF.md`](reviews/review-Astra-Medium-10-09-06-30/IMPLEMENTATION_HANDOFF.md).
It defines T00–T10, beginning with a real-transport authorization proof milestone.
No implementation changes, tests, or live runs were performed for this review;
the suite result below remains the previous session's reported result.

**2026-09-10 T00 implementation:** Added a versioned, redacted run manifest and
append-only lifecycle ledger to the existing investigation job API. Focused suite:
9 tests OK. The missing local `pytest` and `mitmproxy` dependencies were subsequently
installed from their existing pins: the pytest-native plugin suite is 26/26 green and
full stdlib discovery is **1,509 tests OK, 2 skipped**, 272.821s. The optional proxy's
`typing-extensions` metadata conflicts with the bundled Pydantic stack, so verification
uses the bundled core runtime first and appends `.review-deps`; details are in the review
directory's `EXECUTION_LOG.md`. T01–T10 remain open.

**2026-09-10 T01–T03 implementation review:** Reviewed separate worktree
`AgenticVibe-impl`, branch `impl/astra-tickets`, HEAD `bcaab08`. Its 57 new focused
tests passed with access to existing dependencies; no full suite or engagement run
was performed. Review requests changes: production wiring, proof verdict/case/run
binding, session/origin isolation, and ownership metadata remain incomplete.
See [`implementation review`](reviews/review-Astra-Medium-10-09-06-30/IMPLEMENTATION_REVIEW_T01_T03.md)
and its offline diagnostic script. No implementation code was changed by this review.

Branch `WorkingSunday`, **HEAD `f36d454`** (+ any later doc commit). Suite green
(`cd harness && python -m unittest discover -p "test_*.py"`) — **1505 tests OK**,
~277 s, on the committed tree. `config.yaml` at safe defaults;
`config.local.yaml` untouched; hazard #1 intact.

### What session 17 did — implemented the 2026-09-09 project review

Worked [`reviews/2026-09-09/PROJECT_REVIEW.md`](reviews/2026-09-09/PROJECT_REVIEW.md)
top-to-bottom. That file's **IMPLEMENTATION PROGRESS** section is the authoritative
per-item status + the test that verifies each; this is just the summary.

**Closed, each with an offline test + negative control (all HERMETIC — no fresh live run):**

- **All P0 correctness findings:** R01/R02 (coverage stops inventing executed checks;
  honest counts), R03 (cache key includes identity+subtype), R04 (upload uses the real
  `GatedAsyncClient.request()`), R06 (coverage-driven confirmations enter the finding
  pipeline), R07 (monotonic confirmation — a proof is never downgraded), R08
  (execution-aware suppression — REFUTED needs a real controlled negative), R09 (exact
  leg tiers, no substring inheritance), R10 (reject self-comparison + distinct principal
  ids), R12 (second-order SQLi masks reflected payload), R14 (typed discovery-chain
  routing), R16 (per-finding mutation ceiling enforced).
- **Graph/flow:** R05 (replay captured request templates), R18 (`investigate_engagement`
  exposed as a cancellable job API in `server.py`), R19 (credential-feedback map + merge
  derived state), R20 (chain provenance), R21 (per-case completion), R23 (attempt-budget),
  R25 (browser drives AS the identity), R29 (bounded validation fan-out), R30 (operational
  failures surfaced as `result.errors`/`degraded`).
- **Oracle retirements (Phase 5)** — 8 overconfirming verdicts stood down to
  observations/candidates, detectors kept: passive-deserialization, rate_limit,
  reset_token, csrf, verb_tamper, request_smuggling, web_cache; file_upload tightened.
  csrf/verb_tamper removed from `LIVE_VERIFIED_MARKERS`. **See
  [`ORACLE_RETIREMENTS.md`](ORACLE_RETIREMENTS.md)** — the record of what was stood down
  and how to re-qualify each (search code for `RETIRED (review 2026-09-09)`).
- **Precision:** R11 (BFLA needs a privileged-data match), R13 (authenticated
  second-order plant + distinct-identity read).
- **Weaknesses:** #1 (prompt validator observes injection-shaped evidence instead of
  skipping analysis; hard-block opt-in), #5 (repro field isn't remediation), #6 (recall
  UNKNOWN provenance + best-proof), #7 (CSRF WSTG SESS-05), #9 (sitemap header
  multiplicity), #10 (strict ffuf fallback), #11 (tool container force-remove on timeout),
  #13 (high-signal excerpt beyond truncation), #14 (DAG: skipped-required ≠ satisfied),
  #18 (this file trimmed), #19 (removed fabricated token-savings %).

### The honest frontier — NOT done (needs operator direction, per the review's L-phases)

These are the review's dedicated architecture phases or need a schema/design decision;
they were deliberately **not** rewritten unilaterally:

- **Schema / issue-ID model:** R28 per-finding/case-ID binding (synonym match IS done),
  #4 root-cause dedup.
- **Architecture rebuilds:** R15 (one policy-aware executor / registry-only construction),
  R17 (centralized scope/transport + redirect/credential handling), R24 (stateful
  authenticated workflow engine), R26 (per-parameter coverage matrix), R27
  (principal/tenant/session/ownership model), #3 (per-run isolation of global state),
  #8 (OpenAPI schema-driven request construction), #20 (single operator run→export flow).
- **Tuning:** R22 (broaden agent derivation — affects runtime cost), #12 (session reuse
  across raw clients), #2 (cache manifest — over-invalidation risk).
- **Infra/CI:** #15/#16 (packaging/deps), #17 (scored CI tier + Java/browser gates),
  and the **deletion/consolidation table** (Phase 9 — gated on the rebuilds above).
- **The one measurement still owed:** a fresh live max-coverage VulnCorp run. Everything
  above is hermetic; target-recall numbers are unchanged. Use `testing/vulncorp-helpdesk/maxrun/`,
  a FRESH cache DB, toggles in `config.local.yaml` (never a committed flip).

### Environment

Ollama `qwen3:8b` + Docker (`harness/sqlmap:1.10.9`, `harness/ffuf:2.1.0`),
Playwright/Chromium — as CLAUDE.md § Environment. No host `javac` (Burp panel is
self-review only; the review's fixes are all Python).

### Commit shape

Focused commits on `WorkingSunday`, one finding-group each, suite green at the batch
boundary. Nothing pushed. The pre-existing session-17 discovery-breadth WIP was
snapshotted first (`33031f9`) before the review fixes landed on top.
