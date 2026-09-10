# AgenticVibe — independent engineering / architecture / pentest review

**Reviewed 2026-09-10.** Branch `WorkingSunday`, HEAD `e9e5c91`. This is a fresh,
evidence-based pass. It builds on but re-verifies the 2026-09-09 review
(`reviews/2026-09-09/PROJECT_REVIEW.md`) and adds the new signal that review did not
have: the **session-18 live max-coverage run** artifacts under
`testing/vulncorp-helpdesk/maxrun/` (tag `s18_full`).

## What I actually verified (vs. reported)

Per the project's #0 discipline, here is what is verified by a command I ran versus taken
from artifacts/docs:

- **VERIFIED by me:** full suite is green — `python -m unittest discover -p "test_*.py"`
  → **`Ran 1509 tests in 281.029s … OK`** on the committed tree. The CURRENT_STATE count
  is honest.
- **VERIFIED by me (from the saved s18 artifacts, not a fresh run):** the recall,
  coverage, confirmation-inflation, provenance, chain and runtime numbers quoted below
  were extracted directly from `maxcov_results_s18_full.json`, `recall_report_s18_full.json/.md`
  and `report_s18_full.md`.
- **VERIFIED by me (source):** the confirmation-inflation mechanism
  (`orchestrator.universal_header_audit`), the god-module shape, duplicate agents, the
  duplicate-harness snapshot, packaging/CI state.
- **NOT verified (out of scope this pass):** a fresh live run; Java/Burp compilation and
  UI parity (no JDK here); the internal correctness of each individual oracle beyond the
  gate; concurrent multi-engagement behaviour. The live target's true vuln denominator is
  still the 13-item documented set, not exhaustive ground truth.

## Size (measured)

| Surface | Count | LOC |
|---|---:|---:|
| Non-test root modules (`harness/*.py`) | 75 | 24,807 |
| Agents (`harness/agents/`) | 39 | 4,101 |
| Validators (`harness/validators/`) | 38 | 9,652 |
| Test files (`harness/test_*.py`) | 104 | 21,440 |
| Largest single module | `orchestrator.py` | 2,968 |

---

## 1. What is GOOD (preserve)

These are real strengths, several unusual for a project in this space. Keep them.

1. **The core thesis is right.** Captured real HTTP exchanges as input + LLM for
   *hypothesis* + deterministic legs for *confirmation* + an explicit identity/graph model
   is the correct division of labour. Nothing below argues against the architecture; the
   problems are in the wiring, not the idea.
2. **Deterministic confirmation legs, decoupled from detection.** The shape-driven
   precondition legs (`orchestrator.shape_precondition_legs`, pure + unit-tested) and the
   registry of 20+ legs are the crown jewels. When they fire with provenance they produce
   genuinely strong evidence (JWT HMAC key match, cross-identity IDOR, path traversal).
3. **The honest result state machine exists.** `confirmation_gate.py` has real tiers
   (`CONFIRMABLE` / `LIVE_VERIFIED` / `PROVISIONAL` markers, `leg_tier`,
   `apply_confirmation_suppression` distinguishing `inconclusive_unverified` from a
   controlled `REFUTED`). This is exactly the right machinery — the problem (see §5) is that
   one big path bypasses it.
4. **The 2026-09-09 review was taken seriously.** All P0 correctness findings (R01–R16)
   and most P1s are closed *hermetically with negative controls*. That is disciplined work
   and the test suite reflects it (1426 → 1509).
5. **Safety posture.** Safe committed `config.yaml`, git-ignored `config.local.yaml`
   deep-merge, `GatedAsyncClient`, per-finding mutation ceiling, containerised sqlmap/ffuf
   with argument arrays (no LLM-generated shell), throttle/circuit-breaker/token ledger.
6. **Provenance honesty in measurement.** The recall benchmark now reports
   `unknown_provenance_confirms` instead of the old misleading "lucky." That it reports 6/13
   unknown is *painful but honest* — it is the single most useful number in the repo.
7. **Paired fixtures + end-to-end smoke tests with negative controls**
   (`test_smoke_detection.py`, `test_smoke_investigate.py`). The right shape of test for a
   project whose failure mode is "green tests, dead pipeline."
8. **Discovery breadth** — surface discovery, role crawl + access matrix, JS endpoint
   mining, OpenAPI path import, Burp sitemap import, soft-404 calibration.
9. **Operator honesty in docs.** README is candid about passive-default posture and the GPU
   tradeoff; ORACLE_RETIREMENTS.md records what was stood down and how to re-qualify it.

---

## 2. What is BAD (prioritised, with evidence)

### P0 — precision collapse: the "confirmed" number is not trustworthy on a real target

**Evidence (s18, extracted):** the run produced **1,921 fused findings / 687 "confirmed."**
The final analyst report shows **112 confirmed** after collapsing **1,457 duplicates**.
Breaking the 687 down by class (`recall_report_s18_full.md`):

| Confirmed class | Count | Leg stamped |
|---|---:|---|
| information_disclosure | 365 | `(none)` |
| verbose_error_disclosure | 136 | `(none)` |
| cross-origin resource sharing (CORS) | 41 | `(none)` |
| content security policy (CSP) | 41 | `(none)` |
| jwt | 13 | jwt_forge / secret_disclosure |
| path_traversal | 8 | path_traversal |
| idor (all label variants) | ~73 | cross_identity (some none) |
| sqli / xxe / directory traversal | ~10 | `(none)` |

**~583 of 687 "confirmed" findings carry no deterministic leg.** They are structural
observations (a missing CSP header, a permissive CORS header, a debug string) stamped
`confirmed=True`. These are precisely the classes the 2026-09-09 review said MUST NOT
auto-confirm ("a configuration fact or parsed format must not auto-confirm a vulnerability").
A missing CSP header is not a confirmed exploit; it is being counted as one 41 times.

**Root cause (source-verified):** `orchestrator.universal_header_audit()`
(`orchestrator.py:567`) runs the CORS, CSP and verbose-error validators against **every
captured exchange** and, at `orchestrator.py:616-627`, appends
`Finding(..., confirmed=True)` whenever the validator returns `confirmed`. This path
**bypasses `confirmation_gate` entirely** — the honest tier machine never sees these
findings. The Phase-5 oracle retirement stood down CSRF/verb_tamper/rate/reset/smuggling/
web-cache/passive-deser, **but CORS and CSP were never retired**, and `verbose_error`
confirms structurally too. So the fix that was tested (removing the `_AUTO_CONFIRM_CLASSES`
LLM-label block) does not touch the path that actually produces the flood.

This is the "green tests, dead pipeline" failure mode wearing a new costume: **1509 hermetic
tests are green, yet the live pipeline still emits the exact behaviour the retirement was
supposed to remove**, because the tests cover the removed path, not `universal_header_audit`.

### P0 — the confirmation thesis is unproven on the target

**Evidence (s18 recall_score):** 9/13 confirmed, but **only 3/13 (`GT04` idor-ticket,
`GT05` idor-report, `GT07` pathtrav) have "earned" leg provenance.** The other 6 are
`unknown` — e.g. `GT01`/`GT02` SQLi: *"confirmed, but no leg is named in the evidence —
cannot say whether the intended 'sqlmap' path proved it."* Same for XXE, JWT, BFLA, and the
admin-debug disclosure.

The entire selling point of this project is "make confirmation as broad as detection" via
deterministic legs. **On the one real measurement we have, the deterministic engine is
verifiably responsible for only 3 of 13 planted bugs.** The rest are either confirmed by
the structural auto-confirm flood (GT12 = information_disclosure, matched 44 findings) or by
a leg that ran but failed to stamp its provenance. You cannot currently tell which — and
that is the whole problem. **Provenance is parsed from evidence text, not carried as a
foreign key from the execution that produced it** (2026-09-09 weakness #6, still open at the
data-model level).

### P0 — one bug is genuinely missed, others detected-but-unconfirmed

- **`GT13` SSRF `/api/integrations` — missed entirely (0 matched findings).** The ssrf leg
  exists and is live-verified on the fixture, so this is a **reachability/request-fidelity**
  failure, not a leg failure: the SSRF endpoint's request shape never reached the leg.
- **`GT06` idor-comments, `GT09` massassign-profile, `GT10` massassign-register —
  detected_unconfirmed.** Mass-assignment has a `sequence` leg; it did not confirm. Again a
  request-fidelity / workflow-binding gap (write-then-reread needs the real body + object
  binding), exactly the prior review's R05/R24 territory.

### P1 — two overlapping detection pipelines, fused, no source-level dedup

The max-coverage run executes **both** `analyze()` over 37 captured exchanges **and**
`investigate_engagement()`, then the recall benchmark fuses them. The report then collapses
**1,457 duplicates** after the fact. Deduplicating 1,457 findings post-hoc is a symptom: the
same class on the same endpoint family is being (re)confirmed dozens of times across
identities, exchanges and both pipelines. This drives both the finding inflation and the
runtime.

### P1 — runtime regressed 2.9× while unique recall barely moved

**Evidence:** s16 → s18: runtime 10,085s → **29,303s (8.14h, +190%)**; `investigate_engagement`
alone **6.19h**; fused findings 712 → 1,921; confirmations 71 → 687. **Unique confirmed
recall went 8 → 9.** The system spends more the noisier it gets — cost scales with the false
flood, not with signal. A copilot that takes 8 hours and returns 112 "confirmed" findings of
which ~15 are real is not usable as a copilot.

### P1 — graph feedback is dead on the real target

**Evidence:** `investigate.chains = 0`, `chain_rounds = 0`, and every identity has
`source: seed` / `obtained_from: ""` — **no credential was ever leaked-then-reused; no chain
was ever linked** in the flagship loop. (The 6 chains in the report come from the *other*
pipeline, `analyze()`+`chaining.detect`, not from `chain_linker`.) R18/R19/R20 (job API,
credential-feedback map, chain provenance) are hermetically tested but produce nothing on
the live path — the closed loop the architecture is built around did not close.

### P1 — data-loss in confirmed findings

`report_s18_full.md` contains a **CONFIRMED `jwt` critical finding with an empty URL**
(`### jwt -- ` with no endpoint) and empty `Reported by:` fields. A confirmed critical with
no location is not actionable and indicates identity/URL is still being dropped somewhere in
the graph→report projection (prior review R05/R20 residue).

### P1 — `browser_xss` produces zero live confirmations

Zero XSS confirmed via the browser leg across the whole run. Either discovery isn't reaching
an HTML sink, the authenticated browser context (R25) isn't actually carrying state on the
live path, or there is no reflected/stored XSS in scope. Given R25 was "hermetic; live
browser still operator," this is an unverified live capability being counted as a shipped
one.

### P2 — architecture / maintainability

- **`orchestrator.py` is a 2,968-line god-module** with a single `Orchestrator` class that
  owns *both* entry points (`analyze` at :2363 and `investigate_engagement` at :1119). This
  is the review's R15 (one policy-aware executor) unaddressed; it is why behaviour differs
  between the two pipelines and why `universal_header_audit` can bypass the gate.
- **Global mutable state** (`activity_feed`, `collaborator`, `global_throttle`,
  `coordinator`) is process-wide — fine for shared resource ceilings, unsafe for per-run
  evidence/authorization isolation (review #3).
- **Not pip-installable** (flat top-level imports, no `[build-system]`); the **scored CI
  tier is still `if: ${{ false }}`** (review #15/#17). CI cannot catch the precision
  collapse because the only gate is the stubbed-LLM smoke test.

---

## 3. What can be DELETED / consolidated

| Target | Action | Gate before deleting |
|---|---|---|
| `testing/blind-test-kit/harness/` (**90 tracked files**) | Delete — it is a full duplicate snapshot of `harness/` | Confirm the kit consumes the real `harness/` via path or a pinned revision, not this copy |
| `.worktrees/astra-review-fixes`, `.worktrees/astra-t05-t08`, and the sibling `AgenticVibe-impl` worktree | Remove/merge — stale review worktrees on branches `codex/astra-review-fixes`, `astra-t05-t08`, `impl/astra-tickets` | Land or abandon each branch first; they fragment the truth |
| `review_test_output.txt` (266 KB, untracked, at repo root) | Delete — scratch | none |
| `testing/vulncorp-helpdesk/maxrun/` old tags (`baseline_*`, `*_recall_*`, `s16_*`) | Keep the latest (`s18`) + one baseline; archive/prune the rest (~80 MB) | `captured_exchanges.json` (9.8 MB) and `*_state_*.db` carry **live JWTs/cookies** — scrub or keep out of any share, don't just move |
| Untracked benchmark scripts: `run_real_analysis.py`, `run_real_analysis_v2.py`, `run_analysis_simple.py`, `phase_real_run_v6_tp_only.py`, `bench.py`, `ab_routing_recall.py`, `fp_benchmark.py` | Consolidate into **one** benchmark CLI with a schema'd output | Diff their config/inputs/scoring first; preserve historical result JSONs |
| Duplicate agents: `business_logic` + `business_logic_enhanced`, `ai_llm` + `ai_security` | Consolidate (declarative specialist specs) | Measure unique true-positive contribution on held-out cases (do NOT delete by name) |
| `AGENTS.md` vs `CLAUDE.md` | One authoritative orientation + a pointer | Confirm which tool consumes which filename |
| Root doc sprawl (11 top-level `.md`: LEG_DECISIONS, LEG_VERIFICATION, HARNESS_IMPROVEMENT_NOTES, PROXY_SETUP, REVIEW, COMPETITIVE_LANDSCAPE…) | Fold stable content into CLAUDE.md; move point-in-time notes to `archive/` | Keep CLAUDE.md + CURRENT_STATE.md as the only onboarding |
| `universal_header_audit` structural `confirmed=True` (orchestrator.py:616-627) | **Delete the verdict, keep the detection** — emit these as observations, route through the gate | Regression test: safe CORS/CSP/verbose-error must NOT reach `confirmed` |

Do **not** delete: safety controls, negative-control fixtures, the confirmation gate, the
token ledger, human-verification tasks, or run-evidence you still need. Removing those to get
a cleaner number is the project's documented failure mode.

---

## 4. Missing / incomplete features — MoSCoW

"MUST" = required before the "confirmed" number and the 8-hour cost can be trusted, not "every
technique belongs in the next release." Many of these are the 2026-09-09 architecture phases,
re-prioritised by the s18 evidence.

### MUST
- **Route every confirmation through the gate; no path stamps `confirmed=True` directly.**
  Retire CORS/CSP/verbose-error verdicts to observations (as CSRF/verb_tamper already were).
  Acceptance: on s18 inputs, "confirmed" drops from 687 to the leg-proven set; safe structural
  facts appear as observations.
- **Provenance as a foreign key, not parsed text.** Every confirmed finding carries the
  `execution_id` + `leg` + `validator_version` that proved it. Acceptance: 0 `unknown`
  provenance among confirmations; a confirmation with no execution FK is impossible to emit.
- **Canonical request templates + concrete input bindings preserved end-to-end** (R05/R26).
  Acceptance: SSRF `/api/integrations` and both mass-assignment endpoints reach their legs
  with the real body/query/object-id and either confirm or produce an honest controlled
  negative — not silence.
- **One policy-aware executor / registry-only construction** (R15). Collapse the two pipelines
  so `analyze` and `investigate_engagement` cannot diverge or double-count. Acceptance:
  identical settings ⇒ identical allowed actions and one ingestion path; post-hoc dup collapse
  falls from 1,457 toward single digits.
- **Principal/role/tenant/session/ownership model** (R27). Alice and Bob of the same role stay
  distinct; IDOR/BFLA proofs reference owner vs attacker principal IDs.
- **Enforced request/mutation/time budgets that actually bound runtime.** Acceptance: a
  max-coverage run has a declared wall-time ceiling and the count of network sends is reported
  per phase.

### SHOULD
- **Stateful authenticated HTTP + browser sessions** (R24/R25) — verified on the live path,
  not just hermetically; make `browser_xss` produce a real confirmation or be marked
  operator-only in the recall report.
- **Make the credential→re-crawl→chain loop close on a real target** (R18/R19 live). Acceptance:
  a leaked credential from one finding unlocks a new identity/route that is then retested and
  appears in the graph chains — with a negative control that does not unlock.
- **Schema-derived request generation** from the OpenAPI paths already discovered (bodies,
  required fields, examples) — the most direct lever on the reachability gap.
- **Root-cause dedup with stable issue IDs** (review #4) so one shared JWT verifier is one
  issue, not 13, *at source* rather than by post-hoc collapse.
- **Per-parameter coverage matrix** (R26) so "not_applicable" (7,122 cells) and "skipped"
  (3,696 cells) are honest rather than an artefact of query-stripping.
- **Installable package + a real scored CI gate** on a self-hosted GPU runner (flip
  `if: false`), with a negative-control precision floor that would have caught the 583-item
  flood.

### COULD
- Deeper DOM sources/sinks (postMessage/storage), HTTP/2 race sync, GraphQL-specific attacks —
  **only after** core precision/reachability are fixed.
- Additional typed tool adapters, distributed runners, stronger model backends — gated on a
  measured per-case yield.
- Business-invariant templates (approval/quantity/ownership rules).

### DON'T
- **Don't add more specialist agents or legs now.** Breadth is not the constraint; the
  s18 run detected almost everything. Confirmation trust and cost are the constraints.
- **Don't treat a bigger model as the fix.** A larger model cannot un-stamp a structural
  `confirmed=True`, supply a missing SSRF request body, or close the chain loop.
- **Don't lower confirmation thresholds to raise recall** — it inflates the flood.
- **Don't read answer keys / encode target route names.** Keep fixes capability-based.
- **Don't chase a headline recall %** until provenance and the structural flood are fixed;
  today's 9/13 is 3/13 trustworthy.

---

## 5. Why the project is not hitting the results it should — causal model

The success chain is: *discover a useful operation → obtain a valid authorized request →
preserve its inputs → pick an applicable check → execute it correctly → recognise a real
security effect → bind proof to the finding → report/score it correctly.* s18 shows the
breaks are now concentrated at the **back half** of that chain — the front half (discovery,
detection) is largely working.

1. **Proof semantics are still inconsistent — this is the #1 problem now.** Some legs prove
   execution (IDOR, path traversal); a whole other path (`universal_header_audit`) stamps
   `confirmed=True` on a missing header. Both feed the same flag. Result: 583/687 "confirmed"
   are structural noise, the ~15 real proofs are buried, and the metric that should drive
   development points the wrong way.
2. **Provenance isn't carried, so you can't tell whether the legs even work on the target.**
   6/13 confirmations are unattributable. The project's core claim is currently unfalsifiable
   from its own output.
3. **Reachability / request fidelity is the structural ceiling on the *real* legs.** SSRF
   missed, mass-assignment unconfirmed — not because the legs are wrong but because the valid
   request (body, object binding, workflow state) never reached them. This is the same R05/R24
   bottleneck the last review named; it is now the limiting factor for the *good* legs.
4. **Two pipelines + no source dedup = inflation and 8 hours.** Cost scales with the flood.
   The graph loop alone burned 6.19h to add one unique confirmed bug over the previous run.
5. **The graph's closed loop doesn't close on target** — 0 chains, 0 credential rounds — so
   the escalation/composition value proposition isn't being realised where it matters.
6. **Green-tests-dead-pipeline, again, in a subtler form.** The fixes are real and
   hermetically proven, but the *live integration* wasn't re-measured against the negative
   behaviour: the retirement tests assert the old path is gone, not that no path emits a
   structural `confirmed`. The one live run we have is the only thing that surfaced it.

The encouraging read: this is **not** a "model too small" problem and **not** a detection
problem. Detection is broad and mostly works. The gap is confirmation trust, provenance,
request fidelity for the real legs, and cost — all fixable in code without a rewrite.

---

## 6. Roadmap (dependency-ordered)

Small, focused commits; suite green at each boundary; `Co-Authored-By` trailer; fresh
cache/process for any live measurement; never commit a `config.yaml` toggle flip. Each phase
has a live acceptance gate — the point is to stop trusting hermetic-only evidence for
integration behaviour.

**Phase A — Stop the flood (days, highest leverage).**
- Retire CORS/CSP/verbose-error `confirmed` verdicts to observations; route them through
  `confirmation_gate` like everything else. Remove the direct `confirmed=True` at
  `orchestrator.py:616-627`.
- Add a regression test: on the s18 captured exchanges, a safe missing-CSP / permissive-CORS /
  debug-string must land as `observation`, never `confirmed`.
- **Gate:** re-run recall on the saved s18 captures (from cache, no model) — "confirmed"
  collapses to the leg-proven set; the 13-item recall is unchanged for the 3 earned items.

**Phase B — Provenance FK (days).**
- Give every `ValidationResult`/`Finding` an `execution_id`, `leg`, `validator_version`;
  the recall benchmark reads the FK, not evidence text. Emitting `confirmed` without an
  execution FK becomes impossible.
- **Gate:** 0 `unknown_provenance_confirms` on a live re-run; every confirmed GT item names
  its leg.

**Phase C — One executor, one ingestion path (1–2 weeks).**
- Collapse `analyze` and `investigate_engagement` onto a single registry-driven executor and
  a single result-ingestion function; dedup by stable issue ID at source (review #4/R15/R28).
- **Gate:** post-hoc duplicate collapse drops from 1,457 to single/low-double digits; the two
  entry points can no longer diverge; a matrix-only confirmation still reaches the report.

**Phase D — Request fidelity for the real legs (1–2 weeks).**
- Preserve canonical request templates + object bindings end-to-end (finish R05); extend to
  the per-parameter matrix (R26). Prioritise SSRF and mass-assignment.
- **Gate:** SSRF `/api/integrations` and both mass-assignment endpoints reach their leg with a
  real request and produce confirm-or-controlled-negative; no confirmed finding has an empty
  URL.

**Phase E — Close the loop live + budgets (1–2 weeks).**
- Make credential feedback and chain linking fire on the live path (R18/R19/R20 integration
  test against a real chain fixture, not the linker seam). Add enforced wall-time / send
  budgets with per-phase accounting.
- **Gate:** a leaked credential unlocks and retests a new route that appears in graph chains
  (with a negative control); a max-coverage run reports a bounded wall time.

**Phase F — Qualify remaining oracles + real gates (ongoing).**
- Work the oracle-table negative controls in dependency order (authz → injection →
  session/workflow → browser). Stand up the scored CI tier on a GPU runner with a
  negative-control precision floor. Make `browser_xss` prove itself live or be labelled
  operator-only.

**Phase G — Consolidate & package (after A–E).**
- Delete the duplicate harness snapshot and stale worktrees; consolidate benchmark scripts and
  duplicate agents (gated on ablation); make the package installable; fold docs into the two
  onboarding files.

**Sequencing note:** A and B are the highest-value, lowest-risk changes and should land first
— they make every subsequent measurement trustworthy. Do not start G until A–E change the
numbers, and do not add any new detector or leg until A–D are done.

---

## Appendix — s18 numbers I relied on (all from saved artifacts)

- Wall time 29,303.3s (8.14h); `investigate_engagement` 22,266.7s (6.19h).
- Fused findings 1,921 / "confirmed" 687. Final report: 112 confirmed, 346 unconfirmed,
  6 chains, 1,457 duplicates collapsed.
- Recall 9/13 confirmed (earned=3: GT04/05/07), 3 detected-unconfirmed (GT06/09/10),
  1 missed (GT13 SSRF), 6 unknown provenance (GT01/02/03/08/11/12).
- Coverage: 11,137 cells; 319 conclusive (103 confirmed / 126 detected / 90 not_detected);
  7,122 not_applicable; 3,696 skipped; 0 pending/error; 150 legs driven.
- `investigate.chains = 0`, `chain_rounds = 0`; all identities `source: seed`.
- browser_xss confirmations: 0.
- Confirmed-by-class flood: information_disclosure ×365, verbose_error_disclosure ×136,
  CORS ×41, CSP ×41 — all leg-unstamped.
