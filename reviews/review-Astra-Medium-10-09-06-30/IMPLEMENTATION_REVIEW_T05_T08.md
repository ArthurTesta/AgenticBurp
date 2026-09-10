# Review: astra-t05-t08 — T05/R26, T06, T08

Reviewed 2026-09-10 at `e1ac8e9`, branch `astra-t05-t08`, worktree `.worktrees/astra-t05-t08`. Changes compared with `e24ca7f`: four commits, 13 files. Pre-existing uncommitted CURRENT_STATE.md, EXECUTION_LOG.md, and IMPLEMENTATION_HANDOFF.md changes were read for scope and left untouched.

**Decision: request changes for T05 and T06. T08 is an inventory deliverable only; migration and oracle qualification remain open, as its execution log correctly states.** The new bookkeeping and helper tests are useful, but the completion claims for per-parameter testing and reproducible export exceed the implemented behavior.

## Verification

- Bundled Python 3.12, existing `.review-deps` appended to sys.path, unittest modules `test_coverage_cases test_coverage_tracker test_issues test_transport_inventory test_report_generator test_store`: **128 tests passed**, exit 0, 2.231 seconds. Approved access was used for the existing dependency directory.
- `review_t05_t08_checks.py` in this directory: offline synthetic data and temporary SQLite only, exit 0. It demonstrated error/completion misaggregation, occurrence-name collision, exception budget overrun, cross-target issue collision, unknown-input overgrouping, unredacted export markers, mismatched proof verdict enrichment, and lost retest history.
- `git diff --check e24ca7f..HEAD`: exit 0.
- No model, browser/container, blind-target, engagement, or full-suite run. The prior agent's full-suite results remain reported, not independently verified by this review.
- No implementation code changed. Diagnostic output uses synthetic markers, not real credentials, and sends no target requests.

All implementation paths and line references below are relative to `.worktrees/astra-t05-t08/` at the reviewed HEAD.

## R01 — P1: Per-input attribution is fabricated from one whole-request result

**Locations:** `harness/orchestrator.py:1686`, `:1698`, `:2282`; existing cache wrapper at `:1276`.

`_run_leg_core` receives `case_key` but does not pass its coordinates to validation or use them to distinguish the validation request. Each sibling case constructs the same request and same finding class. `_cached_validate` therefore returns the same whole-request result for siblings. Only afterward does `_coverage_proof` stamp each result with a different input coordinate.

Consequently a result concerning one input can be credited to every enumerated input, with multiple case proofs and attempted counts even though no separate input evidence exists. The execution log acknowledges missing validator attribution, but its claim that siblings remain honestly pending is not true when the loop visits those siblings.

**Required correction:** do not label a whole-request result as evidence for a specific parameter without explicit attribution. Retain it at request level and leave unattributed child cases untested/inconclusive. A synthetic production-path regression must supply a result attributed only to input A and verify that B does not inherit its verdict, proof, or execution count. Do not resolve this by merely varying cache IDs: distinct IDs do not establish distinct tests.

## R02 — P1: Coverage still collapses distinct principals into their role

**Locations:** `harness/coverage_tracker.py:443`, `harness/orchestrator.py:1684`.

The new case builder deduplicates identities using `r.role`; the caller maps headers by that same role. Alice and Bob with role `user` become one coverage identity, and the last session overwrites the first. Proof principal IDs then say `user`, not which account supplied evidence. This directly violates the principal dimension of T05 and makes authorization coverage ambiguous.

**Required correction:** use durable principal/session references consistently through case enumeration, reachability, dispatch, and proof recording. Keep role as metadata. Acceptance: two same-role principals and anonymous remain three independent case populations with correctly bound evidence. Coordinate this with the identity track rather than introducing another identity scheme.

## R03 — P1: Export and replay output retain secrets

**Locations:** `harness/issues.py:132`, `:265`, `:293`; `redact()` patterns near `:64`.

`affected_instances` and replay `instances` return raw URLs without redaction. Secret values in query strings therefore survive even though `redact()` knows some query-secret patterns. Redaction of evidence also does not cover JSON key/value secrets. The offline check retained both `?token=SYNTHETIC_URL_MARKER` in export/replay and `{"password":"SYNTHETIC_JSON_MARKER"}` in exported evidence.

**Required correction:** apply structured redaction to every exported field and secret-bearing location, including URLs, userinfo, JSON, headers, and nested evidence. Keep credential-free alias/replay references separate from sensitive local capture data. Acceptance must scan the entire serialized export and replay object for synthetic secret markers; checking only the evidence string is insufficient. Do not describe arbitrary free text as guaranteed secret-free solely because a few regexes passed.

## R04 — P1: Issue identity omits the application and actual authorization boundary

**Location:** `harness/issues.py:154`.

`normalize_path` removes the origin, and the resulting key has no application/target namespace. Same-path, same-class findings on `a.invalid` and `b.invalid` receive identical stable IDs; the offline check reproduced this. Even host-specific exports therefore produce colliding externally visible issue IDs.

The boundary component is only a redundant method-derived `read`/`write` label. It does not distinguish separate tenant/permission boundaries. Missing input attribution also groups all unknowns together: the offline check grouped two distinct unknown-input findings into one issue. Unknown-versus-known separation is not sufficient to meet the conservative grouping requirement.

**Required correction:** include stable application identity and explicitly established issue-boundary coordinates. Preserve separate unattributed cases unless common root cause is established or an operator groups them. Version identity changes and retain retest linkage. Acceptance: different targets and independent same-method boundaries stay distinct, while proven repeated instances remain grouped.

## R05 — P1: Errors disappear and do not consume the case-attempt budget

**Location:** `harness/coverage_tracker.py:288`, particularly `:312`.

`drive_coverage_cases` catches callback exceptions, logs at debug, and continues without recording ERROR or incrementing the budget counter. A callback may have attempted work before failing. Offline diagnostic with budget=1 and three synthetic failing callbacks produced **3 calls, 0 driven, 0 recorded errors**. Returning None has the same uncounted-dispatch problem.

**Required correction:** account for dispatch attempts independently from usable results, preserve case-level operational errors, and expose degraded/incomplete status. Explicitly distinguish unsupported/no-send cases from failed attempts. Acceptance: a budget of one permits at most one attempted callback, its failure is visible, and remaining cases retain an accurate budget/not-attempted reason.

## R06 — P1: A negative child plus an errored child becomes 'all tested'

**Location:** `harness/coverage_model.py:750`.

The aggregation branch checks whether any child is NOT_DETECTED or CONTROLLED_NEGATIVE before checking ERROR. With one controlled negative and one error, the offline diagnostic returned `not_detected` and **"all 2 case(s) tested, none detected"**. The parent thus makes a successful completion claim despite an unresolved child.

The new driver also maps legacy `not_confirmed` and unknown status strings to NOT_DETECTED. These may be observations rather than controlled negatives, so the coverage report can disagree with the corrected T01 inconclusive proof.

**Required correction:** separate risk, execution, and completion semantics. An errored or inconclusive child prevents complete-negative aggregation. Unknown statuses fail conservatively; use the qualified evidence verdict rather than a second optimistic mapping. Acceptance covers negative+error, negative+blocked, unknown status, and retired observation results.

## R07 — P2: Repeated-parameter encoding collides with literal names

**Location:** `harness/coverage_model.py:170`.

Occurrence 1 of `id` becomes proof parameter name `id[1]`, identical to occurrence 0 of a literal parameter named `id[1]`. These are distinct CaseKey coordinates but produce the same proof coordinate and therefore can share a TestCaseRef ID. The offline diagnostic confirms the name collision.

**Required correction:** encode occurrence as a distinct versioned field or use an unambiguous structured encoding. Acceptance: `id=a&id=b&id[1]=c` yields three distinct case/proof identities through persistence, not just three in-memory coordinate hashes.

## R08 — P1: Storage discards retest history before export can preserve it

**Locations:** unchanged integration dependency `harness/store.py:287`–`:305`; new consumer `harness/report_generator.py:475`.

T06 groups supplied members correctly in memory, but `export_issues_for_host` reads the existing findings store. Its fingerprint excludes case/proof/run IDs, and INSERT OR IGNORE drops a later same-summary observation. Offline diagnostic persisted an initial confirmed case and a later unconfirmed retest at identical coordinates: only the initial case remained in `all_host_findings`.

This is a pre-existing persistence behavior that blocks the new T06 history-preservation claim, rather than a new SQL regression. New in-memory grouping tests do not exercise it.

**Required correction:** retain append-only case/retest membership independently of display-finding deduplication, then export that history. Do not replace the old proof or erase the original issue. Acceptance: two runs survive storage/export with distinct attempts and one stable issue, including a patched retest outcome.

## R09 — P2: Export associates one proof's ID with another proof's verdict

**Locations:** `harness/issues.py:222`, `harness/report_generator.py:483`.

The reference takes `proof_id` from the finding, but enrichment takes the best proof for its case. If those differ, the output claims a verdict for the wrong attempt. Offline diagnostic supplied `proof-old` on the member and a confirmed `proof-new` as best for the case; export emitted `proof-old` with verdict `confirmed`.

**Required correction:** resolve verdicts by exact proof ID and verify case membership. If showing the best case proof, emit that proof's actual ID as a separate reference. Acceptance covers multiple outcomes within one case and rejects inconsistent references.

## R10 — P2: 'Reproducible export' is generic instructions, not the captured sequence

**Locations:** `harness/issues.py:234`–`:307`, `harness/report_generator.py:464`.

The export generates generic three-step instructions from method and endpoint family. Replay output has no actual request body, content type, captured step order, baseline/control exchanges, or resolvable artifact set. Every GET issue receives an authorization-read invariant regardless of vulnerability class. Member-specific evidence beyond the best member is not exported, despite being retained temporarily inside Issue.

The new machine-readable export functions also have no non-test caller outside their helper chain; the existing public report flow only adds IDs to the old Markdown output. Burp UI can remain deferred, but T06 still needs a usable deliverable and honest completeness checks.

**Required correction:** export the captured case sequence and actual evidence-derived invariant with safe credential references, preserve member proof details, and explicitly mark missing artifacts/non-replayable cases. Provide an existing API/CLI/operator entry point. Acceptance must verify artifact resolution and required replay fields, not merely the presence of field names. This is an evidence/export requirement, not permission to invent reproduction instructions.

## R11 — P2: The inventory guard does not enforce new outbound call sites

**Location:** `harness/transport_inventory.py:209`.

The scan records module names containing either of two exact strings. A new direct client construction inside an already registered module leaves the set unchanged; aliased imports and other transport APIs are not discovered. Browser/container/socket entries are manually checked for a few known filenames only. Thus the documented claim that new direct outbound sites cannot appear unnoticed is stronger than the test guarantees.

**Required correction:** describe the current check as a module inventory, or strengthen it to identify concrete construction/send sites and transport families. Add negative controls for an extra direct site in a registered module and an aliased constructor. Track executor-policy integration separately: adding an owner to inventory is not authorization enforcement.

## Additional T05 scope gaps

- Child cases are expanded only for parent cells still pending. A prior endpoint-level confirmed/detected finding can prevent untested sibling inputs from being enumerated at all. Test this before claiming complete case visibility.
- Production template derivation omits headers and never supplies a workflow state to expansion, although the standalone CaseKey model supports them. Explicitly record these dimensions as deferred; their helper tests do not establish production coverage.
- `_coverage_proof` does not forward explicit execution/control artifact metadata from results. Qualified negatives therefore cannot follow the same proof contract as the corrected captured-exchange path. It also inherits the previously reviewed singleton run-ID issue; coordinate with the identity track.

## Ticket outcome and correction order

| Ticket | Assessment |
|---|---|
| T05/R26 | Partial. Case schema exists, but attribution, principal identity, accounting, and completion remain incorrect. Do not mark DONE. |
| T06 | Partial. In-memory grouping and formatted output exist; confidentiality, identity isolation, durable history, and actual replay evidence fail acceptance. Do not mark DONE. |
| T08 | Inventory-only, correctly disclosed as partial. Narrow/strengthen the guard claim. Transport migration and oracle qualification remain open. |

Priority: export confidentiality (R03); false coverage/proof attribution and accounting (R01/R02/R05/R06); identity/history integrity (R04/R07/R08/R09); deliverable completeness (R10); inventory enforcement (R11). Coordinate identity/run-context dependencies with the other worktree. Retain safe defaults and re-run focused checks plus required release tests after fixes; no live effectiveness claim follows from these 128 green tests.
