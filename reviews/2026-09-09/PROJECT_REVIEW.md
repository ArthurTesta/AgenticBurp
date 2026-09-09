**AgenticVibe — engineering, architecture, pentesting, and product review**

Reviewed 9 September 2026. Baseline HEAD: `319f0ef`; review includes the pre-existing uncommitted changes. This is an evidence-based review and implementation roadmap, not a certification of every vulnerability detector.

**Overall judgment**

Keep the project, but stop expanding its detector count until execution and evidence are trustworthy. The most valuable foundation is the combination of captured Burp traffic, deterministic verification, explicit identities, and a graph of follow-up work. The current implementation loses important information between those components, has several false-confirmation rules, and measures activity as coverage. Those defects explain substantially more than a generic claim that the local model is too small.

The project is an ambitious research copilot with useful components. It is not yet a reliable coverage engine or a source of automatically submission-ready findings. Increasing raw finding counts would currently make that distinction harder to see.

**Scope and evidence discipline**

- Inventoried and AST-parsed all 254 Python files under `harness/`: 57,610 lines, including tests, comments, and docstrings. This is a size/inventory measurement, not a claim of 57,610 executable lines or line-by-line semantic verification.
- Inspected the principal entry points, graph, coverage, request construction, identity handling, cache, scheduler, model boundary, confirmation dispatch, major verification oracles, persistence/reporting, Burp client/build/selected executor logic, dependencies, CI, and newer run artifacts.
- Included the pre-existing dirty changes: 13 tracked files, 809 insertions and 51 deletions at the initial snapshot, plus untracked validator/test/notes and target artifacts. These are not changes made by this review.
- Did not read answer keys, blind target application source, or the archived handover chain. Did not use target internals to design fixes. Only the published run summaries/logs/results were inspected for the current target.
- Reproductions are in `reproduce_review_findings.py`, with recorded output in `reproductions.json`; the complete Python file inventory is in `source_inventory.json` beside this report.
- **R** below means reproduced with a small offline command; **S** means directly established from source/control flow; **A** means observed in a saved artifact, not freshly measured against the target. Suggestions and risks are explicitly separated from those findings.
- No fresh full model/target benchmark or real Burp/Gradle build is claimed. Test execution details are in `VALIDATION.md`.
- No percentage improvement or completion date can responsibly be promised before repairing the measurement path. The relative contributions of discovery, routing, model quality, and validators require controlled ablation runs.

**What the latest available results actually say**

The rolling handover says the session-16 measurement is still pending. Files under `testing/vulncorp-helpdesk/maxrun/` contradict that: `maxcov_results_s16_full.json`, `recall_report_s16_full.md`, and `report_s16_full.md` exist, with a generated timestamp of 2026-09-09 14:52 UTC.

| Measure | Saved result | Interpretation |
|---|---:|---|
| Runtime | 10,085.7 seconds / 2.802 hours | Observed artifact value, not a fresh benchmark |
| Explicit analyze inputs | 37 | This is not the discovered-surface denominator |
| Fused findings / raw confirmations | 712 / 71 | Raw instances, not unique vulnerabilities |
| Final report | 20 confirmed, 181 unconfirmed, 6 chains | Deduplication/reporting projection differs from raw output |
| Collapsed duplicates | 505 | Substantial duplication; not an accuracy improvement |
| Documented endpoint-known recall | 8/13 confirmed, 3/13 unconfirmed, 2/13 missed | 61.5% confirmed on this subset only; not recall against all planted bugs |
| Graph outcomes / chain rounds | 9 / 0 | Little iterative output relative to overall workload; no credential round in this artifact |
| Coverage cells | 10,878 | Role × endpoint × check, not parameter-level executable cases |
| Claimed tested cells | 4,025 | Includes 3,633 skipped cells because of the implementation |
| Other cell statuses | 19 confirmed, 67 detected, 306 not_detected, 6,853 not_applicable | Even the 306 negatives are not reliable execution evidence |
| Coverage legs driven | 150 | Not equivalent to 150 unique network tests; memoization and skips matter |

Only 392 cells are in confirmed/detected/not_detected states, about 9.7% of the 4,025 cells outside not_applicable. That still is **not verified execution coverage**, because detection is not execution and negative cells can be inferred without a run. Do not replace the misleading 4,025 with another misleading success percentage.

The recall artifact labels seven confirmations “lucky.” The scorer treats missing leg provenance as “lucky,” and uses the first matching confirmation. Consequently that label does not establish seven accidental discoveries. It partly measures missing metadata and result ordering. The artifact also calls several now-implemented legs absent and retains a session-13 title: its explanatory text is stale.

A particularly useful inconsistency: the final report confirms a JWT signing-key disclosure at the debug endpoint, while the recall table calls the information-disclosure item unconfirmed. Category semantics and matching must be reconciled before treating either presentation as the definitive metric.

**What is good and should be preserved**

| Foundation | Why it is useful | Qualification |
|---|---|---|
| Captured HTTP exchanges as the main input | Grounds work in real requests rather than model-invented endpoints | Preserve the full exchange throughout the graph |
| Deterministic confirmation separated from model suggestions | Correct division of responsibility | Deterministic code can still implement a wrong oracle |
| Shape-driven confirmation | Avoids requiring the LLM to name every vulnerability first | Current graph requests often lose the shape |
| Browser execution and OOB callbacks | Can establish execution beyond simple reflection | Need authenticated browser state, scope and trustworthy attribution |
| Independent write/read verification | Better evidence than an echoed mutation | Needs object binding, expected authorization and cleanup |
| JWT HMAC verification of a disclosed key | Strong mathematical evidence of the specific key relationship | Does not by itself establish which privileges a forged token grants |
| Role crawling and anonymous controls | Valuable starting point for authorization testing | Role labels are not identity IDs or ownership proofs |
| Engagement state and dependency graph | Useful representation for follow-up work and human blockers | Data loss and incomplete feedback currently undermine it |
| Burp sitemap import | Human browsing can supply workflow requests a wordlist cannot | Current parser is not lossless HTTP capture |
| JS mining, OpenAPI path discovery, soft-404 calibration | Existing discovery breadth worth extending | OpenAPI discovery is not full schema-driven request construction |
| Container-based sqlmap/ffuf with argument arrays | Reproducible tool versions and no arbitrary shell command generation | Containerization alone does not enforce target scope or budgets |
| Safe committed configuration and local overrides | Good operator control and deployment default | Several direct execution paths bypass portions of this policy |
| Model token ledger, concurrency limit, circuit breaker, fail-open telemetry | Real cost accounting and useful operational controls | Too many controls remain global or cover only one execution path |
| Prompt versions, bounded inputs, header redaction | Useful provenance and privacy foundations | Whole-input blocking also rejects relevant security evidence |
| Paired fixtures and end-to-end pipeline smoke tests | Much better than unit-only testing | The model boundary remains stubbed; some transport mocks are too permissive |
| Typed Burp plans and exchange-bound validation submissions | Reduces result/request mix-ups | Needs the same evidence contract as Python |
| Pure Java logic separated from Montoya | Facilitates testing outside Burp | Real compilation and parity gates are still required |
| Reports distinguish hypotheses and chains | Correct direction for analyst trust | “Confirmed” currently mixes exploit proof with structural observations |
| Explicit human-verification tasks | Honest treatment of unknown business intent | Needs an actionable evidence packet and clear completion criteria |

**Critical correctness and integration findings**

Priorities below are engineering priorities: P0 means fix before trusting broad active-run claims; P1 means directly limits useful results; P2 means maintainability/product maturity. They are not CVSS ratings.

| ID | Priority / evidence | Finding, impact, and concrete repair |
|---|---|---|
| R01 | P0 · R/S | **Coverage invents executed checks.** `coverage_tracker.py:mark_leg_attempts` turns every pending leg-backed cell on an “investigated” endpoint into not_detected, across identities, without knowing which leg ran. Offline reproduction marks 16 cells as run with no execution. Remove inferred attempts; consume immutable execution events. |
| R02 | P0 · S/A | **Skipped counts as tested.** `coverage_model.py:summary` excludes only pending/not_applicable. It includes skipped, error and running. In the saved run, 3,633 of 4,025 “tested” cells are skipped. Define attempted, completed, conclusive and confirmed separately. |
| R03 | P0 · S | **Confirmation cache ignores identity and evidence context.** `orchestrator.py:1165` keys on validator/method/URL/body only. Different cookies, bearer tokens, baselines, finding subtypes and later target states collide. This can replay an administrator's result into another identity's cell, or a skip into a valid request. Include run, identity/session generation, exact request, validator/config version and hypothesis/parameter; invalidate after mutation. |
| R04 | P0 · R/S | **File upload cannot run through its real wrapper.** `file_upload_validator.py:75,128` call `.post()`/`.get()`; `GatedAsyncClient` exposes only `.request()`. An AttributeError occurs before the upload request. The deferred-leg tests replace the wrapper with unrestricted AsyncMocks. Fix the API use and add a real-wrapper/local-server test. |
| R05 | P0 · S | **Graph replay discards original request shape.** `worklist_investigator.py:_seed_exchange` creates empty bodies and response metadata, replaces every `{id}` with `1`; `engagement.normalize_path` removes query strings. Coverage calls this same builder. XML, SSRF URL fields, form bodies, upload parts, denial baselines and observed IDs disappear. Store/replay captured request templates and object bindings. |
| R06 | P0 · S | **Coverage confirmations do not enter the finding pipeline.** `_run_leg` returns a result to the matrix; `drive_coverage_legs` only records a cell. It does not ingest a finding into state, outcomes, persistence, chain linking or report generation. A successful check can improve a coverage count while remaining absent from the analyst's confirmed findings. Use one result ingestion path. |
| R07 | P0 · R/S | **Confirmed graph findings can be downgraded by a later hypothesis.** `SurfaceEndpoint.add_finding` permits replacement when incoming confidence is greater, even if the existing result is confirmed. Reproduced: confirmed 0.9 becomes unconfirmed 0.99. It also drops evidence, URL, validator, summary and identity. Preserve proof and history; never use model confidence to overwrite a proof. |
| R08 | P0 · S | **Nonconfirmation is treated as refutation without checking execution.** `apply_confirmation_suppression` accepts validation reports but never consults them. A disabled validator, missing browser, unsupported body, transport error, exhausted budget or negative result all lead to the same class-tier demotion. Keep unknown/blocked/error/inconclusive distinct from a controlled negative. |
| R09 | P0 · R/S | **Provisional subclasses inherit live status via substring matching.** `leg_tier('dom_xss')` returns live because of `xss`; `leg_tier('privilege escalation race')` returns live because of `privilege escalation`. This defeats the stated promotion policy. Resolve exact canonical technique IDs, with separate verification metadata. |
| R10 | P0 · S/R | **Identity separation is not enforced at authorization confirmation.** The graph registers sessions under `r.role`, overwriting same-role users. `CrossIdentityValidator.validate` tries all configured identities without excluding the source credential; it passes the same candidate as both source and candidate. The comparison confirms identical candidate/attempt responses when anonymous is denied. Require distinct principal IDs and a known owner/entitlement relationship. The offline comparison reproduction demonstrates the missing precondition, not a live target flaw. |
| R11 | P0 · S | **BFLA assumes path naming establishes policy.** `_confirm_bfla` treats a non-admin obtaining a >20-character 2xx response from an admin-looking namespace as a confirmed boundary crossing. An admin namespace is a lead, not an entitlement specification; delegated/read-only access may be legitimate. Require expected permissions or a controlled privileged operation/data oracle. |
| R12 | P0 · R/S | **Second-order SQLi confirms harmless storage/display.** `confirm_second_order_sqli` equates different returned text after two different stored strings with SQL evaluation. A literal echo crosses its similarity threshold and reproduces confirmed=True. Mask payload reflection, establish stable baselines, alternate controls, prove a SQL-dependent semantic change, and verify state isolation. |
| R13 | P0 · S | **Other second-order integration is not a valid authenticated workflow.** `_plant` sends an anonymous POST with guessed fields and suppresses all failures; `_read` defaults anonymous; IDOR chooses the first authenticated role rather than explicit owner/attacker. There is no created-object binding or production reset. Preserve successful write semantics, identity, content type, actual field and trigger relationship. |
| R14 | P0 · S | **Uncommitted discovery chain routing assigns every candidate to SQLi.** The discovery loop retains `dc['kind']` only in labels but sets execution `kind='sqli'`. Different chain kinds receive the SQLi oracle. Also `state.captured_exchanges` is read although the builder does not populate that field; discovery captures can be lost. Route typed candidates to supported executors and use the actual capture store. |
| R15 | P0 · S | **Active settings are not consistently authoritative.** Graph validators are directly constructed and invoked without registry enabled/active checks; GETs pass `SafetyGate.authorize` even when active is false. The graph also ignores most per-validator settings, including disabled state and browser/CDP options. Use registry-created instances and an explicit run execution policy for every entry point. |
| R16 | P0 · R/S | **The per-finding mutation ceiling is declared but not enforced by the gate.** `max_mutating_requests_per_finding` is never counted in `authorize`; three POST authorizations pass with a configured ceiling of one. There is no finding ID in its API. Add run/action IDs, atomic reservations and actual request accounting. |
| R17 | P0 · S | **Scope/transport policy is fragmented.** The gate has no host policy; its wrapper authorizes only the initial request and string bodies. Auto-followed redirects are internal to httpx; bytes/multipart content does not receive the same inspection. File-upload retrieval trusts a response-provided URL and reuses captured headers. Centralize origin/path scope, redirect checks and cross-origin credential stripping. |
| R18 | P1 · S | **The graph investigation is not wired to the normal server engagement API.** `server.py` exposes run_engagement and advance/crawl, but has no call to investigate_engagement. Burp's UI consequently cannot invoke the flagship path through these endpoints. Expose one resumable engagement job API and wire the product UI to it. |
| R19 | P1 · S | **The credential feedback loop is effectively disconnected.** `chain_linker.link_findings` extracts credentials from its optional response map; `investigate_engagement` does not supply that map. Derived state `st2` is not merged into the original state. Closures also retain original roles/validator identity setup. Feed exact response references and merge discoveries under explicit new identities. |
| R20 | P1 · S | **Chain projections discard provenance.** `_chain_input` omits confirmed, basis, evidence and identity. `chaining.detect` cannot reliably distinguish verified from speculative inputs after that projection. Carry finding IDs and evidence references; compose hypotheses separately from executed chains. |
| R21 | P1 · S | **One confirmed issue suppresses further work on the endpoint.** The worklist skips status=validated nodes, although one endpoint can hold unrelated vulnerabilities. Completion belongs to an identity/request/parameter/check case, not the entire endpoint. |
| R22 | P1 · S | **Iterative investigation is still predominantly authorization-specific.** `_derive_probe` produces only idor/auth hypotheses; otherwise it returns None. Shape legs add breadth but cannot repair missing payload-bearing exchanges. Generate work from applicable checks and observed input types, not just access anomalies. |
| R23 | P1 · S | **Precondition budget counts successful confirmations, not attempts.** `precondition_run` increments only when findings exist; `max_precondition_legs` is neither a request nor a leg-attempt budget. Count attempted cases and requests separately before execution. |
| R24 | P1 · S | **Feature crawling is not a persistent authenticated workflow engine.** Production opens a new client for every request, never adopts new cookies into role state, fails to set form Content-Type explicitly, ignores select options/textarea content/multipart semantics, and only follows submitted redirects. GET forms are ignored when submit_forms is false; the inner form loop can exceed max_steps. Retain sessions, parse actual controls, process form responses and enforce budgets per send. |
| R25 | P1 · S | **Browser checks lose authentication.** BrowserDriver.visit accepts only URL/wait time; PlaywrightDriver creates a fresh context without supplied cookies, headers or storage. Authenticated XSS sinks are tested as anonymous. Supply per-identity isolated browser contexts and route all navigations/subrequests through scope policy. |
| R26 | P1 · S | **Parameter coverage is absent from the matrix key.** Cells have identity/endpoint/check, no input location/name/JSON pointer. Predicates see path/method/access rather than real inputs; unknown shape becomes not_applicable. Query stripping compounds this. Add explicit input instances and unknown applicability; deduplicate domain checks at the origin level. |
| R27 | P1 · S | **Role and identity are conflated throughout the model.** Same-role users collapse into one matrix column; feature crawl groups role words and may omit tenant-specific surface. Trust order differs between modules, and custom labels often become generic trust=1. Model principal, role, tenant, session, owned objects and expected permissions separately. |
| R28 | P1 · S | **Validation results bind to raw class labels rather than finding/case IDs.** `_validate_findings` groups confirmed output by finding_class and matches exact free text. Some validators return canonical names, so synonyms can miss confirmation; several same-class hypotheses can inherit one result. Bind by finding/case ID and use canonical classes for display/routing only. |
| R29 | P1 · S | **Captured-exchange validation has unbounded fan-out and duplication.** `_validate_findings` gathers every finding×validator job concurrently, with no shared per-case memoization. Agent concurrency does not bound this phase; stateful probes can interfere. Schedule bounded, dependency-aware jobs and serialize mutations to the same resource. |
| R30 | P1 · S/A | **Operational failures disappear into empty outcomes.** `_confirm` branches return on exceptions; coverage exceptions can return an empty dictionary; coverage-driver failures remain pending and are later labeled budget misses. Saved logs also contain prompt-validation failures. Preserve explicit error events and declare degraded/incomplete runs. |

**Confirmation-oracle audit: what “confirmed” currently proves**

The important question is not whether a validator is deterministic. It is whether its observations exclude a benign explanation and prove the reported security boundary.

| Family | Assessment | Required change / negative control |
|---|---|---|
| SQLi/sqlmap | Stronger when the actual tool establishes injection; fallback and provenance need separate status | Record tool image/version, exact parameter and proof; test missing-tool behavior and stable false controls |
| Reflected/stored/DOM XSS | Real browser execution is valuable, but auth state is missing; DOM support is fragment-focused | Authenticated victim context, nonce-specific execution evidence, escaped/inert controls, other client sources as separate cases |
| JWT forgery | Forged token plus garbage-signature control is useful | Separate acceptance from demonstrated privilege; do not mix secret disclosure into forgery coverage |
| Secret disclosure | HMAC matching proves the observed string signs a presented JWT | Keep it; add authorization context and a redacted proof packet; general secret leakage remains a different capability |
| XXE/SSRF/command injection/deserialization OOB | Callback can be strong evidence | Identify the initiating execution and distinguish a plain URL fetch from shell/deserialization execution; delayed callback windows and controls required |
| SSTI | Nonce-wrapped arithmetic gives a concrete effect | Prove template evaluation only; do not promote automatically to arbitrary code execution |
| Traversal | Recognizable file content is stronger than status/length | Independent baseline, platform-specific controls, restricted-scope reads, exact affected input |
| IDOR/BFLA | Current principal and policy assumptions are insufficient | Two distinct controlled principals, ownership/tenant separation, expected denial and equivalent operation |
| Sequence/mass assignment | Independent persisted field read is useful | Demonstrate the caller was not entitled to set it; prove functional privilege where claimed; use correct read endpoint and cleanup |
| CSRF | **Overconfirms.** Token-name regex substitution and a 2xx replay do not prove a victim browser can send the request or change state. No Set-Cookie in this response is not proof of no SameSite policy; bearer headers may be non-ambient | Cross-site browser PoC with ambient credentials and independent state verification; controls for bearer-only JSON, Origin enforcement, default SameSite and 200 error pages |
| File upload | **Broken transport plus insufficient oracle.** Serving a `.html` comment does not establish an intended filter or dangerous execution context | Fix R04; preserve upload fields/method; check policy and served Content-Type/Disposition/origin; benign attachment-serving control |
| Verb tamper | **Overconfirms.** A POST 405 with a working GET can be correct routing, not auth bypass | Compare equivalent protected data/action under the same unauthorized principal; public GET/private write control |
| Rate limit | **Overconfirms.** Dirty code confirms after as few as two completed requests and counts non-throttle errors as completed. Valid logins cannot establish failed-login lockout behavior | Report only “no throttle observed in N attempts over T”; use authorized test accounts, explicit policy/window, invalid-credential control and cooldown/reset |
| Reset token | **Overconfirms.** Reusing an unexpired random token can be legitimate; a public prefix plus strong random suffix is not predictable. Two numeric samples always have a constant delta | Separate observation from exploitability; require holdout prediction/acceptance, lifetime, single use, rate limits and the random component's entropy |
| TOCTOU | **Overconfirms causality.** Concurrent writes plus a field flip also occurs with ordinary mass assignment; no serialized comparison is performed | Fresh-state serialized negative control, synchronized concurrent experiment, repeatable invariant violation and post-state check |
| Session fixation | Cookie nonrotation can be observed after failed login or for a non-auth cookie; current code does not prove authentication before confirming | Replay old session from a separate client after successful login and verify authenticated identity |
| Weak password | 2xx/no policy phrase is not proof that the account was created or can authenticate | Independent login/account verification, activation handling and cleanup; 200 validation-error control |
| Username enumeration | Some differential support exists; dirty changes widen it | Repeated known/unknown account controls, timing noise and rate-limit handling; distinguish error shape from account existence |
| Passive deserialization | **Format observation becomes vulnerability confirmation.** A Java/PHP/ViewState signature can set confirmed=True for insecure deserialization | Emit an informational format observation; active exploitability needs a separate oracle |
| Web cache poisoning/deception | **Reflection or cache-friendly responses become vulnerability confirmations without persistence/private-data proof** | Keep these as candidates; require a clean second-client retrieval of attacker influence/private data under controlled cache keys |
| Request smuggling | **Status changes, unexpected length, or 404 can become critical confirmations.** `_send_raw_request` uses ordinary httpx and does not guarantee the claimed raw framing/connection relationship | Downgrade to candidate or disable autonomous verdict; protocol-specific transport and paired front/back-end fixture required |
| CORS/CSP/crypto/recon/verbose errors | Useful structural observations, not automatically exploitable bugs | Distinguish confirmed configuration facts from sensitive cross-origin reads, frameability impact, TLS vulnerability and real secret exposure |
| OAuth/WebSocket/subdomain takeover/API-security/race_condition | Implementations exist; presence is not a blanket verified-capability claim | Require dedicated multi-party/protocol/provider/invariant fixtures and expected-policy controls before promotion |

Browser CSRF checks must reflect actual browser request and cookie behavior, as described by [OWASP WSTG's CSRF testing guidance](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery). Concurrency is evidence of a race only when an application invariant is violated under the relevant timing; see [PortSwigger's race-condition methodology](https://portswigger.net/web-security/race-conditions). These support the review criteria, not claims about this target.

**Additional engineering and product weaknesses**

1. **Prompt validation can censor the evidence being tested (S/A).** `prompt_validator.py` rejects code-execution patterns in user data. A scanner must be able to analyze code snippets and malicious prompts as data. The saved run has “Blocked pattern detected in user prompt” errors. Protect the action boundary, label untrusted content and bound its size; do not treat a malicious-looking captured string as permission to silently skip analysis.
2. **Cache invalidation is incomplete (S).** `CacheEntry.is_stale` checks model and overlapping prompt versions, not pipeline version, active configuration, validator versions or newly added agents. Cold-cache operation is a manual hazard. Version analysis artifacts by their complete execution manifest.
3. **Global mutable state undermines run isolation (S).** Validator construction resets a process-wide safety gate; transient identity headers are indexed by hostname; circuit breaker, throttling and telemetry have shared globals. Concurrent engagements/config changes can interfere. Shared service resource limits can remain global, but authorization and evidence state must be per run.
4. **Report dedup is not root-cause identity (S/A).** Store fingerprints include summary wording; graph dedup uses raw class; reports normalize class/path differently. One shared JWT verifier becomes many endpoint findings while distinct bugs in two parameters can collapse. Store a stable issue ID, affected cases and proof records separately.
5. **“Steps to reproduce” can actually be remediation (A).** The current signing-key disclosure report instructs rotation in its reproduction field. Submission-ready output needs prerequisites, exact redacted requests, expected/actual results, impact and controls, not generic advice copied into a procedural field.
6. **Provenance is text parsing (S).** `recall_benchmark.confirmation_leg_of` parses evidence text and hints rather than an execution FK. `_provenance` conflates unknown with wrong route; scoring selects first matching confirmation. Add unknown provenance, complete case matching and deterministic best-proof selection.
7. **WSTG labels are not a complete or consistently correct work program (S).** The catalog has 37 checks; a phase=parameter label does not enumerate parameters. For example CSRF is labeled WSTG-SESS-09 while current WSTG CSRF is SESS-05. Version mappings and use project-owned stable check IDs, with external references as metadata.
8. **OpenAPI support stops at routes/methods (S).** `_spec_paths` extracts path/method combinations but no required parameters, schema examples, request body, content negotiation or response links. This is an extension of an existing feature, not a request to build OpenAPI discovery from scratch.
9. **The sitemap representation is lossy (S).** `_split_message` collapses repeated headers and normalizes line endings, while `_maybe_b64` decodes arbitrary bytes as UTF-8 with replacement. This loses Set-Cookie multiplicity, binary bodies and exact framing. Keep raw bytes plus a parsed analysis view.
10. **ffuf accounting/fallback is unreliable (S).** Its subprocess does not draw each request from the global throttle or Python discovery counter. If JSON parsing finds no routes, silent parsing can turn arbitrary output lines into paths. Add tool-specific request/time limits and strict versioned result parsing; surface fallback use.
11. **Tool timeout cleanup needs verification (S/risk).** `tool_runner.run` controls the docker CLI subprocess, without explicit container ID cleanup; killing the client need not prove the workload stopped. Track container lifecycle and verify termination with an owned-container test.
12. **Many raw HTTP clients discard session and connection reuse (S).** This adds handshakes and divergent behavior; some validators intentionally omit auth. Make anonymous probing explicit, otherwise retain the chosen session.
13. **Content truncation is blind to location of evidence (S).** Single-shot prompts clip bodies, and iterative responses are limited to 1,200 characters. Important HTML sinks or error details can be outside the visible prefix. Extract structural evidence with offsets and mark every truncation; retrieve relevant slices on demand.
14. **The DAG treats skipped as a successful prerequisite (S).** `_SATISFYING=(DONE,SKIPPED)` lets skipping a required credential/authorization task unlock dependents. Distinguish optional steps from required capabilities; validate cycles and impossible dependencies.
15. **Packaging is intentionally incomplete (S).** Flat top-level imports and working-directory assumptions prevent a standard installable package. The review's initial shell had no Python on PATH; the bundled Python lacked project dependencies. Reproducible setup is a feature, not housekeeping.
16. **Dependency declarations differ in scope (S).** Requirements include browser support while the project metadata treats it as optional; the lock also includes Windows proxy/test dependencies. The lock is not split by supported environment and test tier. Declare extras and resolve reproducible environments per tier.
17. **CI omits the decisive gates (S).** `.github/workflows/ci.yml` runs Python smoke/unit and score math; the real scored job is permanently disabled (`if: false`). No Java build job or required real-browser job is defined there. Passing this CI cannot establish model/target recall or Burp compatibility.
18. **The onboarding has become the archived chain again (S).** CURRENT_STATE.md is 737 lines with session 9–16 sections, stale “next” lists and contradictory verification states. AGENTS.md and CLAUDE.md duplicate orientation; even the provisional count differs. Generate capability status from tests/registry and keep one short current delta.
19. **Some comments are unsupported product claims (S).** Fixed token-saving percentages, blanket “zero false positives,” benchmark-target IDs and unverified industry percentages appear in code/docs. Keep mechanisms and evidence references; remove claims that have no maintained measurement.
20. **No complete operator workflow is established for the flagship engine (S).** There are useful activity/settings/engagement panels, but no single run manifest → preflight → job → pause/resume → coverage drilldown → evidence export path for investigate_engagement. Integrate that path before adding more panels.

**What can be deleted, consolidated, or retired**

This review does not delete product files or pre-existing work. “Candidate” means deletion needs the stated dependency check; absence of an obvious import is not enough for dynamic plugins or externally invoked scripts.

| Candidate | Disposition | Gate before deletion |
|---|---|---|
| Inferred `mark_leg_attempts` negatives | Delete the behavior as part of R01 | Replace with execution-event ingestion and regression test |
| Substring-based leg promotion lists | Replace, then delete duplicated matching logic | Registry technique IDs and compatibility mapping for stored findings |
| Giant graph `_confirm` class string switch and parallel validator construction | Consolidate into registry executor, then remove | Entry-point parity tests for all supported cases and config |
| Passive deserialization vulnerability confirmation | Delete that verdict, retain format extraction | Informational observation plus separate active proof path |
| Smuggling/cache/rate/reset/CSRF weak “confirmed” verdicts | Retire those claims until their oracles qualify | Negative controls and independent effect proof; keep useful candidates |
| `testing/blind-test-kit/harness/` | 90 tracked snapshot files: package/distribute from a pinned revision instead | Confirm whether the kit must remain standalone; preserve reproducibility manifest before removal |
| Multiple `run_real_analysis*`, `phase_real_run*`, target-specific maxrun scripts | Consolidation candidates into one benchmark CLI | Compare configuration, inputs, output schema and scoring; preserve historical manifests/results |
| Runtime DBs, captured logs, generated reports, build output, bytecode, temporary review dependencies | Removable/regenerable only when not required evidence or active state | Retention/export check, exact paths, no running process; captures may contain credentials |
| Old session narratives inside CURRENT_STATE.md | Remove from rolling state after retaining historical reference | Keep only verified HEAD, dirty state, latest artifact, current blockers and commands |
| Duplicated AGENTS.md/CLAUDE.md prose | Consolidate to one authoritative orientation plus pointer | Confirm which tools consume each filename |
| `business_logic` / `business_logic_enhanced` and `ai_llm` / `ai_security` parallel prompts | Consolidation candidates, not proven duplicates | Measure unique true-positive contribution and cost on held-out cases; retain coverage-specific rules |
| Per-agent classes consisting only of text | Convert to declarative specialist specs | Preserve plugin extension API, prompt versioning and external consumers |
| Multiple budget/ranking helpers | Simplify ownership, do not delete by name | Trace risk allocation, run budget, per-case budget, retries and model ranking separately |
| Legacy Java stubs/dev runner | Retire after real Gradle CI is stable | Ensure offline fixture developers do not still require them |
| Dead module-level upload marker constants and unused imports | Safe cleanup candidates | Static reference check; no benchmark effect expected |
| Stale report templates and unsupported percentage claims | Delete or replace with generated facts | Keep original run evidence and clear version attribution |

Keep safety controls, paired negative fixtures, confirmation controls, model telemetry, human-review tasks and evidence artifacts. Removing these to get cleaner output or faster “green” tests would repeat the project's known failure mode.

**Missing or incomplete features — must / should / could / don't**

“Must” means necessary for trustworthy supported behavior, not that every pentesting technique belongs in the next release. Existing-but-incomplete features are marked explicitly.

| Priority | Feature | Current state / acceptance condition |
|---|---|---|
| MUST | Immutable execution/evidence ledger | Missing common contract; every reported attempt/confirmation must reference exact requests, responses, case ID and validator version |
| MUST | Canonical request templates and concrete input bindings | HttpExchange exists but graph loses detail; preserve method/query/body/header multiplicity/content type/object IDs |
| MUST | Principal/role/tenant/session/ownership model | Identity machinery exists but conflates labels; Alice and Bob of role user must remain distinct |
| MUST | One policy-aware executor for all entry points | Registry/gate exist but are bypassed; identical settings must yield identical allowed actions in scripts, API and Burp |
| MUST | Honest result state machine | Add unsupported, blocked, dependency_missing, error, inconclusive, controlled_negative, confirmed; no inferred execution |
| MUST | Sound negative controls for each promoted oracle | Add the benign alternatives in the oracle table; safe fixtures must not confirm |
| MUST | Independent finding/observation/chain types | A configuration fact or parsed format must not auto-confirm a vulnerability |
| MUST | Per-parameter executable coverage | Extend matrix to input locations and exact cases; unknown must not become not_applicable |
| MUST | Stateful authenticated HTTP/browser sessions | Preserve refresh/login/cookies/storage and session health; expire/re-authenticate explicitly |
| MUST | Typed successful workflow steps and object provenance | Extend sequence and second-order primitives; bind plant output into trigger input and preserve authorization context |
| MUST | Enforced request/mutation/time budgets and cleanup | Count actual sends across Python, browser and containers; track created objects and incomplete rollback |
| MUST | Run manifest and preflight | Record code+dirty-diff hash, config hash, model digest, tool versions, target reset ID, scopes and capabilities; reject misleading scored runs with missing requirements |
| MUST | End-to-end release gates | Python pipeline + real transport controls + real browser + Gradle compilation/tests + scheduled model benchmark |
| MUST | Unified issue/report ingestion | A coverage-confirmed case must appear in graph, storage and report with matching proof |
| MUST | Honest benchmark denominators | Separate seeded known-route detection, unseeded discovery, confirmation conditional on reach, and full-target recall |
| SHOULD | Resumable job API and Burp run UI | Existing controls are fragmented; show run status, cancellation, blockers and persisted resume cursor |
| SHOULD | Coverage matrix/tree drilldown | Matrix data exists; expose every case's actual attempt/evidence/skip reason in the product |
| SHOULD | Schema-derived request generation | Extend existing OpenAPI discovery to bodies, required fields, examples, auth and links; JSON Schema/GraphQL operations where applicable |
| SHOULD | Modern input support | Nested JSON/arrays, multipart, repeated params, encoded values, header/cookie inputs, UUIDs and application object references |
| SHOULD | Browser workflow discovery | Existing static HTML/JS crawl cannot execute SPA event flows; record actual XHR/fetch/form interactions |
| SHOULD | Broader authorization checks | Controlled same-role cross-user/cross-tenant cases, write authorization, delegated roles and function-level permissions |
| SHOULD | Auth lifecycle work programs | Refresh rotation/reuse, logout invalidation, MFA sequencing, reset single-use/expiry/account binding, authorized failed-login testing |
| SHOULD | OOB lifecycle | Correlated delayed callbacks, polling deadlines, reachability preflight and request-stage attribution |
| SHOULD | Generic sensitive-data observations and verification | Existing HMAC-specific proof is narrow; add structured secrets/PII with context, safe verification and redaction |
| SHOULD | Root-cause dedup and reproducible PoC packets | Group manifestations under one issue while keeping distinct parameters/boundaries separate |
| SHOULD | Dependency-aware fair scheduling | Cheap deterministic checks first, independent cases bounded concurrently, mutation conflicts serialized, uncertainty-driven model allocation |
| SHOULD | Model evaluation and ablation | Measure parse success, routing omissions, useful hypotheses, final proof yield and tokens per unique confirmed issue |
| SHOULD | Replayable human feedback | Accepted/false-positive decisions keyed to stable issues; retain rationale and retest conditions |
| SHOULD | Run isolation, retention and redaction policy | Separate credentials from evidence; sanitize URLs/bodies and control exports, storage lifetime and cloud-bound data |
| SHOULD | Installable package and reproducible launcher | One documented command for service, benchmark and tests; supported Python/Java/tool versions |
| COULD | Additional typed tool adapters | Add only for proven coverage gaps with a policy/evidence contract; breadth is not justification by itself |
| COULD | Advanced protocol suites | HTTP/2 race synchronization, multi-hop desync labs, WebSocket message authorization, GraphQL-specific attacks after core correctness |
| COULD | Deeper DOM sources/sinks and taint tracing | Beyond URL fragments: postMessage, storage, referrer and SPA data flows |
| COULD | Business invariant templates | Analyst-specified rules for approval, quantities, coupons, ownership and workflow order |
| COULD | Contextual knowledge retrieval improvements | Evidence-linked methodology retrieval and targeted context windows; measure benefit first |
| COULD | Distributed runners / stronger model backends | Only after scheduling, isolation and per-case yield are measured |
| DON'T | Add many more specialist prompts now | Increases cost while current requests, binding and verdicts remain wrong |
| DON'T | Treat a larger model as the primary fix | Cannot restore discarded cookies, repair missing wrapper methods or enforce counters |
| DON'T | Lower confirmation thresholds to improve recall | Produces more false confirmations and invalidates the benchmark |
| DON'T | Encode blind target route names or read answer keys | Keep fixes capability-based; use separate evaluator-owned ground truth |
| DON'T | Claim complete WSTG coverage from a small catalog | Publish exactly which cases and versions are supported |
| DON'T | Auto-confirm business intent, takeover claimability or exploitation from a banner | Require policy/context or a controlled proof; otherwise hand off |
| DON'T | Generate arbitrary offensive shell commands with an LLM | Preserve typed, code-built tool requests |
| DON'T | Rewrite everything or delete the test suite | Incrementally replace faulty boundaries and preserve working mechanisms |
| DON'T | Expand autonomous mutation across real targets by default | Keep explicit per-engagement rules and isolated test accounts |

**Why results fall short — causal model**

The success chain is: discover a useful operation → obtain a valid request and authorized test session → preserve its inputs → select an applicable test → execute it correctly → recognize a real security effect → bind proof to a finding → report and score it correctly. A defect at any step limits the final result, even if all later components are excellent.

1. **Reachability and request fidelity are the primary structural bottlenecks.** Discovery produces route families, while verification needs a concrete valid request. Empty reconstructed bodies, lost queries, hardcoded ID=1, weak form submission and anonymous browser contexts make many implemented legs inapplicable or ineffective.
2. **The scheduler favors repeated authorization work.** Authorization-heavy derivation, endpoint-level “validated” skipping and success-counted budgets create uneven coverage. The matrix runs late, after costly content/model work, and is not the sole work driver.
3. **Proof semantics are inconsistent.** Some legs prove execution; others prove format, response variation or a missing header. All can feed the same confirmed flag. This creates both impressive-looking raw counts and untrustworthy precision.
4. **Integration erases identity and provenance.** Class-only binding, role-keyed sessions, cache collisions, slim graph findings and dropped chain inputs lose the very context required to distinguish real boundary violations from normal behavior.
5. **Reporting/scoring distort the feedback used to prioritize development.** Skipped cells count as tested; confirmations found by the matrix do not become report findings; unknown provenance becomes “lucky”; the benchmark covers a known-route subset. Optimizing these numbers can reward the wrong changes.
6. **Tests validate cooperative interfaces and simplified worlds.** The file-upload mock permits methods the real wrapper lacks. Safe storage/display was not a sufficient second-order negative control. The SQLi smoke stubs the LLM, so it cannot test whether the actual model returns useful valid JSON. These are test-design gaps, not an argument against testing.
7. **The system is expensive where it is least certain.** Many agents can inspect the same exchange; validators repeat per finding; clients/browser processes are recreated; discovery adds requests without necessarily adding valid operations. The saved 2.8-hour run proves expense, but not the claimed current CPU/GPU allocation. Measure wall time by phase before hardware conclusions.
8. **Development has outrun integration verification.** New legs and local patches accumulate while the scored CI tier is disabled and onboarding remains stale. A fixture-level “live” result has repeatedly been treated as evidence that the whole product reaches and confirms the same class.

Do not assign a precise percentage of missed findings to these causes yet. Run controlled experiments after the ledger fix: identical frozen requests with deterministic-only checks; then model assistance; then unseeded discovery; then workflows. That isolates failure stages without target-source knowledge.

**Target architecture**

Keep the existing modules but clarify their boundaries:

```text
Burp / recorded browser / HTTP crawl / OpenAPI
                 ↓
Immutable Exchange Store + Principal/Session Store
                 ↓
Application model: concrete operations, inputs, objects, workflows, permissions
                 ↓
Versioned Check Catalog → explicit Case Worklist
                 ↓
Run Scheduler → Policy / Scope / Budget / Transport
                 ↓
Registry executor (Python tool, container, browser, or Burp)
                 ↓
Execution & Evidence Ledger → Oracle → Finding / Observation / Inconclusive
                 ↓
Graph update + coverage + dedup + report + benchmark
                 ↺ new capabilities and valid operations
```

Suggested core records:

- `Principal`: stable ID, roles, tenant, owned test objects, expected permissions; session references rather than raw secrets in findings.
- `Exchange`: raw bytes/reference plus parsed method/origin/path/query/headers/body; timestamps and principal/session generation.
- `Case`: run ID, operation/template ID, exact input location, technique ID, attacker/victim principals, preconditions and budget.
- `Execution`: unique attempt ID, tool/config version, policy decision, exact request/response references, timestamps, side effects and error state.
- `Proof`: oracle version, evidence references, controls, semantic assertion and scope of the proved effect.
- `Issue`: canonical vulnerability and root cause, affected cases, strongest proofs and analyst disposition. Confidence cannot override proof history.

Coverage should be a projection of cases and execution events. It must never reconstruct what “must have happened” from an endpoint's final state.

**Dependency-ordered roadmap**

Each row is an independently reviewable work package. Use small commits with the required Co-Authored-By trailer; preserve safe committed config. Re-run the full required suite after product changes, and use fresh processes/caches for live measurements. Effort labels are relative sizing, not promised elapsed time.

| Phase | Work and dependencies | Acceptance / exit gate | Size |
|---|---|---|---|
| 0. Establish a reviewable baseline | Snapshot current dirty diff and manifest; retain raw run evidence; reconcile known-route score and final report | Exact code/config/data hashes and one reproducible command; no old claims presented as current measurements | S |
| 1A. Make output honest | R01/R02/R08/R09; introduce explicit case/result statuses; stop weak oracles from emitting confirmed | Zero “tested” cells without attempts; errors/skips never refuted; exact technique tiers; safe stored echo remains unconfirmed | M |
| 1B. Repair immediate correctness | R04/R07/R10/R12/R14/R16; add local reproductions as regression controls | Real-wrapper upload works; proof cannot be overwritten; same principal cannot prove IDOR; quotas enforced; typed chain routing | M |
| 2. Preserve requests and identities | Exchange/template store and principal/session/object records; R03/R05/R24/R25/R26/R27 | Same-role Alice/Bob, cross-tenant users, query+JSON+form+multipart and protected browser fixtures retain exact semantics | L |
| 3. Unify execution and findings | Registry-only construction, shared policy executor, bound result ingestion, bounded scheduling; R06/R15/R17/R28/R29 | Scripts/API/Burp honor identical settings; matrix confirmations appear in report; no duplicate jobs for same case; redirects and all transports obey scope | L |
| 4. Make graph feedback real | Case-level completion, preserve chain provenance, supply response evidence, merge derived state; R18–R23 | A confirmed fixture capability unlocks a new identity/route, that route is retested, and the final graph/report includes it; negative control does not unlock | M–L |
| 5. Qualify supported verification families | Implement the oracle-table controls in dependency order: authz, injection, session/workflow, browser, then advanced protocols | Positive/negative real-transport evidence per promoted technique; support metadata generated from test results; unsupported techniques remain explicit | L |
| 6. Improve discovery using valid operations | Extend OpenAPI schema construction, stateful forms/browser workflow capture, object harvesting and input enumeration | Held-out paired application exposes unnamed/nested/SPA features; new valid operations reach deterministic tests; failures explain missing prerequisites | L |
| 7. Establish measured performance | Deterministic-only baseline, routing/model ablations, stable request/state resets, stage timing and unique proof yield | Published per-case outcomes, repeat-run variability, false-positive counts, tokens/requests/time per unique proof; required scheduled benchmark gate | M |
| 8. Deliver the copilot workflow | Resumable engagement jobs, Burp run control, coverage/evidence drilldown and reproducible export | Operator can start, inspect, cancel, resume, resolve blockers and export without scratch scripts; Java build and contract parity pass | M–L |
| 9. Consolidate and package | Delete replacement-obsoleted code; package harness; replace copied kit; shorten docs; unify specialist specs as justified by ablations | Clean checkout setup, supported environment matrix, no historical fixture regression; no lost unique capability | M |

Some phase-1 and phase-2 implementation can be prepared independently, but no feature should be declared complete until its production entry path passes the acceptance gate. Do not rebuild the entire architecture before fixing the small, reproduced blockers.

**First ten implementation tickets**

1. Replace inferred coverage and correct summary counting; tests with zero executed legs and exhausted budgets.
2. Fix upload transport interface; exercise the real gate/wrapper against an owned local fixture with reject and allowed-attachment controls.
3. Make finding confirmation monotonic and retain proof fields/history.
4. Add explicit principal identity and reject self-comparison; test two users with the same role.
5. Fix cache case identity and mutation invalidation; vary Cookie/Authorization with identical URL/body.
6. Replace class-tier suppression with execution-aware outcomes; test disabled, skipped, error and real controlled-negative cases.
7. Demote unsound oracles; add safe stored echo, public GET/private POST, bearer-only CSRF and ordinary mass-assignment race controls.
8. Replay captured templates in graph/coverage; test form/XML/URL/multipart and non-1 object IDs end to end.
9. Route all validator results through one bound ingestion function; prove a matrix-only confirmation reaches persisted report output.
10. Expose the real graph investigation as a job and connect its response/capability feedback; require an entire chain fixture, not just the linker seam.

**Release criteria and metrics**

- Zero false confirmations on the maintained negative-control set. Report the finite size of that set; do not extrapolate to universal zero false positives.
- Every confirmed issue has an exact case, proof and independent control. Every skipped/error case has an accurate reason. No unknown provenance is called earned or lucky.
- Supported techniques have positive and negative real-transport tests; browser capabilities additionally have a real-browser gate. Stubbed LLM tests remain fast plumbing tests.
- Separate metrics for route discovery, valid-operation discovery, input enumeration, attempted cases, conclusive cases, known-route recall, blind discovery recall, unique issue precision and reporting retention.
- Report model parse/dispatch failures, tool availability/fallback, auth expiration, timeout rates, redundant attempts, created-object cleanup and out-of-scope requests.
- Compare ablations on identical inputs and target states; publish variability across repeats. Choose numerical recall/runtime targets only after the corrected baseline.
- The flagship path must pass from the actual Burp/API entry point to a persisted, reproducible report.

**Remaining verification limits**

The live target's complete vulnerability denominator remains unknown to this reviewer by design. The saved 13-item score is not exhaustive target ground truth. Current Ollama/GPU/Docker/browser availability and the latest dirty changes' effect on recall were not established by a fresh max-coverage run. Java compilation, full UI behavior, every registry-only protocol oracle, long-duration state cleanup and concurrent multi-engagement behavior require the explicit gates above. The inventory proves source presence and parseability; it does not justify blanket correctness claims for unreviewed branches.

---

# IMPLEMENTATION PROGRESS

**This section is the running work log for acting on the review above.** It is maintained by the implementation sessions, appended below the frozen review. Discipline (project #0 rule): every "done" row names the test/command that verifies it, or is marked reported/not-verified. "Live-verified" means proven against a running target/browser; "hermetic" means proven by an offline test with a negative control but not yet against the live target.

## Baseline (Phase 0)

- Implementation started from branch `WorkingSunday`, review baseline HEAD `319f0ef`, **plus the pre-existing uncommitted "session-17" WIP** the review measured (discovery-breadth in `api_surface_discovery.py`, `discovery_chain_candidates` in `chaining.py`, `universal_header_audit` + shape preconditions + informational auto-confirm in `orchestrator.py`, new `validators/verbose_error_validator.py`, and edits to `auth_sequence`/`rate_limit`/`registry`). That WIP is itself a review target: R14 (chain routing forces `kind="sqli"`) and the CORS/CSP/clickjacking informational auto-confirm (contradicts the "no config fact auto-confirms a vuln" MUST) both live in it.
- **Full suite baseline (with the WIP applied): 1426 tests OK** (`cd harness && python -m unittest discover -p "test_*.py"`, ~284 s).
- "Verified by" below = a named offline/hermetic test with a negative control (the project's #0 discipline). **None of this is a fresh live-target run** — target recall numbers are unchanged and still owed a measured VulnCorp run.

## Ticket status (the review's "First ten implementation tickets" + the P0 findings they close)

| # | Ticket | Findings | Status | Verified by |
|---|---|---|---|---|
| 1 | Remove inferred coverage; honest summary counting | R01, R02 | ✅ done (hermetic) | `test_coverage_tracker` (`test_no_execution_events_never_invents_not_detected`, `test_execution_event_marks_not_detected`, `test_summary_excludes_skipped_and_error_from_tested`) |
| 2 | Fix upload transport interface; real gate/wrapper test | R04 | ✅ done (hermetic) | `test_deferred_legs.RealWrapperFileUploadTests` (real `GatedAsyncClient`+`MockTransport`, reject + gate-block controls) |
| 3 | Monotonic finding confirmation; retain proof/history | R07 | ✅ done (hermetic) | `test_engagement` (`test_confirmed_finding_not_downgraded_by_confident_hypothesis`, `test_add_finding_preserves_proof_and_history`) |
| 4 | Explicit principal identity; reject self-comparison | R10 | ✅ done (hermetic); ownership/entitlement model still Phase 2 | `test_cross_identity_validator` (`test_rejects_self_comparison_but_tests_distinct_same_role_user`, `test_only_source_principal_configured_skips`, `test_role_session_principal_id_distinguishes_same_role`) |
| 5 | Cache case identity + mutation invalidation | R03 | ✅ identity+subtype key done (hermetic); post-mutation invalidation still TODO | `test_orchestrator_precondition.ConfirmationCacheKeyTests` |
| 6 | Execution-aware outcomes (replace class-tier suppression) | R08 | ✅ done (hermetic) | `test_confirmation_gate` (`test_leg_error_is_inconclusive_not_refuted`, `test_unconfirmed_idor_with_controlled_negative_is_refuted`, `test_unconfirmed_idor_no_execution_is_capped_but_not_refuted`) |
| 7 | Demote unsound oracles; add negative controls | R12 + WIP auto-confirm | ✅ R12 + removed LLM-label config auto-confirm (hermetic); the fuller oracle-table controls (CSRF/rate/reset/smuggling/passive-deser) are Phase 5 | `test_second_order` (`test_not_confirmed_on_literal_echo_of_payload`) |
| 8 | Replay captured request templates in graph/coverage | R05, R14 | ✅ done (hermetic); R14 typed-routing + R05 template store/replay | `test_engagement.RequestTemplateTests`, `test_worklist_investigator.SeedExchangeTemplateTests`, `test_chaining.test_kind_is_typed_by_read_content_type` |
| 9 | One bound result-ingestion path (matrix→report) | R06 | ✅ done (hermetic, isolated + neg control) | `test_smoke_investigate.test_coverage_driver_confirmation_reaches_findings_not_just_matrix`; `test_orchestrator_precondition.CoverageConfirmationFindingTests` |
| 10 | Expose graph investigation as a job; wire feedback | R18, R19 | ✅ done (hermetic); job lifecycle+cancel (R18), response-map + st2 merge (R19). Mid-run RESUME cursor deferred (needs execution ledger) | `test_server.InvestigateJobEndpointTests`, `test_engagement.MergeStateTests` |
| + | Enforce per-finding mutation ceiling | R16 | ✅ done (hermetic) | `test_safety_gate.PerFindingMutationCeilingTests` |
| + | Exact-technique leg tiers (no substring inheritance) | R09 | ✅ done (hermetic) | `test_confirmation_gate.test_provisional_subclass_not_promoted_by_substring_of_live_class` |

Later phases (2–9: request/identity model, unified executor, graph feedback, oracle qualification, discovery, measured performance, copilot workflow, packaging) are tracked as they are reached.

## Work log

_(newest first)_

### 2026-09-10 — Phase 1B/2/4 batch: R05, R18, R19 (+ commits of the first batch)

Committed the Phase-1A/1B batch (HEAD `cf8d95b`): a session-17 WIP snapshot commit, then one focused commit per finding group, then this tracker. Then:

- **R05 (request-template preservation)** — `SurfaceEndpoint.template` + `EngagementState.record_template()` + `template_from_exchange()` capture the real query/body/content-type/observed-object-id from each exchange (recorded in `review_captured_exchanges`); `worklist_investigator._seed_exchange` and the coverage `_run_leg` now REPLAY that template (real body/query, observed id, captured Content-Type, identity's own auth overlaid) instead of fabricating an empty body / stripped query / id=1. Falls back to fabrication when no capture exists. Full suite 1468 OK.
- **R18 (flagship job API)** — `server.py`: `POST /engagement/{host}/investigate` runs `investigate_engagement` as a tracked background asyncio job; `GET .../investigate[/{job_id}]` polls status/result; `POST .../{job_id}/cancel` cancels via task cancellation. Closes "the flagship path is unreachable from the API." Mid-run **resume cursor** (SHOULD-tier) is deferred — investigate_engagement isn't internally checkpointed; that needs the Phase-2 execution ledger (documented in code).
- **R19 (credential feedback loop)** — `investigate_engagement` now builds a `responses` map (url→{headers,body}) from real captures and passes it to `chain_linker.link_findings` (previously omitted, so leaked-credential detection was starved), and merges the derived-identity state `st2` back into the primary `state` via new `EngagementState.merge_from()` (previously st2's surface/findings never reached the final report). Merge is monotonic (respects R07).

Suite after this batch: **1468 OK** for R05; R18/R19 targeted green — full-suite confirmation recorded below once it lands.

### 2026-09-09 — Phase 1A/1B P0 correctness batch (12 findings)

Worked the review's first-ten tickets in dependency order. Every change ships with an offline test + negative control; full suite kept green. **All hermetic — no fresh live-target run.** Full suite after the batch: **1461 tests OK** (from 1426 baseline; +35 tests), ~277 s.

- **R01/R02 (coverage honesty)** — `coverage_tracker.py`: deleted the inferred `mark_leg_attempts` (it fabricated `not_detected` on every applicable cell of an "investigated" endpoint) → replaced with `record_execution_events()` that records only REAL leg executions; unrecorded cells finalize to SKIPPED with an explicit "attempt not tracked — not inferred as tested" reason. `coverage_model.summary()` now separates `attempted`/`conclusive`/`skipped`/`error`; `tested` == conclusive (never counts skipped/error/pending).
- **R07 (monotonic confirmation)** — `engagement.py::SurfaceEndpoint.add_finding`: a confirmed proof is never overwritten/downgraded by a later unconfirmed hypothesis whatever its confidence; proof fields (evidence/summary/validator/…) are preserved instead of slimmed to 4 keys; superseded entries kept under `_superseded`.
- **R10 (self-comparison + principal identity)** — `cross_identity_validator.py`: rejects any candidate whose credentials equal the source request's, dedups principals by credential; `RoleSession.principal_id()` + orchestrator registers identities under it (same-role users no longer overwrite). (Owner/entitlement modeling remains Phase 2.)
- **R08 (execution-aware suppression)** — `confirmation_gate.py`: REFUTED (low, "likely FP") now requires a REAL `not_confirmed` execution in `validation_reports`; a leg that errored/skipped/didn't run → distinct `inconclusive_unverified` (still capped to low — the precision floor holds — but honestly labelled, never "refuted").
- **R09 (exact leg tiers)** — `confirmation_gate.leg_tier`: `PROVISIONAL_MARKERS` resolved first so `dom_xss`⊃`xss` and `privilege escalation race`⊃`privilege escalation` stay provisional; an explicit override still promotes deliberately.
- **R03 (cache identity)** — `orchestrator.confirmation_cache_key()` includes an identity (auth-header) signature and the finding subtype, so a leg run as admin can't replay into a user's cell. (Post-mutation invalidation still owed.)
- **R04 (upload transport)** — `file_upload_validator.py` uses `GatedAsyncClient.request()` (the only method it exposes) instead of `.post()/.get()`; added a real-wrapper `MockTransport` test that the old unrestricted-AsyncMock tests couldn't catch.
- **R16 (mutation ceiling)** — `safety_gate.py`: `authorize`/`authorize_burst` take a `finding_id` and atomically reserve mutating sends against `max_mutating_requests_per_finding` (capped by the hard ceiling); no-finding-id callers unchanged.
- **R12 (second-order SQLi echo)** — `second_order.py`: mask the reflected payload before the TRUE/FALSE comparison; a literal echo no longer confirms, a genuine result-set change still does.
- **R14 (typed chain routing)** — `chaining.discovery_chain_candidates` classifies `kind` by the read's content-type; `orchestrator` routes only json-read (`second_order`) pairs to the SQLi oracle (no more forced `kind="sqli"`), skips html-read (stored-XSS) pairs, and sources exchanges from the real capture store (`rc.captured`+`feature_caps`), not the never-populated `state.captured_exchanges`.
- **R06 (bound ingestion)** — `orchestrator.coverage_confirmation_finding()` + `_run_leg`: a coverage-driven confirmation is ingested into `state` (→ worklist/summary/report/persistence), not just recorded as a matrix cell. Isolated end-to-end test (worklist off) + negative control.
- **WIP oracle cleanup (part of ticket #7)** — removed the `_AUTO_CONFIRM_CLASSES` block that fake-confirmed CORS/CSP/clickjacking/version-disclosure/etc. from an LLM label alone (violated "a config fact must not auto-confirm a vulnerability"). These now ship as unconfirmed observations. (An active cors/csp validator can still confirm via the real validation path.)

**Not done this batch:** R05 (canonical request-template preservation in graph/coverage — Phase 2, large), R18/R19 (resumable engagement job API + credential-feedback merge — Phase 4/8), the full oracle-table negative-control program (Phase 5), and the deeper items in weaknesses #1–#20. R03 post-mutation invalidation and R10 ownership modeling are partial as noted.

