# Implementation review: T01, T02a, T02b, T03

Reviewed 2026-09-10. Implementation worktree: `C:/Users/arthu/Documents/AgenticVibe-impl`; branch `impl/astra-tickets`; HEAD `bcaab08`. Compared with `e9e5c91`. No implementation files changed during this review.

**Decision: request changes.** These commits provide useful additive foundations, but the tickets do not meet the original production-wiring and correctness acceptance criteria. In particular, optional injection seams are not completed production integration.

## Verification performed

- Inspected all five implementation commits and their changed production modules, new tests, plus existing registry, server, identity store, and confirmation consumers.
- Focused command: bundled Python, append the existing `.review-deps` directory to `sys.path`, then load `test_evidence`, `test_principals`, and `test_run_context` using unittest. **57 tests passed, exit 0, 5.655 seconds.** Executor tests use their existing simple local HTTP fixture; no engagement, model run, or blind target was used.
- Initial sandbox attempt ran 57 tests with five import-related errors: sandbox access to the existing httpx package was unavailable. Re-running with approved access resolved those errors. They are environment failures, not reported as implementation defects.
- `review_implementation_checks.py` in this directory ran offline with synthetic validator results and a temporary SQLite database; **exit 0**. It independently demonstrated same-case collision, confirmation propagation to a skipped finding, artifact-free non-legacy proof creation, optimistic negative mapping, reused orchestrator run ID, and metadata reset on identity re-save.
- `git diff --check e9e5c91..HEAD` passed.
- The full suite, model tier, browser/container tier, and blind/live engagement effectiveness were **not run or verified**. No full-suite success is claimed.

## Findings

### F01 — P1: T02/T03 are not enabled by normal production entry points

Locations: `harness/validators/registry.py:318`, `harness/orchestrator.py:1241`, `harness/validators/cross_identity_validator.py:197`.

Both production constructors still instantiate CrossIdentityValidator without `ownership` or `run_context`. No production caller constructs a RunContext or OwnershipLedger, or calls RoleSession.to_principal(). Role crawl remains on its old transport. Consequently an ordinary API/graph run retains the old transport and identity behavior despite the new tests passing.

The new tests explicitly inject the objects themselves and call a validator or its `_probe` method. That establishes an available seam, not integration through the actual entry point. T02a's principal/session models and metadata accessors similarly have no production consumer.

Required outcome: run creation owns and supplies the context and identity/ownership state; normal registry/graph callers receive it; teardown is tied to the run lifecycle. Verify through the public job/API boundary with an injected transport observer or a harmless local fixture, without constructing the migrated validator directly in the test. Do not claim full migration for browser/container paths deferred to T08.

### F02 — P1: Observations are promoted to controlled negative proofs

Locations: `harness/evidence.py:83`, `harness/evidence.py:262`, `harness/orchestrator.py:2336`.

Verdict.from_validation maps every `not_confirmed` result to CONTROLLED_NEGATIVE, and the factory independently sets `executed=True` from that same status. Existing validators use `not_confirmed` for observations and unavailable proof, including retired oracles. The new ownership-sharing observation also uses that status. An observation does not establish that the exact security boundary was tested and held.

The focused test `test_not_confirmed_is_controlled_negative` asserts this incorrect blanket conversion, so green tests actively preserve the defect. Offline diagnostic confirms the mapping.

Required outcome: negative evidence needs an explicit case-bound controlled-negative contract and actual execution/control evidence. Legacy `not_confirmed` results default to inconclusive unless that stronger contract is supplied. Keep blocked/error/inconclusive distinct, and test retired observations as negative controls for the mapper.

### F03 — P1: Same-class findings still share cases and inherit each other's confirmations

Locations: `harness/orchestrator.py:2293`, `harness/orchestrator.py:2297`, `harness/orchestrator.py:2380`.

Production case construction uses method+URL, canonical class, and literal principal `captured`; it ignores the individual finding, input, request body, and actual principal. The final confirmation assignment remains class-keyed. Different proof IDs identify attempts, not different cases.

Offline diagnostic supplied two same-class synthetic findings: A returned confirmed, B returned skipped. Both proof records had the same case ID and B was nevertheless marked confirmed. This directly fails T01's required acceptance test. The new wiring test only checks distinct classes, while parameter distinction is tested solely on the standalone data model.

Required outcome: carry the originating concrete case/finding binding through dispatch, persistence, and result assignment. Preserve synonym handling without broadcasting confirmation across cases. Add a production `_validate_findings` regression with two same-class findings and different outcomes, plus separate principals/request variants. Deferring issue grouping to T06 does not justify deferring T01 case binding.

### F04 — P1: Cross-identity executor calls share one cookie jar and still use global identities

Locations: `harness/validators/cross_identity_validator.py:231`, `harness/validators/cross_identity_validator.py:351`, `harness/run_context.py:263`, `harness/run_context.py:315`.

Even when a context is injected, every cross-identity send uses `session_ref=None`. All such calls select the same persistent default client and cookie jar. A Set-Cookie response during one identity's request can therefore affect a later identity or anonymous request. The session-isolation test covers explicit `s1`/`s2` executor calls, not this caller's actual use.

Identity selection also still reads process-global identity_headers by host, rather than the run's session/principal state. Separate context objects therefore do not establish isolated engagements. This is source-verified; no credential disclosure against a target was attempted.

Required outcome: bind every identity-bearing and anonymous call to explicit isolated session state, reject unresolved session references rather than silently falling back, and source identities from the run. Verify sequential and concurrent runs with harmless session markers, conflicting permissions, and independent cancellation. Retain controls that prove anonymous requests remain anonymous after another principal receives a cookie.

### F05 — P1: Session credentials are not bound to a permitted origin

Locations: `harness/run_context.py:133`, `harness/run_context.py:228`, `harness/run_context.py:257`.

ManagedSession has no origin/destination credential policy. Executor labels the initial request's origin as `origin0`, then treats it as the session's own origin. Thus selecting the same session for a different allowed host attaches its credentials there immediately. Host scope says where requests may go; it does not authorize forwarding every session's credentials.

Additionally, explicit header stripping does not control cookies subsequently attached by httpx's persistent cookie jar. Cookie scoping is not identical to origin scoping. The existing cross-origin test asserts Authorization stripping only and never seeds a cookie jar. Preserved redirect bodies also have no separate cross-origin forwarding decision.

Required outcome: bind session credentials to explicitly authorized destinations, evaluate cookies and retained bodies as well as headers, and do not infer credential authorization from the initial request. Verify with synthetic credentials and an offline request observer or harmless local fixture. Explicitly cover same-host/different-port origins and default-port normalization. No live leakage test was performed in this review.

### F06 — P1: New 'structured proofs' lack supporting artifacts and are not legacy-labelled

Locations: `harness/orchestrator.py:2336`, `harness/evidence.py:252`, `harness/run_context.py:213`.

The production proof factory supplies no baseline, attack, or control artifact IDs, but persists current confirmations with `legacy=False` and no qualification limitation. The offline diagnostic confirms this. The executor creates a URL/status descriptor for only the returned outcome; there is no artifact sink holding replay exchanges, no captured intermediate-hop history, and no linkage from those descriptors to the persisted proofs.

This is a compatibility summary with a structured envelope, not the proof contract required by T01. Empty IDs cannot be dereferenced or independently reviewed. The returned proof array is also separate from individual finding records.

Required outcome: preserve unstructured results with explicit compatibility provenance; require capability-specific supporting evidence for migrated structured verdicts. Store resolvable artifacts and attach exact case/proof references. Persistence rejection/failure must be surfaced, not ignored or reduced to debug logging while returning an apparently durable proof. Do not fabricate artifacts for old results.

### F07 — P1: Run IDs are scoped to the server singleton, not the engagement

Locations: `harness/orchestrator.py:2243`, `harness/server.py:55`, `harness/server.py:880`.

The new `_run_id()` lazily assigns a single `self.run_id` and reuses it forever. The server owns a process-wide Orchestrator instance. T00 generates job-specific manifest IDs, but no caller connects those IDs to the proof factory. Repeated analyses can therefore enter the same case namespace even across new jobs or changing credentials. A prior confirmed attempt can remain the strongest proof for a later, unrelated case with matching coordinates.

The offline diagnostic demonstrates reuse on one orchestrator; the singleton/job mismatch is source-verified. Required outcome: pass an immutable run identifier through invocation-local context, with an explicit policy for captured exchanges belonging to a run. Do not fix this by mutating singleton `run_id` before each concurrent call. Verify two back-to-back and two overlapping invocations with distinct proof namespaces and matching manifest IDs.

### F08 — P2: Re-saving an identity deletes the new principal metadata

Location: `harness/store.py:941`.

`save_identity` still uses INSERT OR REPLACE with only the original five columns. SQLite replaces the row and applies defaults to newly added tenant, permissions_json, and trust columns. Offline sequence: save Alice, set tenant-A/read permission/trust=3, save Alice again. Result: tenant=None, permissions=[], trust=1.

Required outcome: update original identity fields without replacing unrelated metadata, or write a complete row through one authoritative model. Add a re-save regression, not just the current set/get round-trip test. Confirm existing API reads can return the intended metadata once wired.

### F09 — P2: An authorized identity ends evaluation before other identities are checked

Location: `harness/validators/cross_identity_validator.py:406`.

The new authorized-sharing branch returns a validator-wide `not_confirmed` immediately. If Bob is legitimately shared and Carol is another configured principal, seeing Bob's authorized response ends the loop before Carol is considered. One authorized case cannot establish the outcome of the remaining cases. The existing ownership wiring tests configure only one other identity, so they cannot detect this behavior.

Required outcome: record authorized sharing for that case and continue other required cases, then aggregate outcomes without claiming skipped principals were tested. The legacy downstream downgrade text currently says all other identities were denied; that statement is also false for this new early-return path. Add a multi-principal synthetic-result test that verifies all required cases are considered.

### F10 — P2: Ownership lookup loses both declared permissions and object identity

Locations: `harness/validators/cross_identity_validator.py:214`, `harness/validators/cross_identity_validator.py:402`, `harness/store.py:151`.

The validator reconstructs Principal from name/role only, dropping declared permissions, tenant, and provisional identity metadata. OwnershipLedger's explicit-permission authorization branch therefore cannot be reached through this production adapter even though standalone model tests pass.

The object key is URL path alone. Query-selected objects such as `/item?id=1` and `/item?id=2` become identical, and persisted ownership facts have no run/host namespace. Facts about one selected object or target can be applied to another. Required outcome: pass the authoritative principal and use a consistent object reference that preserves application/tenant/run provenance and concrete object selection. Unknown ownership or incomplete entitlement information must not silently become a complete authorization specification.

## Additional T03 acceptance gaps

- Redirect handling rewrites every 301/302/303 method to GET, including cases where that is not the intended method semantics; drops all one-shot headers on redirects; and reports the terminal redirect as `ok` when its limit is reached. There is no explicit loop outcome. These need focused protocol-behavior tests before migration.
- A redirect chain that sent an initial request but is later blocked returns `executed=False`, while its request budget was consumed. Store chain attempt history separately from the final-hop disposition so reporting can distinguish these states.
- The context's config is an alias of the caller's mutable dictionary, not an immutable snapshot.
- The migrated executor path omits the old `_probe` call to `global_throttle.acquire()`. An overall request ceiling is not a request-rate limit. Shared throttling needs an explicit executor hook.
- `ScopedGatedClient` is named in module documentation but no such class exists; actual transport is in Executor. Naming itself is not a defect, but documentation should describe the delivered interface accurately.

## Ticket status

| Ticket | Assessment |
|---|---|
| T01 | Partial: additive tables/models/API array exist; case binding, verdict qualification, run isolation and artifacts fail acceptance |
| T02a | Partial: standalone models and storage helpers exist; production session integration and metadata preservation incomplete |
| T02b | Partial: optional ownership hook exists; unwired, loses permission metadata, stops early, and uses an ambiguous object key |
| T03a/b | Partial: executor and local transport tests exist; not wired at normal entry points and session/origin isolation is incomplete |

## Recommended correction order

1. Correct verdict semantics and exact case binding (F02/F03/F06); these currently misrepresent evidence.
2. Establish invocation-local run identity and isolate credential/session state (F04/F05/F07) before enabling the executor broadly.
3. Preserve principal metadata and ownership case semantics (F08/F09/F10).
4. Complete normal entry-point wiring (F01) with harmless production-path transport tests and explicit run cleanup.
5. Close remaining redirect/accounting/throttling gaps, rerun focused tests and the required full suite, then update CURRENT_STATE.md and the implementation execution log with observed results.

Do not mark any ticket complete solely because all 57 existing tests remain green. Add negative controls for the uncovered invariants and verify the actual integration boundary.
