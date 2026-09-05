# Leg verification status — the live-verified vs smoke-only split

The confirmation legs are not equally trustworthy. A leg that has only ever
passed a **smoke test** (network stubbed at `httpx`, decision logic asserted) is
not the same as one **live-verified** against a real target with a true positive
and a matched negative control. This file is the canonical record of which is
which, and it is the data structure the confirmation gate consumes:
`confirmation_gate.LIVE_VERIFIED_MARKERS` mirrors the **live** column, and Phase 2
verification is what moves a leg from *smoke_only* to *live_verified* there.

Why the gate cares (Phase 1.1): for an **unconfirmed** finding, a live-verified
leg's silence is strong evidence against (→ demote to low, REFUTED); a smoke-only
leg's silence is weak evidence (→ cap at medium, UNPROVEN — don't bury a
possibly-real finding). So promoting a leg here tightens suppression for its
class.

## Status

| Leg | Class | Status | How verified |
|---|---|---|---|
| `cross_identity` | idor / access control | **live_verified** | session-11 max-coverage run vs VulnCorp (IDOR confirmed) |
| `sqlmap` | sqli | **live_verified** | session-11 run (SQLi confirmed, sqlmap-in-container) |
| `jwt_forge` | jwt (alg:none) | **live_verified** | session-11 run (alg:none forgery accepted) |
| `xxe` | xxe | **live_verified** | session-11 run (`/api/tickets/import`, OOB callback) |
| `path_traversal` | path_traversal | **live_verified** | session-11 run (`/uploads/1` → win.ini); re-confirmed via `run_leg_verification` against the fixture |
| `ssti` | ssti | **live_verified** | Phase 2, `test_leg_live_verification` — real Jinja render endpoint (`{{89*97}}`→8633) + escaped-echo negative control |
| `open_redirect` | open_redirect | **live_verified** | Phase 2, `test_leg_live_verification` — real blind 302 to a sentinel host + fixed-target negative control |
| `ssrf` | ssrf | **live_verified** | `test_leg_live_verification` — a real server-side fetch of the `url` param to the in-process collaborator + a no-fetch negative control |
| `command_injection` | command_injection | **live_verified** | `test_leg_live_verification` — a real shell endpoint runs the injected `curl` fetch to the collaborator (skipped when `curl` is absent) + a no-shell negative control |
| `sequence` | mass_assignment | **live_verified** | `test_leg_live_verification` — a real mass-assignable write persists across an independent re-read + an allowlisted-write negative control |
| `secret_disclosure` | jwt (signing key) | live (offline proof) | Phase 3.1 — HMAC verification is cryptographic proof; no live send needed |
| `browser_xss` | xss | smoke_only (default) | seam-mocked unit test. OBSERVED confirming live via `run_leg_verification` (real Chromium executed the reflected payload) — but kept smoke_only in the DEFAULT gate set because Chromium is optional infra ON THE HARNESS; on a browser-equipped machine promote it via `apply_confirmation_suppression(live_verified_markers=...)` |

The ~13 analyze-only class validators (`cors`, `csp`, `crypto`, `recon`,
`oauth`, `header_injection`, `http_request_smuggling`, `web_cache_poisoning`,
`subdomain_takeover`, `websocket`, `race_condition`, `api_security`,
`deserialization`) are unit-tested only and are not part of the gate's
confirmable set.

## How to live-verify

- **Hermetic, in the `unittest` suite** — `harness/test_leg_live_verification.py`
  stands up `testing/leg-verification/vuln_fixture.py` on a real localhost socket
  and runs each leg against a true-positive endpoint + a matched control, with
  real HTTP (no stubs): `ssti`, `open_redirect`, `ssrf` and the `sequence`
  (mass-assignment) leg all run here. `command_injection` runs here too but is
  skipped when `curl` is absent (the injected payload needs it on the host). The
  OOB legs reach the in-process collaborator (`collaborator.py`), which is itself
  just a loopback listener — no external service needed.
- **Operator-run** (`python testing/leg-verification/run_leg_verification.py`) for
  the legs whose confirmation depends on host infra the suite can't assume:
  `path_traversal` (a real canonical system file) and `browser_xss` (a real
  Chromium). Both confirmed on the dev machine this session.

When a leg is newly live-verified, add its class markers to
`confirmation_gate.LIVE_VERIFIED_MARKERS` and update the table above.

## Freeze policy (Phase 2.1)

**No new confirmation legs until the existing smoke_only legs above are
live-verified.** The gap that matters now is trust in the legs already built, not
breadth. A new leg added while the current ones are unverified only widens the
"green tests, dead pipeline" surface. Build fixtures and live-verify what exists
first; then, and only then, add the next leg.
