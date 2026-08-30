# Blind test run 2 — corrected results

## What the tester actually did (verified directly from raw data, not the report)

Genuinely good exploration: 90 exchanges, 2 real registered users, real
cross-identity token usage, real payload variation (negative/zero/
massive/malformed quantities). Independently re-derived and confirmed
the two headline claims before trusting them:

- **Cross-identity IDOR is real.** Decoded the JWT used in exchanges 69
  and 70 (`base64.urlsafe_b64decode` on the payload segment) — it
  carries `user_id: 4`. Both requests successfully retrieve orders
  belonging to `user_id: 5`. That's genuine cross-identity access, not
  a self-access mislabeled as a finding.
- **Negative/zero/massive quantity payloads and their exact responses
  are real** — checked against the raw exchange bodies, they match the
  report's numbers precisely (`total_price: -24.99`, `0.0`,
  `24989975.01` respectively).

## What was broken, and why the original run showed 0 findings

Two independent bugs in `answers.py` (the tester's own file — not the
harness):

1. **A crash that nullified the entire file.** Three uses of the
   literal `null` (JSON syntax) instead of Python's `None`. The moment
   `get_answer()` was called for *any* exchange, this raised
   `NameError`. Confirmed directly: `python3 answers.py` crashes
   immediately. The harness's own per-agent error handling caught this
   silently for all ~300+ agent calls across the 90-exchange run and
   recorded each as a failed call with no findings — which is why
   `harness_driver.py run` completed cleanly and reported "90
   exchanges" with zero findings and zero critique invocations, despite
   the exploration underneath being real.
2. **Findings keyed to the wrong exchange or the wrong agent.**
   Verified via `harness_driver.py record` against the real
   `fast_path.py`:
   - The 95%-confidence IDOR finding was attached to exchange 49 (`GET
     /api/orders/1`), whose own token decodes to `user_id: 5` accessing
     an order owned by `user_id: 5` — self-access, not IDOR. The real
     cross-identity evidence (exchanges 69/70) had no finding attached
     to it at all.
   - The massive-quantity finding was keyed to `business_logic`, which
     `fast_path.py` never dispatches for that exchange (only
     `idor`/`auth`/`misconfig`/`api_security`/`supply_chain` are). It
     would never have surfaced even with bug #1 fixed.
   - The zero-quantity finding had the same dispatch mismatch, and
     unlike the massive-quantity case, **no dispatched agent's actual
     specialty covers it** — `api_security`'s resource-exhaustion
     framing fits an unbounded *large* value, not a suspiciously small
     one. Rather than force it under an agent it doesn't belong to,
     it's dropped from the corrected answers. This isn't a loss of
     signal — it's a genuine, now-confirmed instance of a limitation
     already on record: `fast_path.py`'s structural anomaly check
     (added earlier this project) only fires on a *negative* value in a
     money/quantity field, not a zero or unexpectedly-small one.

## Corrected result — real, verified end-to-end pipeline output

```
Ran 90 exchanges through the real orchestrator.
Critique was invoked 5 time(s).

[69] access order 2 with testuser token       -> idor (0.95, high)
[70] access order 3 with testuser token       -> idor (0.95, high)
[82] order with negative quantity             -> improper_input_validation (0.9, critical)
[84] order with massive quantity              -> unrestricted_resource_consumption (0.9, high)
[86] order with string quantity               -> improper_error_handling (0.8, low)
```

All 5 findings survived critique review. Zero false positives across
the other 85 exchanges.

## What this run actually demonstrates about the harness

- **`fast_path.py`'s structural body-anomaly check (added earlier this
  project specifically to catch negative price/quantity manipulation)
  worked correctly in a genuinely blind setting**, on a target and
  payload set it had never seen tuned against it: `business_logic`
  correctly dispatched on the negative-quantity exchange (#82) and
  nowhere else in this run.
- **The order-URL IDOR pattern fix (added earlier this project)
  correctly dispatched `idor` on both cross-identity exchanges** (#69,
  #70) — this is the fix's first real exercise outside the original
  self-graded discovery run.
- **A real, previously-undocumented-until-now confirmation of a known
  gap:** zero-quantity manipulation has no home in the current agent
  specialty set. Worth considering either broadening `business_logic`'s
  dispatch triggers to include a zero-value check alongside the
  existing negative-value one, or accepting this as out of scope and
  saying so explicitly rather than leaving it as an implicit gap.
- **The bigger lesson is procedural, not architectural:** two genuine,
  well-evidenced vulnerabilities were nearly lost entirely because of a
  trivial bug (`null` vs `None`) in the bridge between manual testing
  and the harness's structured pipeline. `blind-test-kit/METHODOLOGY.md`
  doesn't currently tell a tester to sanity-check their own answers file
  runs cleanly before relying on its output — worth adding.
