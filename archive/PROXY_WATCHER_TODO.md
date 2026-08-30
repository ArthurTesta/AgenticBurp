# Next Step: Forced-Egress Safety Proxy

**Status: implemented and unit-tested; NOT yet live-verified.** See
`harness/safety_proxy_addon.py` (the addon), `harness/test_safety_proxy_addon.py`
(22 tests, built against mitmproxy's own real test fixtures, not hand
mocks), and `PROXY_SETUP.md` (CA trust setup for httpx, sqlmap, and
Burp's JVM -- source-verified for httpx and sqlmap by reading their
actual code this session; the Burp/JVM leg is standard documented
procedure, not confirmed against a real Burp instance). `safety_gate.py`
(in-process, Python-side) is complete and tested; the proxy is the next
layer, not a replacement for it.

**A real defect was found and fixed while building this**, in
`safety_gate.py` itself, not in the new proxy code: `classify()` never
URL-decoded the url/body before checking hard-deny patterns, so
`rm+-rf+/` or `rm%20-rf%20/` classified as SAFE where `rm -rf /`
correctly classified as HARD_DENIED -- a real, previously-undetected
evasion of the destructive-pattern check, present since before this
session, in the file this project's own tests call "the highest-stakes
file in this project." Fixed with a single decode-then-check pass
(checks both raw and decoded forms); see `test_safety_gate.py`'s new
`test_*_encoded_space_does_not_evade_the_*` tests.

## Why this is worth doing, specifically

`safety_gate.py` closes the risk it can see -- but it lives inside the
same Python process as the validators it gates, which creates four
specific blind spots:

1. **Process boundaries.** sqlmap runs as a subprocess. The gate decides
   whether to *launch* it; once launched, sqlmap's own internal fuzzing
   logic sends whatever it sends, with no further checkpoint.
2. **Runtime boundaries.** `ValidationExecutor.java` runs inside Burp's
   JVM -- a separate runtime the Python-side gate has no visibility into
   at all. It's currently safe by manual code review (hardcoded
   `MAX_BURST = 5`, no unbounded loops, verified this session) -- but
   "reviewed and looked fine" is weaker than "structurally can't happen."
3. **Code that never calls the gate.** The structural test in
   `test_safety_gate.py` greps for the *exact* bypass pattern already
   found and fixed. A new validator that hardcodes a dangerous method
   as a literal, rather than deriving it from `exchange.method`, would
   pass that test and bypass the gate entirely.
4. **No independent audit trail.** The gate's log lives inside the
   process it's gating. A bug that skips `authorize()` entirely leaves
   no record, because logging is a side effect of the check running.

A forced-egress proxy -- all traffic routed through it by network
configuration, not code discipline -- closes all four: it sees sqlmap's
real traffic, Java's real traffic, traffic from code that forgot to call
anything, and it's a witness that can't be silently skipped by a bug
elsewhere.

It also enables something the in-process design cannot do at all:
**cross-component accounting.** Java's burst ceiling (5) and Python's
race-condition ceiling (20, hard-capped) are independent today. If both
fired near the same target around the same time, that target could see
up to 25 concurrent mutating requests -- neither ceiling knows the other
exists. Only something in front of both can enforce a combined limit.

## Recommended design

**One policy, two enforcement points -- not two separately maintained
rule sets.** The single most likely way a second safety layer becomes
worse than no second layer is if its rules drift out of sync with
`safety_gate.py`'s and nobody notices, producing false confidence
without the substance.

- The proxy addon **imports `safety_gate.py` directly** and calls the
  same `classify()` / hard-deny-pattern logic. One source of truth.
- **Java integration is nearly free**: Burp already supports chaining
  to an upstream proxy natively. Pointing that at a local
  policy-enforcing proxy requires zero changes to
  `ValidationExecutor.java`.
- **Python integration**: `HTTPS_PROXY`/`HTTP_PROXY` env vars (httpx
  already respects these) plus sqlmap's native `--proxy` flag, both
  pointed at the same local proxy.
- Likely implementation: a `mitmproxy` addon script, since it's
  Python-native (same language as `safety_gate.py`, no cross-language
  policy translation) and has first-class support for inline
  request-blocking addons.

## Honest cost and limits, stated before starting

- Most real targets are HTTPS. A proxy that inspects content (not just
  tunnels it) needs to MITM -- a CA certificate trusted by httpx, by
  sqlmap, and potentially by the JVM's trust store. Real setup, not a
  config flag.
- This is a second enforcement point that must stay in lockstep with
  the first (mitigated by the shared-import design above, but not
  eliminated as a maintenance burden).
- The policy logic itself can be unit-tested in isolation the way
  `safety_gate.py` was. **Live TLS interception against a real target
  cannot be fully verified in a sandboxed environment without a real
  target to point it at** -- that verification gap should be closed
  with a real test run before this is trusted, not assumed away.

## Suggested next steps, in order

1. ~~Write the mitmproxy addon importing `safety_gate.SafetyGate`
   directly (reuse, not reimplementation).~~ **Done** --
   `harness/safety_proxy_addon.py`.
2. ~~Unit-test the addon's request-interception logic with mocked
   mitmproxy flow objects~~ **Done, and stronger than planned** --
   used mitmproxy's own real test fixtures (`mitmproxy.test.tflow`)
   rather than hand-rolled mocks, so the tests exercise the actual
   library's object shapes. 22 tests in `test_safety_proxy_addon.py`,
   covering fail-closed behavior on exceptions, the combined-burst
   ceiling, the startup bypass-option refusal, and non-UTF8 body
   handling.
3. ~~Document the CA-trust setup for httpx, sqlmap, and Burp's JVM.~~
   **Done for httpx and sqlmap** (source-verified against the actual
   httpx and sqlmap code, not assumed) **-- Burp/JVM section is
   standard documented procedure, not confirmed against a real Burp
   instance.** See `PROXY_SETUP.md`.
4. **Not done -- the actual remaining gap.** Run it against a real,
   disposable test target (e.g. a local OWASP Juice Shop instance) and
   confirm traffic actually flows through it before relying on it for
   anything real. `PROXY_SETUP.md` §5 lists exactly what this needs to
   confirm, including the two steps (real Burp, real sqlmap binary)
   this sandbox cannot do at all.
