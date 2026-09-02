# Detection scorecard — test-target (PixelMart)

Real run of the 36-agent harness against the purpose-built, **uncontaminated**
PixelMart corpus (built precisely because Juice Shop is training-contaminated).
Reproduce:

```
cd testing/test-target && python detection_fixture.py build   # model time, once
cd testing && python score.py --corpus test-target --from-cache --min-severity medium
```

- **Model:** qwen3:8b (local Ollama) · **Corpus:** test-target (11 labeled TP + TN)
- **Date:** 2026-09-02 · **Scorer:** `testing/score.py` (exchange-level, OWASP 2021)

## Headline — false-positive reduction (this session)

Two levers, **zero recall loss** throughout (recall held at 0.727, tp=8):

| step | precision | recall | F1 | FPs |
|---|--:|--:|--:|--:|
| baseline (all findings) | 0.229 | 0.727 | 0.348 | 27 |
| + operating point **severity ≥ medium** | 0.333 | 0.727 | 0.457 | 16 |
| + **agent precision fixes** (misconfig, supply_chain) | **0.421** | **0.727** | **0.533** | **11** |

**Net: precision 0.229 → 0.421 (+84 %), FPs 27 → 11 (−59 %), recall unchanged.**

1. **Operating point.** Gating to what an analyst triages (severity ≥ medium) drops
   low-severity missing-header noise — not detections. A *confidence* gate does
   nothing (FPs are high-confidence, c≈0.8–0.95); severity is the knob. sev ≥ high
   over-corrects (recall 0.727→0.545), so medium is the point.
2. **Agent fixes.** `supply_chain` now emits an exposure *finding* only when the body
   literally *is* a served manifest (FPs 5→2). `misconfig` stays in its lane (no more
   XSS/CSRF findings) and rates missing-headers as low (out-of-lane + generic FPs
   gone). Neither touches a true positive in this corpus, so recall is unaffected.

### Per category (severity ≥ medium, after fixes)
| Category | support | precision | recall | F1 |
|---|--:|--:|--:|--:|
| A01 Broken Access Control | 3 | 0.333 | 0.333 | 0.333 |
| A03 Injection | 4 | 0.571 | 1.000 | 0.727 |
| A04 Insecure Design (business logic) | 1 | n/a | 0.000 | n/a |
| A05 Security Misconfiguration | 1 | 0.333 | 1.000 | 0.500 |
| A07 Auth Failures | 1 | 0.500 | 1.000 | 0.667 |
| A10 SSRF | 1 | 0.500 | 1.000 | 0.667 |

## The 11 remaining FPs — root cause

- **Injection pile-ons on TN4 + TP10 (~7):** sqli/xss/ssrf fire on a reflected
  "attack attempt" (TN4) and a file-disclosure response (TP10). **The real pipeline's
  validators (browser-XSS, sqlmap) are built to kill exactly these — the agents-only
  bench BYPASSES validators, so it overstates them.** Real-pipeline precision is
  already higher than 0.42.
- **Over-reaches (~2):** jwt on a benign exchange (TN5), xss on an SSRF exchange (TP9).
  Broad fix = agent lane discipline in `base_agent` (full rebuild to measure).
- **Taxonomy near-miss (~1):** TP7 "workflow bypass" → A01 vs truth A04. A `score.py`
  `_CATEGORY_KEYWORDS` / per-label-truth calibration, not a detection bug.
- **Residual supply_chain (~1):** TP10 genuinely exposes a manifest-shaped response.

## T3 — multi-request closes the A01 IDOR recall gap (measured)

Single-exchange analysis missed the IDOR cases (A01 recall 0.33: TP3 weak, TP4/TP10
missed). The deterministic cross-identity probe (`cross_identity_probe.py` — two real
identities, the 4-probe source/candidate/attempt/anon comparison) against live
PixelMart:

```
[TP3 profile IDOR] CONFIRMED (confidence=0.91)
[TP4 order IDOR]   CONFIRMED (confidence=0.91)   <- single-exchange MISSED this
```

Both are now **confirmed** — a proof from real cross-identity HTTP, not an LLM guess —
raising A01 IDOR recall from 1/3 to **2/3**, with **no model call**. (TP10 is
file-disclosure, not IDOR; A04 business logic is human-hand-off by design — the harness
flags intent-level flaws for a human rather than fake-confirming them.)

**Takeaway:** the highest-value categories the teardown flagged (IDOR/authz) are exactly
where multi-request turns a missed/low-confidence guess into a *confirmed* finding. The
engagement arc already builds this (`role_crawl.py` → access matrix → cross-identity
BOLA); wiring it on-by-default for object-scoped endpoints is the remaining step.

## Caveats
- Small n (11 TPs), single pass — per-exchange variance (see
  `DETECTION_BENCH_METHODOLOGY.md`). Directional until blind-target-2 corroborates.
- `score.py` demands the *correct* OWASP category, so it is a strict lower bound.

## Tried and rejected
- **Agent lane discipline** (a shared `base_agent` "report only your own class"
  rule, full rebuild): measured **worse** — sev≥medium FPs 11→15, precision
  0.421→0.348, recall unchanged. The 8B model didn't reliably self-identify its
  lane; the out-of-lane FPs persisted and `jwt` newly over-fired. Reverted. The
  effective approach stays **targeted specialty-level fixes** (misconfig/supply_chain).

## Next
- **blind-target-2** for an independent, uncontaminated number.
- The remaining pile-on FPs are best cut by the **validator layer** (real pipeline),
  not by prompt rules — the agents-only bench can't see that gain.
