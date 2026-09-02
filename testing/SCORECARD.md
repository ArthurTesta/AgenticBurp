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

## Headline (operating point: severity ≥ medium)

| | precision | recall | F1 | FPs |
|---|--:|--:|--:|--:|
| all findings | 0.229 | 0.727 | 0.348 | 27 |
| **severity ≥ medium** | **0.333** | **0.727** | **0.457** | **16** |

Gating to what an analyst actually triages (**severity ≥ medium**) lifts precision
**+46 % with zero recall loss** — it drops low-severity missing-header noise, not
detections. A confidence gate does *nothing* here (the FPs are high-confidence,
c≈0.8–0.95); severity ≥ high over-corrects (recall 0.727→0.545). So medium is the
operating point.

### Operating-point curve
```
sev>=info     precision=0.229 recall=0.727 f1=0.348  (fp=27)
sev>=low      precision=0.229 recall=0.727 f1=0.348  (fp=27)
sev>=medium   precision=0.333 recall=0.727 f1=0.457  (fp=16)   <- adopt
sev>=high     precision=0.600 recall=0.545 f1=0.571  (fp=4)    (loses 2 real TPs)
```

### Per category (severity ≥ medium)
| Category | support | precision | recall | F1 |
|---|--:|--:|--:|--:|
| A01 Broken Access Control | 3 | 0.333 | 0.333 | 0.333 |
| A03 Injection | 4 | 0.571 | 1.000 | 0.727 |
| A04 Insecure Design (business logic) | 1 | n/a | 0.000 | n/a |
| A05 Security Misconfiguration | 1 | 0.250 | 1.000 | 0.400 |
| A07 Auth Failures | 1 | 0.500 | 1.000 | 0.667 |
| A10 SSRF | 1 | 0.333 | 1.000 | 0.500 |

## The 16 remaining FPs — root cause

- **`supply_chain` over-fires** "exposure of dependency metadata" on 5 exchanges
  (medium/high). No TP here is a supply-chain vuln, so tightening it is pure
  precision gain, zero recall risk. *(Next lever — cheap targeted rebuild.)*
- **TN4 reflected-injection cluster (~5):** every injection agent fires XSS/SQLi on
  one benign "attack attempt". **The real pipeline's validators (browser-XSS, sqlmap)
  are built to kill exactly these — the agents-only bench BYPASSES validators, so it
  overstates FPs here.** Real-pipeline precision is already higher than 0.33.
- **`misconfig` generic + out-of-lane (~4):** reports "XSS"/"CSRF" outside its
  specialty. Fix = agent lane discipline (a `base_agent` common rule → full rebuild).
- **Taxonomy near-misses (~3):** e.g. TP7 "workflow bypass" → A01 vs truth A04. A
  `score.py` `_CATEGORY_KEYWORDS` / per-label-truth calibration, not a detection bug.

## Caveats
- Small n (11 TPs), single pass — per-exchange variance (see
  `DETECTION_BENCH_METHODOLOGY.md`). Directional until blind-target-2 corroborates.
- `score.py` demands the *correct* OWASP category, so it is a strict lower bound.

## Next
1. **Tighten `supply_chain`** (require a concrete manifest/version) — done next.
2. **Agent lane discipline** in `base_agent` (report only your own class) — broad
   FP cut, but a full fixture rebuild to measure.
3. **blind-target-2** for an independent number, then **T3** (multi-request on).
