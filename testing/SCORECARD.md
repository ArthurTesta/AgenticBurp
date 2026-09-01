# Detection scorecard — test-target (PixelMart)

Real run of the 36-agent harness against the purpose-built, **uncontaminated**
PixelMart corpus (built precisely because Juice Shop is training-contaminated).
Reproduce:

```
cd testing/test-target && python detection_fixture.py build   # model time, once
cd testing && python score.py --corpus test-target --from-cache
```

- **Model:** qwen3:8b (local Ollama) · **Corpus:** test-target (11 labeled TP + TN)
- **Date:** 2026-09-01 · **Scorer:** `testing/score.py` (exchange-level, OWASP 2021)

| Category | support | precision | recall | F1 |
|---|--:|--:|--:|--:|
| A01 Broken Access Control | 3 | 0.333 | 0.333 | 0.333 |
| A03 Injection | 4 | 0.571 | 1.000 | 0.727 |
| A04 Insecure Design (business logic) | 1 | n/a | 0.000 | n/a |
| A05 Security Misconfiguration | 1 | 0.067 | 1.000 | 0.125 |
| A07 Auth Failures | 1 | 0.500 | 1.000 | 0.667 |
| A10 SSRF | 1 | 0.333 | 1.000 | 0.500 |
| **Overall (micro)** | **11** | **0.229** | **0.727** | **0.348** |

`tp=8  fp=27  fn=3`

## Read

- **Recall is decent (0.73); precision is poor (0.23) — the harness over-fires.**
  27 false positives against 8 true detections. Injection (SQLi/XSS) is strong
  (recall 1.0). Access control (0.33) and business logic (0.0) are weak — exactly
  the categories the teardown flagged as hardest for an 8B local model.
- **This precision is a lower bound.** `score.py` is stricter than `bench.py`: it
  requires a finding to map to the *correct* OWASP category, so a real detection
  named with a different class counts against both precision and recall. Some of
  the 27 FPs and the A01/A04 misses are likely taxonomy/labeling, not pure
  detection failures — calibrating `_CATEGORY_KEYWORDS` + per-label ground truth
  is the T2 follow-up.
- **Small n (11 TPs), single pass.** Per-exchange results carry run-to-run
  variance (see `DETECTION_BENCH_METHODOLOGY.md`). Directional, not a published
  headline until blind-target-2 (uncontaminated, T2.2) corroborates.

## Next
- **Cut false positives** (the dominant problem): confidence-gate tuning + the
  taxonomy calibration above.
- **Run blind-target-2** for an independent number, then **T3** (multi-request on)
  to see whether A01/A04 recall improves.
