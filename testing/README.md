# Testing

Two distinct things live here, for two distinct purposes. Don't
conflate them.

## `test-target/` — self-graded, for iterating on the harness itself

A small deliberately-vulnerable app (PixelMart) with a known answer key
(`test-target/ANSWER_KEY.md`), built specifically because OWASP Juice
Shop's vulnerabilities are so publicly documented that any LLM's
"success" against it is contaminated by training-data recognition
rather than genuine reasoning. Use this when you're changing
`fast_path.py`, an agent's specialty prompt, or anything else in
`harness/` and want a quick, repeatable check of whether dispatch and
detection still work — you already know the answers, so this measures
"did I break something," not "does this actually work."

Three-phase methodology: `capture_exchanges.py` → `phase1_record.py`
(real dispatch) → `phase2_answers.py` (genuine per-agent answers,
already written) → `phase3_run.py` (real end-to-end pipeline). See
`test-target/README.md` and `test-target/DISCOVERY_RUN_RESULTS.md` for
the existing results and exact reproduction commands.

## `blind-test-kit/` — for a genuine, uncontaminated measurement

A self-contained package (own harness copy, a sanitized target with
every hint stripped, a generalized version of the same three-phase
driver) meant to be handed to a **different agent who did not build the
target and does not have the answer key.** This is the only way to get
a real signal on detection quality rather than a self-graded regression
check — see `blind-test-kit/METHODOLOGY.md` for the full procedure and
`blind-test-kit/run-1-results/`, `blind-test-kit/run-2-results/` for
what's come out of it so far (one run produced no usable signal due to
shallow exploration; the next produced a real, verified result after
fixing two bugs in the tester's own answers file — see
`blind-test-kit/run-2-results/RUN_2_CORRECTED_RESULTS.md`).

**If you're about to hand this to someone for a blind run:** zip
`blind-test-kit/` and send that — don't send `test-target/` (it has the
answer key and the exploit-payload capture script sitting right in it),
and don't send the `run-*-results/` folders inside `blind-test-kit/`
either (they'd leak a prior run's discovered endpoints to a fresh
tester, undercutting their own exploration).
