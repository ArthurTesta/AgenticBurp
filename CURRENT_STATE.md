# Current state

The single rolling per-session delta. Stable context (architecture, hazards, environment,
file map) is in [`CLAUDE.md`](CLAUDE.md) — read that first, then this.

**Update this file in place at session end. Do not create a new numbered handover.**

---

## State (as of session 7)

- **Branch:** `WorkingSunday`. **HEAD:** `7541ec1`. Working tree: only untracked
  `testing/` artifacts; `harness/` tracked tree clean. **NOT pushed** (local only); `main`
  untouched.
- **Suite green:** from `harness/`, `python -m unittest discover -p "test_*.py"` → **OK,
  1006 tests** (was 965 at `2ff6d68`; +41 this session, all additive).
- **Environment verified:** Ollama `qwen3:8b` reachable; Docker up (29.7.2) with
  `harness/sqlmap:1.10.9` built. No host `javac`. (See CLAUDE.md § Environment.)

## What shipped last session (7) — all committed, all tested

Confirmation was **decoupled from detection** — a leg now runs wherever an endpoint's
*shape* warrants it, not only where an agent flagged that class.

- **§4 proactive precondition legs** (`0b0a1d1`, `ebb1de5`, `7541ec1`) —
  `worklist_investigator` gains a `precondition_fn` seam; `orchestrator.shape_precondition_legs`
  (pure, module-level, unit-tested) routes legs by shape and reuses `_confirm`. Covered by
  `test_orchestrator_precondition` (22), `test_worklist_investigator` (13),
  `test_smoke_investigate` (2, real pipeline + negative control).
- **§6.2 dedup + confirmed-first collapse** (`adbf5f2`) — `report_generator` collapses per
  `(endpoint-family, canonical class)`, keeps the best instance with `duplicate_count`.
  `test_report_generator` (29).
- **§6.3 sqlmap login-SQLi tuning** (`74a2432`) — recognises auth requests, adds
  `--ignore-code 401,403`, falls back to a boolean-differential probe. `test_sqlmap_validator` (39).

## The KEY caveat — verified in the pipeline, not yet re-measured in a run

The §4 smoke test proves the wiring reaches the validator and confirms end-to-end, and
each underlying leg was verified live in isolation (session 6). **PENDING:** the full
max-coverage re-run against VulnCorp to re-measure vs the prior **225 findings / 45
confirmed (all cross-identity IDOR)**. Expectation: jwt alg:none on `tickets/mine` now
confirms proactively (it never did before), plus other mislabelled JWT/object-scoped
endpoints. Until that run exists, "§4 increased confirmed breadth in a real run" is
**reported/expected, not measured**. Runner: the max-coverage script (scratchpad, ~3 h);
use a FRESH cache DB.

## Remaining work (ranked)

1. **Re-run + re-measure §4 against VulnCorp** — the number that proves the coupling fix
   moved confirmed breadth. Highest value now.
2. **Push `WorkingSunday` + open the PR into `main`** (11+ commits unpushed across sessions).
3. **Update the report artifact** (`a56d56f5-…`) — still shows the first run's 228/32 and
   the "confirmation ceiling" framing; fold in the coupling finding and the §4 fix.
4. **Proactive xxe/ssrf in the captured-exchange (`analyze()`) path** — the shape router
   already routes them, but in `investigate_engagement` they fire only when a node carries
   a real XML body / URL param, which route-discovery seeds don't. The XML `import`
   exchange that produced 0 findings lives in the captured-exchange stream — wire the same
   router there.
5. **Containerise `browser_xss`** (optional host-cleanliness) — chromium-on-host works today.
6. **Java:** compile the Burp panel; wire the Cross-Identity + Discovery tabs (needs a JDK —
   Burp Community's bundled one is at `…/BurpSuiteCommunity/jre/bin/javac.exe`).
7. **Remaining Burp capability executors** — 9 of 31 category keys still lack a typed Java executor.

## Notes

- No config, `main`, or answer-key/target-source files were touched last session.
- Deep history for sessions 1–7 is in `archive/SESSION_HANDOVER_*.md` — for spelunking, not onboarding.
