# Session handover 7 — decoupling confirmation from detection (§4), dedup (§6.2), sqlmap login SQLi (§6.3)

Same discipline as prior handovers: every claim is **verified** by the command/test
shown, or marked **reported/pending**. This is the **authoritative current-state
doc**. Read it first, then SESSION_HANDOVER_6.md for the confirmation-leg work and the
detection→confirmation coupling this session attacks, then HANDOVER_5 for the
graph-driven engagement loop (`investigate_engagement`) it all builds on.

**The one thing to internalise this time:** HANDOVER_6 §3 proved the ceiling was the
*coupling* — a confirmation leg only ran where an agent had already produced a finding
of the matching class on that exact exchange, so the new legs confirmed nothing in a
full run despite each working in isolation. This session implements the fix
(HANDOVER_6 §4): confirmation is now driven by the ENDPOINT'S SHAPE, independent of
agent labels. It is unit-tested AND covered by a new hermetic end-to-end smoke test —
but the empirical **re-run and re-measure** against VulnCorp (the number that proves it
moved the needle) is still PENDING (§4 below).

---

## 0. Read first — state, environment, hazards

- **Branch:** `WorkingSunday`. **HEAD:** `7541ec1` (verified `git rev-parse`). Working
  tree: only untracked `testing/` artifacts (as at session start); **`harness/` tracked
  tree clean**. **NOT pushed** (local only). `main` untouched.
- **Suite green:** from `harness/`, `python -m unittest discover -p "test_*.py"` →
  **OK, 1006 tests** (verified; was 965 at HEAD `2ff6d68`, +41 this session — all additive).
- **6 commits this session** (`git log --oneline 2ff6d68..HEAD`), dependency-ordered so the
  suite is green at each:
  `0b0a1d1` §4 proactive precondition-driven legs (worklist_investigator + orchestrator) ·
  `adbf5f2` §6.2 dedup + confirmed-first collapse (report_generator) ·
  `74a2432` §6.3 sqlmap login-SQLi tuning (validators/sqlmap) ·
  `ebb1de5` §4 shape-routing extracted to module level + unit-tested ·
  `7541ec1` §4 end-to-end smoke test.
- **Environment (verified this session):** Ollama reachable, model `qwen3:8b`
  (`curl -s http://localhost:11434/api/tags`). Docker up (29.7.2) with the pinned
  `harness/sqlmap:1.10.9` image already built. No host `javac`.

### HAZARDS (carried from HANDOVER_6 — still live)

1. **Config-toggle trap.** `harness/config.yaml` stays at safe defaults; live toggles go
   in git-ignored `config.local.yaml`. **Never `git add harness/config.yaml`** with
   toggles flipped; never commit `config.local.yaml`. Verified clean this session (the 6
   commits touched neither).
2. **NEVER read** `*ANSWER_KEY*` or a blind target's `app.py`. Target is
   `testing/vulncorp-helpdesk/` (:5002). README is safe.
3. **Windows Defender quarantines host-installed offensive tools** — that is why sqlmap
   runs in the container. Do NOT `pip install sqlmap` on the host.
4. **Server restart + fresh cache after any Python change** — a warm `*_cache.db` replays
   the old analysis (use `cache.init_cache(db_path=...)` or delete it for a real re-run).
5. **Java can't compile here** (no JDK) — Burp panel changes self-reviewed only.

---

## 1. What was built this session (all committed, all tested)

### §4 — Proactive, precondition-driven confirmation legs (`0b0a1d1`, `ebb1de5`, `7541ec1`)

The coupling fix. A leg now runs wherever an endpoint's SHAPE warrants it, not only where
an agent flagged that class.

- **`worklist_investigator.investigate_worklist` gains a `precondition_fn` seam.** For each
  scanned node it runs the shape-warranted legs REGARDLESS of whether the agent probe
  produced a finding — including on nodes with **no actionable agent hypothesis at all**
  (a JWT-carrying endpoint the agent would skip still gets its alg:none forged). It keeps
  only CONFIRMED results, so shape is a reason to TRY a leg, never a source of unconfirmed
  noise. The module stays network/LLM-free (the seam does the work). Bounded by
  `max_precondition_legs` (default 24).
- **`orchestrator.shape_precondition_legs(node, exchange, roles, base_url)`** (module-level,
  pure, unit-tested) picks the legs: object-scoped GET → cross-identity; JWT-carrying GET →
  jwt-forge (seeded from the **lowest-trust** reachable identity that actually carries a
  JWT); XML body → xxe; URL-shaped param → ssrf. `investigate_engagement`'s `_precondition`
  is now a thin loop over this router reusing the already-live `_confirm` dispatcher on an
  isolated `exchange.model_copy()` (so a baseline-populating leg can't perturb the agent
  probe).
- **The xxe/ssrf legs need a real request body/param**, which route-discovery seeds don't
  carry — so in `investigate_engagement` they fire only on a captured exchange that has that
  shape (real Burp use), never as a blind guess. jwt-forge and cross-identity are the legs
  that fire from route+identity shape alone, which is the §3 case (jwt alg:none on
  `tickets/mine`).

**Verification:**
```bash
cd harness
python -m unittest test_orchestrator_precondition   # 22 tests: the shape router
python -m unittest test_worklist_investigator        # 13 tests incl. 6 precondition-wiring
python -m unittest test_smoke_investigate            # 2 tests: REAL investigate_engagement
```
`test_smoke_investigate` is the important one: it runs the real
`investigate_engagement` → `worklist_investigator` → `_precondition` →
`shape_precondition_legs` → `_confirm` → real `jwt_forge_validator` pipeline against a
canned one-endpoint surface and a stubbed vulnerable/secure socket, and asserts a
JWT-carrying endpoint **no agent labelled "jwt"** still gets its alg:none forgery
confirmed. The negative control (a signature-verifying server) proves it guards
CONFIRMATION, not just that the leg ran. This is the analyze()-smoke-test discipline
(`test_smoke_detection.py`) extended to the investigation path, which nothing covered
before.

### §6.2 — Dedup + confirmed-first collapse in the report (`adbf5f2`)

`report_generator.generate_markdown_report` now collapses findings per
`(endpoint-family, canonical class)` — object ids normalised to `{id}` so `/tickets/1`
and `/tickets/2` are one family — keeping the best instance (confirmed > severity >
confidence). The survivor carries `duplicate_count` and the report states how many
collapsed, so nothing is silently dropped. Turns a max-coverage run's 225/45 duplicate
pile into a real shortlist. Host-scoped (called with `store.all_host_findings()`).
```bash
cd harness && python -m unittest test_report_generator   # 29 tests (+4 collapse)
```

### §6.3 — sqlmap login-SQLi tuning (`74a2432`)

A valid-cred (2xx) login capture defeated sqlmap: its payloads break the credential
predicate and get 401, which sqlmap skips as "target not testable" — and the existing
`--ignore-code` only fired for a non-2xx BASELINE, which a successful login isn't. Two
fixes in `validators/sqlmap.py`:
1. Recognise an auth request (`_looks_like_auth_request`: credential body/query field, or
   an auth-shaped path segment — exact-segment matched so `authors`/`passengers` don't
   false-match) and add `--ignore-code 401,403` (comma-list verified against the pinned
   image), scoped to those requests.
2. When sqlmap still misses an auth endpoint, run the dependency-free boolean-differential
   probe as a SECONDARY (it reads the 2xx↔401 flip directly) and prefer a real CONFIRMED
   over sqlmap's miss. A genuine sqlmap confirmation is never overridden.
```bash
cd harness && python -m unittest test_sqlmap_validator   # 39 tests (+10)
```

---

## 2. The KEY caveat — §4 is verified in the pipeline, not yet re-measured in a run

The smoke test proves the §4 wiring reaches the validator and confirms end-to-end, and the
underlying legs (jwt alg:none, cross-identity, xxe OOB) were each verified live in
HANDOVER_6. What is **PENDING** is the empirical re-run HANDOVER_6 §4 asked for: run the
full max-coverage suite against VulnCorp with the proactive routing on and re-measure vs
the prior `225 findings / 45 confirmed (all cross-identity IDOR)`. The expectation is that
jwt alg:none on `tickets/mine` now confirms proactively (it never did before), plus any
other JWT/object-scoped endpoint the agents mislabelled. Until that run exists, "§4
increased confirmed breadth in a real run" is **reported/expected, not measured**.

`scratchpad/max_coverage.py` (from HANDOVER_6 §5) is the runner; a run is ~3 h on this
`qwen3:8b` 41% CPU / 59% GPU split. Use a FRESH cache DB (hazard #4).

---

## 3. Remaining work (ranked)

1. **Re-run + re-measure §4 against VulnCorp** (§2 above) — the number that proves the
   coupling fix moved confirmed breadth. Highest value now.
2. **Push `WorkingSunday` + open the PR into `main`** (11+ commits unpushed across sessions).
3. **Update the report artifact** (`a56d56f5-…`) — still shows the first run's 228/32 and
   the "confirmation ceiling" framing; fold in HANDOVER_6 §3's coupling finding and this
   session's §4 fix.
4. **Proactive xxe/ssrf coverage in the captured-exchange (`analyze()`) path** — the §4
   router already routes them, but in `investigate_engagement` they only fire when a
   discovered node carries a real XML body / URL param, which route-discovery seeds don't.
   The XML `import` exchange that produced 0 findings in HANDOVER_6 §3 lives in the
   captured-exchange stream, so wiring the same shape router there is the natural next step.
5. **Containerise browser_xss** (optional host-cleanliness) — chromium-on-host works today.
6. **Java:** compile the Burp panel; wire the Cross-Identity + Discovery tabs (needs a JDK —
   Burp Community's bundled one is at `…/BurpSuiteCommunity/jre/bin/javac.exe`).
7. **Remaining Burp capability executors** (HANDOVER §5h left 9 of 31 category keys without
   a typed Java executor) — unchanged this session.

---

## 4. Notes / corrections

- The §4 legs are NOT limited to `investigate_engagement`'s discovery seeds — the router is
  a pure function (`shape_precondition_legs`) that reads any exchange's shape, so it drops
  cleanly into the captured-exchange path too (§3 item 4).
- `_confirm` (the dispatcher the proactive legs reuse) was already proven live: the
  max-coverage run's 45 confirmed IDORs all came through its cross-identity branch. §4 adds
  callers, not a new confirmation mechanism.
- No config, no `main`, and no answer-key/target-source files were touched this session.
