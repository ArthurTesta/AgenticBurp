# Session handover 6 — confirmation legs (containerised + OOB) and the detection→confirmation coupling

Same discipline as prior handovers: every claim is **verified** by the command/test
shown, or marked **reported/pending**. This is the **authoritative current-state
doc**. Read it first, then SESSION_HANDOVER_5.md for the graph-driven engagement
loop (`investigate_engagement` = milestones A+B+C) this builds on, then HANDOVER_4
for the cross-identity/eval background.

**The one thing to internalise this time:** we expanded the deterministic
confirmation legs from 2 to 6 (they all work in isolation, verified live) — but a
max-coverage run proved the new ones confirm **nothing** in the full pipeline,
because **confirmation is coupled to detection**: a leg only runs where an agent
already produced a finding of the matching class on that exact exchange. That
coupling, not the legs, is now the ceiling. The fix is §4.

---

## 0. Read first — state, environment, hazards

- **Branch:** `WorkingSunday`. **HEAD:** `b289b89` (verified `git rev-parse`). Working
  tree clean. **NOT pushed** (local only). `main` untouched.
- **Suite green:** from `harness/`, `python -m unittest discover -p "test_*.py"` →
  **OK, 965 tests** (verified). Run before trusting anything, after every change.
- **4 commits since HANDOVER_5** (`git log --oneline 91a1a58..HEAD`), dependency-ordered:
  `e3ef6bf` XSS leg (browser_xss in the investigation path) ·
  `43d74e6` container tool-runner · `441dc84` sqlmap-in-container ·
  `b289b89` JWT-forge / XXE / SSRF legs (+ OOB collaborator).
- **Docker is now used for the SQLi leg.** Daemon must be RUNNING (Docker Desktop).
  Image `harness/sqlmap:1.10.9` is built locally (`docker build -t harness/sqlmap:1.10.9
  -f tools/sqlmap.Dockerfile tools`). If the daemon is down, sqlmap silently falls back
  to host binary / boolean probe.
- **Ollama** `qwen3:8b`, 41% CPU / 59% GPU split — still the perf bottleneck (a
  max-coverage run is ~3 h).

### HAZARDS (carried + new)

1. **Config-toggle trap** (still live). `config.yaml` at safe defaults; live toggles in
   git-ignored `config.local.yaml`. **Never `git add harness/config.yaml`** with toggles
   flipped; never commit `config.local.yaml`. Verified clean this session.
2. **NEVER read** `*ANSWER_KEY*` or a blind target's `app.py`. Target is
   `testing/vulncorp-helpdesk/` (:5002, ~40 planted, 4 roles/2 orgs). README is safe.
3. **Windows Defender quarantines host-installed offensive tools.** It removed a
   host `pip install sqlmap` this session — that is WHY sqlmap runs in a container now.
   Do NOT `pip install sqlmap` on the host. (Chromium/playwright for browser_xss stay on
   the host — a normal browser, not flagged.)
4. **The XXE/SSRF collaborator binds a loopback port in-process** (daemon thread). It
   needs nothing external; the target on the host reaches it at `127.0.0.1:<port>`.
5. **Server restart + cold cache** after any Python change (warm `*_cache.db` replays).
6. **Java can't compile here** (no JDK). Burp panel changes self-reviewed only.

---

## 1. What was built this session (all committed, all tested)

- **`43d74e6` container tool-runner** (`tool_runner.py`, `tools/sqlmap.Dockerfile`):
  runs offensive CLIs in throwaway Docker containers, not on the host. Resolves the
  docker CLI, reports daemon availability, rewrites loopback URLs to
  `host.docker.internal` (Docker Desktop networking) + adds host-gateway, runs `--rm`.
  Unit-tested with the docker seam mocked.
- **`441dc84` sqlmap in a container**: `SqlmapValidator(container_image=...)` wraps the
  (already safety-checked) sqlmap args in `docker run` and rewrites the `-u` target.
  Host binary mode unchanged when no image set. **Verified live**: sqlmap ran in the
  container against the target via `host.docker.internal` and returned a clean result.
- **`e3ef6bf` XSS leg**: the investigation `_confirm` dispatcher routes by class —
  access-control→cross-identity, xss→browser_xss (headless-browser execution). Also
  lifts precision (declines XSS that never reaches an HTML sink, e.g. a JSON API).
  Chromium installed on host (`playwright install chromium`).
- **`b289b89` JWT-forge / XXE / SSRF + collaborator** (pure Python, no container —
  they craft payloads + listen, not run a binary):
  - `collaborator.py` — in-process OOB HTTP callback listener (the Burp-Collaborator
    role, local). **Verified**: records callback hits.
  - `validators/jwt_forge_validator.py` — forge alg:none / reused-signature (+ role
    escalation), replay, confirm only when a forgery is accepted where a
    garbage-signature token is rejected. **Verified live**: confirmed VulnCorp's
    alg:none (garbage→401, forged→200).
  - `validators/xxe_validator.py` — POST an external-entity payload → collaborator; a
    callback proves resolution (blind-safe). **Verified live** against the import endpoint.
  - `validators/ssrf_validator.py` — redirect a URL-shaped param → collaborator.
    Mechanism verified; no SSRF endpoint was reachable on this target.
  - Both xxe/ssrf route their mutating sends through the safety gate
    (`GatedAsyncClient`). All three registered in the validator registry AND wired into
    the investigation `_confirm` dispatcher.

---

## 2. Deterministic confirmation legs — status

| Leg | Class | Mechanism | Verified live |
|---|---|---|---|
| cross_identity | IDOR / object-level access control | replay as other identities + anon | ✅ (45 in the run) |
| sqlmap (**container**) | SQLi | sqlmap in Docker via tool_runner | ✅ runs; 401-baseline blocks login SQLi |
| browser_xss | XSS | headless-browser execution (chromium on host) | ✅ (declines JSON XSS = precision) |
| jwt_forge | JWT alg:none / reused-sig | forge + replay + garbage control | ✅ confirmed alg:none directly |
| xxe | XXE | external-entity → OOB collaborator | ✅ confirmed directly |
| ssrf | SSRF | URL-param → OOB collaborator | mechanism ✅; no endpoint here |
| pure-Python validators | mass-assign, CORS, CSP, header-inj, deserialization, crypto, oauth, recon, race… | httpx, active_enabled | registered |

Enable in a run: `active_enabled: true`; sqlmap needs `container_image:
harness/sqlmap:1.10.9` + Docker up; xxe/ssrf need `allow_mutating_replay: true`. See
`scratchpad/max_coverage.py` for the exact config.

---

## 3. THE KEY FINDING — confirmation is coupled to detection (VERIFIED)

A max-coverage run with EVERY leg enabled (§5) confirmed **45** findings — **all of
them cross-identity IDOR**. The three new legs contributed **zero**, though each
confirms when called directly. The `maxcov_results.json` shows exactly why:

- **XXE never ran.** The XML `import` exchange produced **0 agent findings**. Validators
  dispatch PER FINDING (`for_finding(finding, exchange)`), so an exchange with no finding
  gets no validator — the leg never sees it.
- **jwt_forge never fired where it could confirm.** The jwt agent labelled "JWT
  algorithm confusion" on `admin/debug`, `admin/users`, `health`, `change-email` (all
  places the leg correctly declines — BFLA already accepts a garbage token, or POST) and
  **not** on `tickets/mine`, the one endpoint where alg:none is confirmable.
- **sqlmap** ran on the login `sql` findings but couldn't confirm (login returns 401 to
  the injection attempts and its 200 baseline means `--ignore-code` isn't added).

**So a perfect confirmation leg produces nothing unless an agent (a) produced a
finding, (b) on the exploitable exchange, (c) with a matching class label.** That
coupling — not leg quality — is the ceiling now.

---

## 4. THE NEXT LEVER — proactive, precondition-driven confirmation (highest value)

Decouple confirmation from agent labels: **drive each leg by the ENDPOINT'S SHAPE**,
in the graph-driven investigation, regardless of whether an agent flagged that class:

- run **xxe** on any endpoint that ACCEPTS XML,
- run **jwt_forge** on any JWT-carrying request to a protected endpoint,
- run **sqlmap / cross_identity** on any parameterised / object-scoped endpoint.

The engagement graph already knows each node's shape (methods, params, object-scoping,
whether the request carried a token), so `investigate_worklist` is the natural place: for
each node, pick the legs its shape warrants and run them, not just the legs matching an
agent's finding. That turns the legs from *reactive to findings* into *proactive
per-endpoint probes* — which is what would finally catch the alg:none, the XXE, etc.
Then re-run and re-measure.

Secondary levers (from HANDOVER_5, still open):
- **Dedup + confirmed-first ranking.** The run's 45 confirmed are heavy duplicates over
  ~4 endpoint-families; 225 raw findings. Collapse per-(endpoint, class), float confirmed.
- **sqlmap login-SQLi:** feed `--ignore-code`/the raw request so the 401-on-injection
  baseline stops defeating it (the boolean-probe fallback may also apply).
- **Coverage:** the SSRF integrations + deserialization cookie routes were never
  discovered (wordlist limit); in real use the Burp sitemap supplies them.

---

## 5. Max-coverage re-run (VERIFIED)

Every leg on, sqlmap-in-container, 2 passes (analyze() over 33 exchanges + the graph
loop). **10,512s (~2.9 h). `scratchpad/max_coverage.py`, `maxcov2.log`,
`maxcov_results.json`.**

- **225 findings · 45 confirmed · 19 classes hypothesised · 0 composed chains.**
- **All 45 confirmed are cross-identity IDOR** (insecure_direct_object_reference /
  IDOR/BOLA), ~4 distinct endpoint-families. Up from the prior run's 32 (also all IDOR).
- Reached (hypothesised) ~13 classes incl. sqli, jwt, xss, mass-assignment,
  open-redirect, disclosure. **Missed/unconfirmed:** jwt, xxe, ssrf, sqli, xss — all for
  the §3 coupling reason, not because the legs fail (they were each verified live in
  isolation this session).
- Prior baseline for comparison: HANDOVER_5 §5b (228/32/4-distinct).

---

## 6. Remaining work (ranked)

1. **Proactive precondition-driven leg routing (§4)** — the change that makes the 4
   new legs actually contribute in a run. Highest value.
2. **Dedup + confirmed-first ranking** — collapses 225 → a real shortlist.
3. **sqlmap login-SQLi tuning** (--ignore-code / raw-request path).
4. **Push `WorkingSunday`** + open the PR into `main` (9+ commits this session unpushed).
5. **Update the report artifact** (a56d56f5-…) — it still shows the FIRST run's
   228/32/4 and the "confirmation ceiling" framing; fold in §3's coupling finding.
6. **Containerise browser_xss** (optional, for full host-cleanliness) — needs
   playwright connect-over-CDP to a browser container; chromium-on-host works today.
7. **Java:** compile the Burp panel; wire the Cross-Identity + Discovery tabs.

---

## 7. Notes / corrections

- The legs are NOT broken — each was verified confirming live in isolation this session
  (jwt alg:none, xxe OOB, sqlmap-in-container running, collaborator hits). The run's zero
  is a ROUTING problem (§3), and the fix is §4.
- Docker networking on Windows: containers reach the host via `host.docker.internal`, not
  `--network host` (host networking is limited on Docker Desktop). `tool_runner` handles
  the rewrite.
- The in-process collaborator is deliberately in-process, not a container: it needs no
  offensive binary and nothing lands on disk. A DNS-based interactsh in a container would
  be the upgrade for internet-facing OOB; unnecessary for a local target.
