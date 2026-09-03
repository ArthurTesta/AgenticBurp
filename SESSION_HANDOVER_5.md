# Session handover 5 — the graph-driven engagement loop (coverage → prioritise → investigate → chain)

Same discipline as SESSION_HANDOVER_4.md: every claim is either **verified** this
session by the command/test shown, or marked **reported/pending**. This is the
**authoritative current-state doc**; read it first, then HANDOVER_4 for the
cross-identity/eval background it builds on.

The one thing to internalise: this session **inverted the architecture**. The old
pipeline fired ~36 agents at every captured exchange, once each, and gave up when a
shot found nothing (see SESSION_HANDOVER_4's eval: 166 findings, 14% confirmed, the
real bugs scattered mid-list). The new flow lets the **engagement graph drive**:
discover the real surface, rank what to test, give each node a bounded multi-step
investigation, and link findings into chains. Entry point:
`orchestrator.investigate_engagement()`.

---

## 0. Read first — state, environment, hazards

- **Branch:** `WorkingSunday`. **HEAD:** `5ecba71` + this docs commit (verified `git
  rev-parse`). **NOT pushed** (local only). `main` untouched.
- **Suite green:** from `harness/`, `python -m unittest discover -p "test_*.py"` →
  **OK, 941 tests** (verified). Run before trusting anything, after every change.
- **7 commits this session** (`git log --oneline dc35071..HEAD`), in dependency order
  so each commit's imports resolve and the suite is green at each:
  `4dba995` #5 slug · `1daa68b` #1 panel+toggle · `ade0215` discovery ·
  `6c9c68f` Milestone A · `e2217b0` Milestone B · `d204a2c` Milestone C ·
  `5ecba71` chain_linker canonicalise fix (from the capstone run, §5).
- **Ollama IS available in this environment now** (changed since HANDOVER_4): `qwen3:8b`
  loaded, but split **41% CPU / 59% GPU** (doesn't fully fit VRAM) — the single biggest
  perf bottleneck. A login-exchange analyze() took ~17 min in the passive pipeline;
  agents-only ~2-3 min. A full-VRAM GPU turns hours into minutes.

### HAZARDS (carried + new)

1. **Config-toggle trap** (unchanged, still live). `config.yaml` stays at safe defaults;
   live active-mode toggles live in git-ignored `harness/config.local.yaml`
   (deep-merged by `server.load_config()`). **Never `git add harness/config.yaml`**
   with toggles flipped; **never commit `config.local.yaml`**. Verified clean this
   session — the 6 commits touched neither.
2. **NEVER read** `*ANSWER_KEY*` or a blind target's `app.py`. The new blind target is
   `testing/vulncorp-helpdesk/` (VulnCorp Helpdesk, Flask, :5002, ~40 planted vulns, 4
   roles/2 orgs). Its `README.md` is safe (setup + design notes); its `ANSWER_KEY.md`
   and `app.py` are NOT.
3. **VulnCorp on :5002 rebuilds `helpdesk.db` on start** and is stateless. If login
   returns "no such table: users", stale/multiple instances are deadlocked on a 0-byte
   DB — kill them and start ONE fresh (debug off = single process). Seed accounts are in
   README §Roles.
4. **Server restart after any Python change** (`reload=False`); warm `*_cache.db` replays
   old analyses — delete/rename the cache DB for a real re-run.
5. **Two run modes, different cost.** The passive pipeline + active validators is slow
   (~17 min/exchange, sqlmap etc. fire live). Agents-only is ~2-3 min. The new
   graph-driven investigation (`investigate_engagement`) cost = discovery (~4000 read
   probes, fast) + N nodes × step_budget iterative LLM steps.
6. **Java can't compile here** (no JDK/Gradle). The Burp panel changes (#1) were
   self-reviewed against existing patterns; real gate is the user's `gradle shadowJar`.

---

## 1. What was built (all committed)

- **#5 (`4dba995`)** — `cross_identity_validator.has_object_identifier` now recognises a
  NAMED-slug object id (`/users/alice`) via a conservative rule (collection-noun
  context + reserved-word denylist + nested-collection guard), without reopening the
  `/users/me` TN3 false positive. +2 tests.
- **#1 (`1daa68b`)** — the Burp UI cross-identity toggle (the top item in HANDOVER_4 §4):
  `ValidatorRegistry.set_active_enabled / set_cross_identity_enabled / state()`; GET+POST
  `/settings` report and flip them at run time (in-memory, gone on restart);
  `HarnessClient.setValidators/setSessionHeaders`; a Cross-Identity tab in
  `HarnessToolsPanel`. +7 tests.
- **Discovery (`ade0215`)** — `api_surface_discovery.py`: active black-box API discovery
  (spec probe, nested wordlist, 405 Allow-mining, response-driven id enum, sub-resource
  sweep). Read-only, scope-gated, throttled, `max_probes`-bounded. Lifted VulnCorp
  reachable endpoints **17 → 27** (verified live). +11 tests.
- **Milestone A (`6c9c68f`)** — `role_crawl` gains `active_discovery` (sources its surface
  from discovery, ids templated to `{id}`); `engagement_builder.build_engagement()`
  fuses discover → per-role access matrix → `EngagementState` → a prioritised worklist.
  `/crawl-roles` exposes the flag. Live: surfaced an **anon-reachable `/api/admin/debug`**
  the per-exchange run never saw. +4 tests.
- **Milestone B (`e2217b0`)** — `iterative_agent` gains **path-segment mutation**
  (`mutate location=path`) so object ids can be enumerated (the pass-2 "no mutable
  parameters" gap); `worklist_investigator.investigate_worklist()` walks the ranked nodes
  top-down, derives a grounded hypothesis per node, runs the iterative agent with a step
  budget, and folds findings back (validated nodes sink → no re-test), fault-isolated.
  **Verified live:** qwen3 enumerated `/api/tickets/1 → 2..8` and confirmed IDOR in 7
  steps. +10 tests.
- **Milestone C (`d204a2c`)** — `chain_linker.link_findings()`: escalation edges
  (`detect_capabilities` → `apply_capabilities` → task graph) + chain composition
  (`chaining.detect` → `chain` tasks). `orchestrator.investigate_engagement()` runs A+B+C
  end to end incl. a bounded closed loop (re-test AS a credential a finding leaked,
  dedup/verify/cap guarded). +5 tests.

---

## 2. The new architecture — `investigate_engagement`

```
build_engagement(base, roles)                                     [A]
   ├─ api_surface_discovery.SurfaceDiscovery.discover()  → routes
   ├─ role_crawl.crawl_roles(active_discovery=True)      → access matrix + idor candidates
   └─ EngagementState.ingest_role_crawl()               → prioritised worklist (harness owns ranking)
        │
worklist_investigator.investigate_worklist(probe_fn, state, ...)  [B]
   for each top-ranked node:  _derive_probe(node) → run_active_probe (iterative agent, N steps)
        → state.ingest_findings()  (validated node sinks; never re-tested)
        │
chain_linker.link_findings(state, findings)                       [C]
   ├─ detect_capabilities/apply_capabilities → escalation edges in the task graph
   └─ chaining.detect → composed `potential-attack-chain` tasks
        │
   bounded closed loop: re-test AS any leaked credential (derived identity)
```

Returns `{summary, worklist, outcomes, chains, task_graph, ready_tasks, blocked_tasks,
idor_findings, auth_bypass_candidates}`. Requires `iterative_agent.enabled`
(run_active_probe enforces it) and, for cross-identity CONFIRMATION of the IDORs,
`validators.cross_identity` + `validators.active_enabled` (note: the iterative-agent
investigation path does NOT itself invoke the cross_identity validator — that runs in
`analyze()`; confirmation of investigation findings is the next wiring, see §4).

Each milestone maps to a user requirement from this session: coverage (A),
harness-owned prioritisation (A), agents that ITERATE instead of one-shot (B),
re-test avoidance (B), linked vulnerabilities (C), chained bugs reachable (C).

---

## 3. How to verify / operate

```bash
cd harness && python -m unittest discover -p "test_*.py"          # 940, OK
cd harness && python -m unittest test_api_surface_discovery test_engagement_builder \
              test_worklist_investigator test_chain_linker test_iterative_agent
```
Live A+B+C over a running target (needs iterative_agent enabled + Ollama):
build an `Orchestrator(cfg)` with `cfg["iterative_agent"]["enabled"]=True`, assemble
`role_crawl.RoleSession` per seed role, then
`await orch.investigate_engagement(base_url, roles, max_nodes=..., step_budget=...)`.
(See this session's `scratchpad/capstone_investigate.py` for the exact pattern.)

Discovery only, no LLM:
`SurfaceDiscovery(base, headers=<admin>, allowed_hosts=[...]).discover()`.

---

## 4. Remaining work (ranked)

- **Confirm investigation findings with cross-identity.** `investigate_engagement`'s
  iterative findings ship `confirmed=False` (LLM claims). Wire the cross_identity
  validator (or role_crawl's same-object compare) into the investigation path so a
  path-IDOR the agent reaches gets DETERMINISTICALLY confirmed, then floats to the top.
  This is the highest-value next step — it joins B's reach to HANDOVER_4's confirmation.
- **The `confirmed`-as-ranking-key fix** (from HANDOVER_4 eval): promote confirmed above
  unconfirmed and dedupe per (exchange, class). Cheap, high-impact on the ranking.
- **Capstone measurement** (see §5): a full `investigate_engagement` run vs pass 1's 8
  confirmed / 40 planted — quantify the loop's reach.
- **Coverage ceiling:** discovery is wordlist-bound; non-dictionary routes (SSRF
  integrations, refunds/approve, JWT key asset) stay invisible. In real use the surface
  comes from the Burp sitemap (proxied usage) — discovery supplements it.
- **Push `WorkingSunday`** + open the PR into `main`.
- **Java:** compile the Burp panel (#1) in Codespace; wire the Cross-Identity tab's
  Apply to the live server; add an `active_discovery` checkbox to the Discovery tab.

---

## 5. Capstone run (VERIFIED)

Full `investigate_engagement` over VulnCorp, `max_nodes=10, step_budget=12`,
iterative_agent + active validators on. **Completed in 346s (~5.8 min)** — far
faster than the passive pipeline's ~2h because investigation stops per-node on the
first confirmed reach instead of running every agent to completion.

- **Reach: 7 of 9 investigated nodes reached findings** (`stop=found`) — the iterative
  agent walked and confirmed on `/api/reports/{id}`, `/api/admin/debug` (**as
  anonymous**), `/api/kb/articles/{id}`, `/api/tickets/{id}`, `/tickets/{id}/comments`,
  `/tickets/{id}/assign`, `/tickets/{id}/attachments`. Two nodes came back empty
  (`/api/admin/users` auth probe exhausted its steps; `/uploads/{id}` gave up).
- **Access-matrix leg (deterministic, no LLM): 5 IDOR findings + 5 auth-bypass
  candidates** from the per-role matrix over 20 endpoints.
- **All investigation findings ship `confirmed=False`** — they are the iterative
  agent's claims (the model even self-reports conf=1.0). Cross-identity confirmation is
  the separate leg NOT yet wired into this path (§4 top item).
- **Escalation task graph: 11 edges** (7 `recrawl_area`, 2 `obtain`, 2
  `recrawl_as_privileged`) — but ONLY after a bug fix (`5ecba71`): the first run
  produced 0 edges because the iterative agent's free-text class labels
  ('IDOR/BOLA', 'Broken Function-Level Authorization') weren't canonicalised, so
  detect_capabilities/chaining silently skipped every LLM finding. Fixed + regression-
  tested; re-linking the same 14 findings now yields the 11 edges.
- **Composed chains: 0** — every finding this run was access-control (homogeneous); the
  chain rules compose ACROSS classes (sqli+idor, ...), so a single-class run has nothing
  to pair. Not a bug — a data property. Investigating injection-bearing nodes too (login
  SQLi, the search endpoint) would give the linker mixed classes to chain.

**Honest read vs pass 1 (8 confirmed / 40 planted):** the loop REACHES far more of the
surface (27 discovered vs 17; 7 nodes actively investigated to a finding) and links them
into an escalation graph — but its findings are unconfirmed until the cross-identity leg
is wired in. So this measures **reach**, and pass 1 measured **confirmation**; joining
them (§4) is the next step. `scratchpad/capstone_results.json` has the full detail.

---

## 6. Notes / corrections

- The iterative agent found 0/5 in HANDOVER_4's pass 2 for STRUCTURAL reasons (couldn't
  mutate path ids, couldn't forge JWTs, lost SQLi to sqlmap). Milestone B fixes the path
  one; JWT-forgery and crypto remain out of scope for the value-mutation loop and should
  route to deterministic validators, not the agent.
- On VulnCorp the credential closed-loop (finding → leaked token → re-test) has nothing
  to fire on: the app leaks passwords-in-logs, not tokens-in-responses. The edge is built
  and unit-tested; it just won't demonstrate on this target. reachable-area + chain
  linking DO fire (verified on pass-1's real 166 findings: 1 sqli+idor chain, 5 tasks).
