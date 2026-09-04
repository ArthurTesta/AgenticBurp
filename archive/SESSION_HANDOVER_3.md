# Session handover 3 — active modes, the engagement spine, and the closed autonomous loop

Same discipline as SESSION_HANDOVER_2.md: every claim is either (a) **verified**
this session by the exact command/test shown, or (b) marked **reported/not-run**.
"+N tests" means N unit tests added and the suite green after. This file is the
**authoritative current-state doc** — SESSION_HANDOVER.md (session 1) and
SESSION_HANDOVER_2.md (session 2) are historical; HANDOVER.md is session-1-era
project detail. Read this one first.

---

## 0. Read first — state, environment, hazards

- **Branch:** `WorkingSunday`. **HEAD:** `1e43515`, pushed to `origin/WorkingSunday`
  (verified: `git push` reported up-to-date). `main` is untouched this session.
- **Test suite green:** from `harness/`, `python -m unittest discover -p "test_*.py"`
  → **OK, 889 tests** (verified). Run before trusting anything and after every change.
- **Started this session at `04ef3e3`** (end of session 2). 27 commits added
  (`git log --oneline 04ef3e3..HEAD`). No source work uncommitted (see §5 for the
  config exception).

### HAZARDS (each cost real time this/last session)

1. **The config-toggle commit trap (ACTIVE, will bite you).** `harness/config.yaml`
   in the **working tree** has two active-mode toggles turned ON that are
   **deliberately OFF in the repo**: `iterative_agent.enabled: true` and
   `engagement.auto_escalate: true`. This is the intended state — safe defaults
   committed, active modes on only for the live local server. **Any `git add
   harness/config.yaml` will sweep those ON toggles into your commit.** Twice this
   session they leaked in and had to be reverted (commits `d6abd84`, and the fix
   inside `1e43515`). Before committing config.yaml: set both back to `false`,
   commit, then re-set to `true` locally. Verified repo vs working-tree state in §5.
2. **Server must be restarted after ANY Python change.** `server.py` runs uvicorn
   with `reload=False`. A long-running server never picks up new routes/behavior.
   The signature is "new endpoint returns 404 while /health and /analyze work" —
   that's a stale server, not a bug. Restart procedure in §6. This was hit live
   (all new endpoints 404'd until restart).
3. **The running server is a DETACHED background process.** Currently **PID 20084**
   on `127.0.0.1:8787` (verified listening), started from the working-tree config
   so `iterative_agent` + `auto_escalate` are ON, `driver_execute` OFF. It is not
   tied to a terminal. Stop it with `Stop-Process -Id <pid> -Force` (find the pid
   via the port — see §6). Do NOT assume a code change is live without restarting.
4. **Java cannot be compiled here.** No JDK, no Gradle, no Montoya jar in this
   environment (verified: `javac` not found, montoya not in `~/.gradle`). All Java
   is written to match existing patterns and self-reviewed; the **real signal is
   the user's Gradle build in Codespace** (`gradle shadowJar`). One compile error
   surfaced and was fixed (`cd95320`: `setAlignmentX` needs a `JComponent`); assume
   more are possible.
5. **Prior-session hazards still apply** (carried from HANDOVER_2, not re-observed
   this session): a parallel/"side" coding agent may edit this same tree — verify
   `harness/*.py` exists and the suite imports before/after any git op. Warm
   `*_cache.db` replays old analyses in ~0.1s — delete/rename for a real re-run.
   **Do NOT read `testing/blind-target-2/app.py` or any `*answerkey*`** — it
   invalidates the blind eval.
6. **Active/aggressive modes now exist and several are ON locally.** Unlike session
   2, the harness can now drive real adaptive traffic (iterative agent, validators,
   role-crawl, the engagement driver's execute path, auto_escalate re-crawl). All
   are opt-in by config/flag and scope-gated to `server.allowed_hosts` + throttled,
   but the blast radius is larger than session 2. See §3 for every toggle.

---

## 1. What was built this session (all committed, all tested)

Chronological; each is a commit on `WorkingSunday`. Grouped by theme.

### Backlog items from HANDOVER_2 §2 (A1, F2, F5, A2–A4, V1)
- **A1 pt2 — missing-auth probe** (`32bfcbb`, `77b0f94`). `missing_auth_probe.py`:
  reconstruct a request from a CallShape/method+path, fire it auth-stripped through
  throttle+scope, flag `missing_authentication` on a substantive 2xx; garbage-token
  pass distinguishes "no auth" from "any token works". `POST /probe-missing-auth`.
- **F2 — pause→validate→remember** (`b9e6120`). `pivot_memory.py`: consumes an
  iterative agent (F4) result, holds findings unconfirmed, builds validation
  TestPlans, remembers into host history, runs `chaining.detect` + new
  `chaining.pivot_hints` (forward "you have half of chain X" directions). Wires F4:
  `orchestrator.run_active_probe`, `POST /active-probe` (gated `iterative_agent.enabled`).
- **F5 — resource governor** (`302c982`, `2fe2ddf`, `4e5b2c2`). `resource_governor.py`:
  `VulnBudgetPolicy` (per-vuln retry/agent/token caps), `PerVulnSpend`, and
  `plan_allocation` (greedy prioritizer: full/reduced/deferred + guidance under a
  budget). `run_retry_agents` (re-dispatch same agent to cap), `plan_allocation`.
  `POST /retry-agents`, `POST /plan-allocation`. `allocation_prioritizer.py`: a
  cloud-model ranking feed (`use_llm_priority`) — **model ranks, deterministic
  governor allocates/enforces**.
- **Model selection** (`499840a`, `92ec153`). `OllamaClient.list_models`;
  `set_coordinator_model` / `set_agents_model` (flip all agents or one to any model,
  e.g. gemma 31b for debugging); `GET /models` (local tags + config `models.cloud`),
  `POST /models/select`; `GET/POST /settings` (runtime throttle + retry budget).
- **A2 — browser XSS validator** (`26301fa`). `browser_driver.py` (guarded lazy
  Playwright, `available()` probe, `BrowserDriver` protocol) + `validators/
  browser_xss_validator.py`: loads candidate URLs, confirms XSS only on real
  execution (nonce via dialog/console/error). `active=True`, skips cleanly with no
  browser. Registered in `validators/registry.py`.
- **A3 — tool catalog** (`c52652c`). `tool_catalog.py`: standard web-app tools
  (ffuf/feroxbuster/dirsearch/…, sqlmap, dalfox, SSRFmap, jwt_tool, …) tagged to
  canonical vuln classes; `recommend_for_finding` templates a command to the URL.
  Auto-surfaced in `AnalysisResponse.tool_recommendations`; `GET /tools`,
  `POST /tools/recommend`. The "agent needs a tool → return it to the user" path.
- **A4 — confidential-info detector** (`68d05a8`). `confidential_info_detector.py`:
  stateless regex pass over ONE response for secrets (cloud/API keys, private-key
  blocks, connection-string creds), PII (Luhn-checked cards, SSNs), internal-infra
  (private IPs, internal hosts, fs/cloud paths). **Values REDACTED** before they
  reach a finding. Wired as a deterministic report in `analyze()`; `POST /scan/confidential`.
- **V1 — activity feed** (`0e0fa19`). `activity_feed.py`: process-wide bounded
  ring buffer of activity events with monotonic seq; `analyze()` + active-probe
  publish; `GET /activity?since=N`. (Burp panel renders it — Java.)

### The Java batch (`9edae4f`, `cd95320`, `9c1c4fc`, `bbfedda`)
- `HarnessClient` gained generic `getJson/postJson` + typed methods for **every**
  new endpoint. `AnalysisModels` gained DTOs. New **"Harness Tools" suite tab**
  (`HarnessToolsPanel`) with sub-tabs: Engagement, Models&Settings, Discovery
  (crawl + role-crawl + missing-auth), Active Testing, Budget, Tools, Confidential
  Scan, Activity. `SiteMapImporter` adds discovered endpoints to Burp's native
  Target site map (unrequested entries, no extra traffic). **Compiles in Codespace,
  not here.**

### Role-aware crawl + IDOR/authz (`0f02671`, `38d0dec`)
- `role_crawl.py`: crawl once per role (real captured session headers, never
  stored), union surface, probe every endpoint with every role → **access matrix**
  `endpoint→{role:status}`. Derives auth-bypass (anon reaches substantive 2xx, or
  inverted-privilege) + IDOR (object-scoped reachable by an identity) candidates.
  Same-object **cross-identity comparison**: identical response to distinct
  identities → BOLA `idor_findings`. `POST /crawl-roles` auto-registers a named
  identity per role (idempotent, defensive). `SiteMapImporter` + role-crawl UI.

### THE ENGAGEMENT ARC — the integration spine (this session's centerpiece)
Motivated by the user's observation that the pieces were "a series of nice
functions that don't talk to each other," and by two research sources (verified
against the actual VulnBot paper arXiv 2501.13411, plus AppSecSanta 2026, D-CIPHER,
PentAGI, CHECKMATE):
- **Slice 1 — spine** (`7be1f6c`). `engagement.py`: per-host `EngagementState`
  where crawl/role-matrix/LLM-rating/findings all land in ONE surface model,
  collapsed into a single auditable **fused "test-next" score** with per-endpoint
  reasons (privileged-path-reachable-by-anon and object-scoped-reachable outrank a
  bare tier; validated drops). `normalize_path` aligns `/orders/{id}` with
  `/orders/42`. Wired (all defensive): `analyze` folds findings, `/crawl` +
  `/crawl-roles` fold surface+matrix+identities, `/prioritize` folds LLM ratings.
  `GET /engagement/{host}`. Persisted per-host JSON (`store.save/load_engagement`).
- **Slice 2 — closed loop** (`bb45668`). `detect_capabilities`: a finding+response
  yields a `credential` (JWT/cookie/token observed — headers EPHEMERAL, never
  persisted) or `reachable_area`. `apply_capabilities` folds them into the work
  queue. With `auto_escalate` on, `analyze()` re-crawls the origin as the new
  derived identity in-process and folds new surface back — the token-leak→identity→
  new-surface cycle, automatic.
- **Slice 3 — Burp UI** (`bbfedda`). Engagement tab: ranked JTable + advance.
- **Slice 4 — driver** (`d1731db`). `plan_engagement` (pure planning: fused
  worklist → F5 governor budget → ranked full/reduced/deferred plan). `run_engagement`
  opt-in execute, **double-gated** (`execute=true` request AND
  `engagement.driver_execute` config). `POST /engagement/{host}/run`.

### The 4 architecture gaps from AppSecSanta 2026 + VulnBot (verified against the paper)
- **Gap 1 — penetration task graph** (`b0b80e8`). `task_graph.py`: VulnBot-style
  dependency DAG replacing the flat queue. Two-axis lifecycle — a FAILED prereq
  does NOT satisfy dependents. `detect_capabilities` writes real edges
  (`obtain(DONE)→recrawl_as_derived(READY)`; privileged-anon area → BLOCKED
  `needs="privileged credentials (human)"`). `GET /engagement/{host}` returns
  `ready_tasks` + `blocked_tasks`.
- **Gap 2 — re-planning loop** (`77d37f0`). `run_engagement` is now VulnBot's
  Plan/Task/Summarizer cycle: each round plan→execute→summarize→re-plan, bounded by
  `max_rounds` + effort budget + convergence, de-duping targets across rounds.
- **Gap 4 — business-logic hand-off** (`179d408`). `business_logic_review`: flag
  business-logic classes/path-shapes (checkout, transfer, coupon, wallet…) as a
  BLOCKED `needs="human judgment"` task — never fake-confirmed. Per the survey's
  "~70% of critical vulns are business logic; agents can't detect intent."
- **Gap 3 — Memory Retriever** (`7b64d08`). `knowledge.retrieve` now merges the
  built-in corpus with tester-authored notes + auto-remembered confirmed findings
  from the store (keyword-scored, no embedding dep). `analyze()` auto-remembers
  confirmed findings (class + path shape only). `POST/GET /knowledge`.
- **auto_escalate guards** (`1e43515`). Three bounds on the credential re-crawl:
  DEDUP (identity already escalated → skip), VERIFY (probe the credential once
  before spending a crawl; ≥400/out-of-scope → discard), CAP
  (`engagement.max_auto_escalations`, default 10, per host per process). **Also
  fixed a latent bug**: `httpx` + `global_throttle` were used in slice-4's
  `run_engagement` but only imported inside `__init__`, so the driver's execute
  path NameError'd on every fetch and swallowed it — now module-level imports.
  The D-CIPHER auto-prompter was deliberately NOT adopted (documented to hurt).

---

## 2. Full new-endpoint surface (all on `harness/server.py`, loopback + optional bearer)

Verified registered (`server.app.routes`). Grouped:
- Discovery: `POST /crawl`, `POST /crawl-roles`, `POST /probe-missing-auth`
- Active: `POST /active-probe` (gated `iterative_agent.enabled`),
  `POST /retry-agents`, `POST /plan-allocation`
- Engagement: `GET /engagement/{host}`, `POST /engagement/{host}/run` (driver,
  plan-only unless `driver_execute`), `POST /engagement/{host}/advance`
- Models/settings: `GET /models`, `POST /models/select`, `GET/POST /settings`
- Tools/knowledge/scan: `GET /tools`, `POST /tools/recommend`,
  `POST /scan/confidential`, `GET/POST /knowledge`
- Observability: `GET /activity?since=N`
- (Pre-existing: `/analyze`, `/estimate`, `/prioritize`, `/effort`, `/report`,
  `/identities`, `/sessions`, `/health`, `/validation-results`, `/test-plans`,
  `/findings/*`, `/cache/*`.)

---

## 3. Config toggles (harness/config.yaml) — repo default vs live

All active/aggressive modes default OFF in the repo (safe checkout). Verified.

| key | repo default | working tree (live server) | effect |
|---|---|---|---|
| `coordinator.cloud_primary` | false | false | cloud 31b routes first; fast_path becomes floor |
| `adaptive_respin.enabled` | false | false | no-op unless cloud_primary |
| `iterative_agent.enabled` | **false** | **true (uncommitted)** | `/active-probe` + F4 |
| `engagement.auto_escalate` | **false** | **true (uncommitted)** | credential-leak → auto re-crawl |
| `engagement.driver_execute` | false | false | driver may fetch+analyze (else plan-only) |
| `engagement.max_auto_escalations` | 10 | 10 | per-host escalation cap |
| `validators.active_enabled` / `allow_mutating_replay` | true (armed, pre-session) | true | active validators + mutating replay |
| `throttle.max_requests_per_second` | 0 (unlimited) | 0 | global outbound ceiling |

The two **uncommitted** rows are the config-toggle trap (§0.1). Everything else in
config.yaml matches the repo.

---

## 4. Architecture map (how it corresponds to the surveyed tools)

VulnBot's 5 modules → ours: Planner = `plan_engagement`+`run_engagement` loop;
Memory Retriever = `knowledge.py` (corpus + store notes + remembered findings);
Generator = specialist agents → findings + `tool_catalog`; Executor = validators /
`analyze` / iterative agent (real sends); Summarizer = `_summarize_round` +
engagement `summary()`; Penetration Task Graph = `task_graph.py`.

The deliberate divergence (endorsed by the survey's 87%→~0 lab-to-real cliff):
**every active/autonomous step is opt-in and human-gated** — we do not chase full
autonomy. The driver plans by default; execute is double-gated; findings need
approval; business logic is handed to the human.

---

## 5. Verified state at handover

```
HEAD 1e43515 (WorkingSunday), pushed. Suite: 889 tests OK.
Uncommitted source: harness/config.yaml ONLY (the 2 local toggles, §3).
Other uncommitted/untracked: the built *.jar, harness_state.db / harness_cache.db
  (runtime artifacts), and the pre-existing untracked testing/* kit files
  (present at session start too; recoverable at bdbd9e6 per HANDOVER_2).
Server: PID 20084, 127.0.0.1:8787, detached, config = iterative+auto_escalate ON.
```

---

## 6. How to verify / operate

```bash
cd harness
python -m unittest discover -p "test_*.py"              # full suite (~889, OK)
python -m unittest test_engagement test_task_graph \
  test_engagement_driver test_engagement_escalation \
  test_role_crawl test_knowledge_rag                    # this session's core units
```
Restart the server after any Python change (PowerShell):
```
$c = Get-NetTCPConnection -LocalPort 8787 -State Listen -ErrorAction SilentlyContinue
if ($c) { Stop-Process -Id $c.OwningProcess -Force }; Start-Sleep -Seconds 2
# then, from harness/:  python server.py   (backgrounded)
```
Confirm live flags: `python -c "import server as s;o=s.orchestrator;print(o.engagement_auto_escalate,o.engagement_driver_execute,o.iterative_agent_enabled)"`.
Commit config.yaml safely: set `iterative_agent.enabled:false` + `auto_escalate:false`
first, commit, then re-set both to true locally (uncommitted).

---

## 7. Remaining backlog (what the next agent should build)

**Highest-value, and the last item from the session-3 improvement list:**
- **Campaign report** — the reporting (`report_generator.py`) predates the whole
  engagement arc and is per-exchange. Build an engagement-aware report: surface
  coverage, the role×URL access matrix, the escalation/task-graph chain (finding →
  identity gained → new surface → finding), results grouped by identity. This is
  the natural renderer of the task graph + engagement state.

**Other candidates (lower priority):**
- Fused-score **calibration**: the weights in `engagement.SurfaceEndpoint.fused_score`
  are hand-tuned. Track precision@k (did high-ranked endpoints yield confirmed
  findings?) and make weights config-tunable.
- Cross-surface **dedup** of findings/plans at the engagement level (the Juice Shop
  "sqlmap 0→15, same endpoint" problem).
- **Validation → routing feedback**: a confirmed class on one endpoint should bias
  fast_path/coordinator toward the same class on structural siblings.
- **Coverage metric** on the engagement summary ("N high-priority untested remain").
- Wire the role-crawl `idor_findings` into one-click `cross_identity_compare`
  TestPlan execution in the Burp plan executor.
- Execution **sandboxing** for the sqlmap subprocess path (PentAGI's Docker theme;
  our in-process httpx paths are already low-risk).

**Java that will need Codespace verification:** the whole Harness Tools tab +
Engagement tab + SiteMapImporter (committed, self-reviewed, uncompiled here).
