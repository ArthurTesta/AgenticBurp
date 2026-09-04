# AgenticVibe — project context for Claude

Stable orientation for every session. **This file + [`CURRENT_STATE.md`](CURRENT_STATE.md)
are the whole onboarding** — read those two, not the archived handover chain. Everything
here is meant to stay true across sessions; the per-session delta (branch, HEAD, test
count, what's in flight) lives in `CURRENT_STATE.md`.

## What this is

An agentic-AI-pentesting harness: a Burp-Suite copilot backed by local Ollama models that
reasons over captured HTTP exchanges and drives a graph-driven engagement loop
(`orchestrator.investigate_engagement`) with deterministic confirmation legs. It sits in
the *copilot* lane (peer set PentestGPT / Nebula / AI-OPS, not XBOW / Shannon — see
`COMPETITIVE_LANDSCAPE.md`). Detection is broad; the ongoing work is making
**confirmation** as broad as detection.

## The #0 discipline — "green tests, dead pipeline"

Real detection was silently **zero** three separate times while a large mocked suite
stayed green. That is the recurring failure mode of this project, and guarding against it
is the first rule:

- **Tie every claim to a command/test that verifies it, or mark it reported/not-verified.**
  Keep that distinction sharp in `CURRENT_STATE.md` and in what you tell the user. A
  plausible number (test count, finding count) trusted instead of inspected is the trap.
- **New pipeline code that no test exercises is the danger zone.** Add an end-to-end smoke
  test *with a negative control* (`test_smoke_detection.py`, `test_smoke_investigate.py`),
  not just unit tests of the plumbing.
- Make focused, dependency-ordered commits so the suite is green at each. End commit
  messages with the `Co-Authored-By` trailer.

## HAZARDS — read before touching anything

1. **Config-toggle trap.** `harness/config.yaml` stays at safe defaults; live active-mode
   toggles go in git-ignored `harness/config.local.yaml` (deep-merged by
   `server.load_config()`). **Never `git add harness/config.yaml`** with toggles flipped;
   **never commit `config.local.yaml`**.
2. **Never read `*ANSWER_KEY*` or a blind target's `app.py`.** Current target:
   `testing/vulncorp-helpdesk/` (Flask, :5002, ~40 planted vulns, 4 roles / 2 orgs). Its
   `README.md` is safe; `ANSWER_KEY.md` and `app.py` are NOT.
3. **Windows Defender quarantines host-installed offensive tools** — that is why sqlmap
   runs in Docker. Do **not** `pip install sqlmap` on the host. (Chromium/playwright for
   `browser_xss` is a normal browser and stays on the host.)
4. **Restart the server + use a cold cache after any Python change.** A warm `*_cache.db`
   replays the old analysis — delete/rename it (or `cache.init_cache(db_path=...)`) for a
   real re-run. Server runs `reload=False`.
5. **VulnCorp rebuilds `helpdesk.db` on start and is stateless.** "no such table: users"
   means stale/multiple instances on a 0-byte DB — kill them, start ONE (debug off).
6. **Java can't compile here** (no JDK). Burp-panel changes are self-reviewed only; the
   real gate is the user's `gradle shadowJar`.

## Environment (this machine — Windows)

- **Ollama** reachable, model `qwen3:8b`, split ~41% CPU / 59% GPU — the perf bottleneck.
  A full max-coverage run is ~3 h. Check: `curl -s http://localhost:11434/api/tags`.
- **Docker** up, with `harness/sqlmap:1.10.9` built
  (`docker build -t harness/sqlmap:1.10.9 -f tools/sqlmap.Dockerfile tools`). Daemon down
  ⇒ sqlmap silently falls back to host binary / boolean probe.
- Containers reach the host via `host.docker.internal` (not `--network host` — limited on
  Docker Desktop); `tool_runner.py` rewrites loopback URLs.
- No host `javac`.

## Architecture — `investigate_engagement` (the graph-driven loop)

The old pipeline fired ~36 agents at every captured exchange once each and gave up on a
miss. The current flow lets the **engagement graph drive**: discover surface → prioritise
→ bounded per-node investigation → link into chains. Entry: `orchestrator.investigate_engagement()`.

```
build_engagement(base, roles)                                    [A] coverage + ranking
  ├─ api_surface_discovery.SurfaceDiscovery.discover()  → routes
  ├─ role_crawl.crawl_roles(active_discovery=True)      → per-role access matrix + IDOR candidates
  └─ EngagementState.ingest_role_crawl()               → prioritised worklist
       │
worklist_investigator.investigate_worklist(...)                  [B] iterate, don't one-shot
  for each top-ranked node: _derive_probe → iterative_agent (N steps) → ingest_findings
  · a `precondition_fn` seam runs SHAPE-warranted confirmation legs per node,
    independent of whether an agent labelled that class (the §"decoupling" fix)
       │
chain_linker.link_findings(...)                                  [C] escalate + compose
  ├─ detect/apply_capabilities → escalation edges in the task graph
  └─ chaining.detect → composed attack-chain tasks
       │
  bounded closed loop: re-test AS any leaked credential
```

**Confirmation is decoupled from detection.** `orchestrator.shape_precondition_legs(node,
exchange, roles, base_url)` (pure, unit-tested) picks legs by endpoint *shape* —
object-scoped GET → cross-identity; JWT-carrying → jwt-forge; XML body → xxe; URL param →
ssrf — and reuses the live `_confirm` dispatcher. Shape is a reason to *try* a leg; only
CONFIRMED results are kept, so it never adds unconfirmed noise. The captured-exchange path
(`analyze()`) has the analogue: `orchestrator.shape_precondition_findings(exchange)` runs the
XXE/SSRF legs the exchange's own shape warrants (appended as a rule-based report before
validation, pruned to confirmed-only after), so an XML-accepting endpoint no agent labelled
"xxe" still gets its external-entity leg.

### Deterministic confirmation legs

| Leg | Class | Mechanism |
|---|---|---|
| `cross_identity` | IDOR / object-level access control | replay as other identities + anon |
| `sqlmap` (container) | SQLi | sqlmap in Docker via `tool_runner` |
| `browser_xss` | XSS | headless chromium; declines non-HTML-sink (precision) |
| `jwt_forge` | JWT alg:none / reused-sig | forge + replay + garbage-sig control |
| `xxe` | XXE | external-entity → in-process OOB `collaborator` |
| `ssrf` | SSRF | URL-param redirect → OOB `collaborator` |

Enable in a run: `active_enabled: true`; sqlmap needs `container_image: harness/sqlmap:1.10.9`
+ Docker; xxe/ssrf need `allow_mutating_replay: true` (their replay is a non-GET send —
`xxe_validator.py:84`, `ssrf_validator.py:109`). Mutating sends go through the safety gate
(`GatedAsyncClient`). See the current run script (named in `CURRENT_STATE.md`).

**Those six are the curated set — the registry is wider.** The table is what the **graph
loop**'s `_confirm` dispatcher (`orchestrator.py:814`) proves (access-control→`cross_identity`,
xss→`browser_xss`, `jwt_forge`, `ssrf`, `xxe`) plus `sqlmap`. The **captured-exchange path
(`analyze()`)** instead runs the *full* `ValidatorRegistry` via `for_finding()`
(`orchestrator.py:1450`): the same six **plus ~13 more class-scoped validators** — `cors`,
`csp`/clickjacking, `api_security`/mass-assignment, `crypto`/tls, `http_request_smuggling`,
`header_injection`/crlf, `race_condition`, `oauth`/oidc, `recon`, `websocket`/cswsh,
`subdomain_takeover`, `web_cache_poisoning`, and passive-only `deserialization`. Each declares
`finding_classes` + an `active` flag (`validators/base.py`); **all are `active` except
`deserialization`**, so under the safe default `active_enabled: false` only `deserialization`
runs — the rest arm only once a live run turns active mode on. `validators/registry.py` is the
source of truth for what's wired; the graph `_confirm` set is deliberately narrower and better
verified (see `COMPETITIVE_LANDSCAPE.md` §0 on which legs are live-verified vs smoke-only).

## Key file map (`harness/`)

| Area | Modules |
|---|---|
| Engagement loop | `orchestrator.py`, `engagement_builder.py`, `engagement.py`, `worklist_investigator.py`, `chain_linker.py`, `chaining.py`, `task_graph.py` |
| Discovery / crawl | `api_surface_discovery.py`, `role_crawl.py`, `scope_discovery.py`, `crawler.py`, `js_endpoint_extractor.py` |
| Agents / LLM | `iterative_agent.py`, `agent_manager.py`, `ollama_client.py`, `planner.py`, `analysis_pipeline.py` |
| Confirmation | `validators/` (~20 validators — `registry.py` is the source of truth: the 6 legs `cross_identity`/`sqlmap`/`browser_xss`/`jwt_forge`/`xxe`/`ssrf` **plus** `cors`/`csp`/`crypto`/`recon`/`oauth`/`header_injection`/`http_request_smuggling`/`web_cache_poisoning`/`subdomain_takeover`/`websocket`/`race_condition`/`api_security`/`deserialization`), `collaborator.py`, `active_verification.py`, `tool_runner.py` |
| Safety / infra | `safety_gate.py`, `safety_proxy_addon.py`, `security.py`, `cache.py`, `store.py`, `config.yaml` (+ git-ignored `config.local.yaml`), `server.py` |
| Reporting | `report_generator.py`, `categories.py`, `knowledge.py` |
| Burp side | `burp-extension/` (Java; can't compile here) |

## Commands

```bash
# full suite (run before trusting anything, after every change)
cd harness && python -m unittest discover -p "test_*.py"
# a focused module
cd harness && python -m unittest test_orchestrator_precondition
```
A live max-coverage run is driven by a script named in `CURRENT_STATE.md` (kept in the
scratchpad, not committed). Use a FRESH cache DB (hazard #4).

## Handover protocol — keep onboarding cheap

The whole point of this layout is that a new session reads two short files, not a chain.
To keep it that way:

- **Update `CURRENT_STATE.md` in place** at session end — overwrite it, don't create
  `SESSION_HANDOVER_N+1`. It is the single rolling delta.
- **When you learn something *stable*** (an architecture change, a new hazard, a new leg, a
  moved file), fold it into THIS file rather than re-narrating it in the next handover.
  That is what stops the 100k-token reconstruction from coming back.
- Older `SESSION_HANDOVER_*.md` and `HANDOVER.md` are archived under `archive/` for
  git-history spelunking only — not part of onboarding.
