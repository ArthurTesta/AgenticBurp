# Burp LLM Harness

A Burp Suite extension that sends a request/response pair you're looking
at to a local, Ollama-backed multi-agent analysis pipeline. A coordinator
model decides which of 36 narrow security specialists (SQLi, XSS, IDOR,
SSRF, auth, business logic, and more) are worth running on that specific
exchange, each specialist reports structured findings with evidence and a
suggested next test, an adversarial review pass attacks the high-confidence
ones before they ship, and the result shows up in a tab inside Burp.

**Default posture:** passive. Out of the box it looks at one exchange at a
time, doesn't send traffic to the target on its own, and doesn't generate
working exploits — it tells you what to try next in Repeater. Use it only
against applications you're authorized to test, same assumption Burp runs on.

**Since then it has grown opt-in active + campaign capabilities** (all OFF by
default, scope-gated to `allowed_hosts`, throttled): discovery crawls
(`/crawl`, role-aware `/crawl-roles`), an iterative send→observe→adapt agent
(`/active-probe`), real-execution validators (browser-driven XSS, sqlmap), a
missing-auth probe, and an **engagement layer** that fuses every signal
(crawl + role access matrix + LLM rating + findings) into one ranked
"test-next" worklist backed by a penetration **task graph**, with a
budget-governed driver (`/engagement/{host}/run`) and a closed
finding→credential→re-crawl loop. Every active/autonomous step stays opt-in
and human-gated by design — see the config toggles in `harness/config.yaml`.

> **Docs map:** **`CLAUDE.md`** holds the stable orientation (architecture,
> hazards, environment, file map) and **`CURRENT_STATE.md`** the per-session
> delta (branch, HEAD, what shipped, what's pending) — those two are the whole
> onboarding. The historical `SESSION_HANDOVER_*.md` chain and the old
> `HANDOVER.md` deep-reference are archived under `archive/` for git-history
> spelunking only.

---

## Is my machine good enough for this?

**Short answer: yes, a laptop with a discrete GPU or a desktop with an
RTX 3070 (8GB) can run this.** The only GPU-bound piece is Ollama; Burp
itself, the Python harness, and the Java extension all run fine on CPU.

The longer, more useful answer, since "yes" alone would hide a real
tradeoff on an 8GB card specifically:

- The default models this project ships with (`llama3.1:8b` for the
  10 explicitly-tuned agents, `gemma2:9b` for everything else — see
  [Models & config](#models--config) below) are both roughly 5-6GB on
  disk at Ollama's default `Q4_K_M` quantization. **Either one on its
  own fits comfortably in 8GB of VRAM.**
- The problem is *both at once*. Ollama can keep multiple different
  models loaded simultaneously, but only if there's enough VRAM for all
  of them — otherwise it evicts the least-recently-used one to make room
  for whichever model the next request needs. Two ~5-6GB models add up
  to more than 8GB, so on a single 8GB card they can't both stay
  resident. Since agents are dispatched *concurrently* and different
  agents can be assigned different models, this means an 8GB card will
  end up swapping models in and out of VRAM mid-analysis rather than
  running two models side by side — turning what's designed as parallel
  dispatch into effectively-serial dispatch with a reload delay (typically
  a few seconds per swap) in between. This is a reasoned estimate from
  how Ollama documents its own model-eviction behavior, not something
  measured on real hardware — if you hit this, `ollama ps` while a run
  is in progress will show you directly whether it's thrashing.
- **If you have 8GB of VRAM and want to avoid this entirely**, set every
  agent to the *same* model tag in `harness/config.yaml` (either put
  `llama3.1:8b` in `agent_defaults.model` and remove the per-agent
  overrides, or the reverse). Ollama can serve multiple concurrent
  requests against one already-loaded model without any swapping, so
  this gets you true concurrency back at the cost of not being able to
  give the harder-to-classify agents a stronger model than the routine
  ones.
- **Separately from the model-mixing issue above**, even a single
  shared model can run into trouble if too many agents are dispatched
  for one exchange at once — by default up to 6 or more agents fire
  simultaneous inference requests, and on a memory-constrained card that
  can exceed available VRAM for concurrent KV-cache allocations, forcing
  slow CPU fallback or worse. `config.yaml`'s `concurrency.max_parallel_agents`
  (default: 3) caps how many agents run at the same time regardless of
  how many were dispatched — lower it if you're still seeing slowdowns
  on an 8GB card, or raise it (or set it to 0 for unbounded) if you have
  headroom to spare.
- **If you have 12GB+ of VRAM** (3060 12GB, 3080 12GB, 4070 Ti Super,
  anything in that range or above), this isn't a concern — both default
  models fit simultaneously with room to spare, and mixed-model dispatch
  works as designed.
- CPU-only (no GPU at all) also works, just slowly — Ollama falls back to
  CPU inference automatically. Expect each agent call to take much longer
  (roughly 5-15x, very hardware-dependent), which matters because the
  harness dispatches several agents per exchange.

---

## What it actually does, end to end

1. You're looking at a request in Burp (Proxy history, Repeater, or the
   Target site map). You right-click it and choose **Send to LLM
   Harness**, or use the built-in **Attack Surface Map** tab, which scores
   every endpoint Burp has already seen using local pattern rules (no LLM
   call — exposed admin paths, numeric/UUID IDs, URL-shaped SSRF
   parameters, state-changing verbs like checkout/transfer) and ranks them
   so you know which ones are worth sending in the first place.
2. The Burp extension POSTs that exchange to a small local Python server
   (`harness/server.py`, FastAPI, `http://127.0.0.1:8787` by default).
3. The **orchestrator** decides which specialist agents to run. Most of
   the time this is a fast, deterministic pattern match (URL shape, query
   parameters, headers, response body) with no LLM call at all; only
   genuinely ambiguous exchanges get routed by an actual coordinator model
   call. See [How agent dispatch works](#how-agent-dispatch-works) below.
4. The selected agents run **concurrently**, each with its own narrow
   system prompt plus a shared set of ground rules (don't invent evidence
   that isn't in the exchange, distinguish "I reasoned this from what's
   shown" from "I'm recalling this from general knowledge" from "I'm
   assuming this," and respond with structured JSON only).
5. High-confidence findings go through an **adversarial critique pass**:
   one more model call that has to independently re-read the raw evidence,
   propose a rival explanation, and probe for a fragile assumption before
   a finding is allowed to ship as-is.
6. Anything that names a software component (a version banner, a
   dependency manifest) gets checked against the real GitHub Advisory
   Database and CISA's Known Exploited Vulnerabilities catalog —
   deterministic lookups, not the model guessing whether a version is
   vulnerable from memory.
7. Findings are saved to a local SQLite database, keyed by host, so the
   next exchange you send from the same target is analyzed with
   awareness of what's already been found there.
8. The result — findings with severity, confidence, evidence, a suggested
   Repeater test, and (for reviewed ones) the critique's verdict — renders
   in Burp's **LLM Harness** tab.

---

## Architecture

```
Burp (Proxy / Repeater / Target site map)
   │
   │  Attack Surface Map tab: local heuristic scoring, no LLM call
   │  right-click a request → "Send to LLM Harness"
   ▼
Burp extension (Java, Montoya API)
   │  HTTP POST /analyze  (localhost only, by default)
   ▼
harness/server.py  (FastAPI)
   ▼
orchestrator.py
   │
   │  1. fast_path.py: deterministic agent selection from URL/query/
   │     header/body patterns -- no LLM call for the common case
   │  2. falls back to coordinator.py (one LLM call) only when no
   │     pattern gives a confident answer
   │  3. exchange_cache (cache.py): skips re-running agents entirely if
   │     this exact exchange (content-based hash, ignoring pure
   │     transport noise like Date/ETag headers) was already analyzed
   │     with the current model/prompt versions
   │  4. dispatches the selected agents CONCURRENTLY
   ├── agents/  (36 specialists, dynamically loaded via a plugin system --
   │             see agents/plugin.py; each one is a small class with its
   │             own system prompt, grouped roughly as:)
   │      injection & payload-based:  sqli, xss, xxe, ssti, nosql,
   │          command_injection, deserialization, header_injection
   │      access control & identity:  idor, auth, jwt, oauth, csrf
   │      business/workflow:          business_logic,
   │          business_logic_enhanced, race_condition
   │      protocol & transport:       ssrf, http_request_smuggling,
   │          websocket, web_cache_poisoning, cors, open_redirect,
   │          subdomain_takeover
   │      config, recon & exposure:   misconfig, recon, info_disclosure,
   │          csp, crypto, file_upload, anomaly, rate_limit
   │      AI/LLM-specific:            ai_llm, ai_security
   │      supply chain:               supply_chain
   │      general API shape:          api_security, graphql
   │
   │  5. adversarial critique pass over high-confidence findings
   │     (one batched call, not one per finding)
   │  6. component candidates -> github_advisories.py (known-CVE lookup)
   │     and kev_check.py (is it actively exploited right now),
   │     both deterministic, no LLM call
   │  7. accumulated per-host findings -> chaining.py (rule-based
   │     relationship detection between findings, no LLM call)
   ▼
Ollama (localhost:11434) — whatever models you've pulled;
see "Models & config" below for which agent uses which by default
   ▼
harness/harness_state.db (SQLite) — findings persist across exchanges,
keyed by host, so later analysis on the same target has context
```

Every finding carries `severity` (impact, if real) separately from
`confidence` (how sure the agent is it's real at all) and a `basis` tag —
`derived` (reasoned from this specific exchange), `recalled` (general
knowledge of the vulnerability class), or `assumed` (guessing about
something the exchange doesn't actually show) — so you can tell a
genuine observation from an educated guess at a glance in the Burp UI.

### How agent dispatch works

Two layers, in order, per exchange:

1. **Fast path** (`fast_path.py`) — pattern-matches the URL, query
   parameters, headers, and response body against a curated set of rules
   (e.g. any query parameter at all implies `sqli`+`xss`; a `/graphql`
   path implies the `graphql`, `sqli`, `idor`, `business_logic` agents; a
   403 response implies `auth`+`idor`+`misconfig`). This is instant and
   free — no model call. It's deliberately conservative: if nothing
   matches with real content-based signal, it falls through to step 2
   rather than guessing.
2. **Coordinator** (`coordinator.py`) — only reached when the fast path
   found nothing. One LLM call that's shown the exchange and the full
   list of available agents, and decides which apply. If this call fails
   or returns nothing usable, it fails open and dispatches *every* agent
   rather than silently analyzing nothing — a deliberate "a false
   negative here is worse than some wasted compute" tradeoff, though it
   means a bad coordinator response is also the most expensive possible
   outcome. Worth knowing about if you're watching resource usage.

### What's already handled for you (so you don't need to think about it)

- **Caching** — an exchange that's byte-identical *for analysis purposes*
  (ignoring headers like `Date`/`ETag`/`X-Request-Id` that change on every
  request regardless of content) to one already analyzed with the same
  model and prompt versions is served from cache instead of re-run.
  Session cookies and auth tokens are deliberately never ignored here —
  the cache can't accidentally serve one user's result for a different
  user's identical-looking request.
- **Early termination** — if the first batch of agents turns up a
  high-confidence critical/high finding, remaining agents in the queue
  for that exchange can be skipped rather than run unconditionally.
- **Effort budget** — `config.yaml`'s `effort_budget` section tracks
  cumulative token spend across a whole session and can either just warn
  once you cross a number you set, or actually stop dispatching new calls
  — see the comments in that config section for which mode fits your
  situation.

---

## Setup

### 1. Install and start Ollama

```bash
# install per https://ollama.com, then:
ollama pull llama3.1:8b
ollama pull gemma2:9b
ollama serve
```

You don't strictly need both models — see [Models & config](#models--config)
below if you'd rather standardize on one (recommended on 8GB VRAM cards,
per the GPU section above).

### 2. Start the harness

```bash
cd harness
pip install -r requirements.txt
python server.py
# -> http://127.0.0.1:8787 , confirm with: curl http://127.0.0.1:8787/health
```

Requires Python 3.10+. If you want the optional forced-egress safety
proxy (routes the harness's own outbound calls through a mitmproxy addon
that fails closed rather than open — see `PROXY_SETUP.md`), also run
`pip install -r requirements-proxy.txt`; it's not required for normal use.

### 3. Build and install the Burp extension

Requires a JDK 17+ and Gradle.

```bash
cd burp-extension
gradle shadowJar     # or: ./gradlew shadowJar if you generate a wrapper first
```

This pulls Burp's Montoya API and Gson from Maven Central automatically —
you need normal internet access for this step (a from-scratch build has
not been verified in a fully offline environment). In Burp: **Extensions
→ Installed → Add → Java** → select `build/libs/burp-extension-all.jar`.
A new **LLM Harness** tab appears; set the harness URL (defaults to
`http://localhost:8787`) and click Test Connection. Then right-click any
request in Proxy history, Repeater, or the Target site map and choose
**Send to LLM Harness**, or use the **Attack Surface Map** tab to find a
promising one first.

### Models & config

`harness/config.yaml` controls everything model-related:

```yaml
coordinator:
  model: "llama3.1:8b"     # used for routing decisions -- give this
                            # your strongest available model; a bad
                            # routing call can silently skip a whole
                            # exchange before any specialist sees it

agent_defaults:
  model: "gemma2:9b"        # what any agent without its own override
                            # below uses. Most of the 36 agents are
                            # narrow, well-scoped classification tasks
                            # and don't need a large model.

agents:
  sqli:
    model: "llama3.1:8b"    # per-agent override -- takes precedence
                            # over agent_defaults for this one agent
  # ...nine more agents are explicitly pinned to llama3.1:8b in the
  # shipped config; everything else uses agent_defaults.
```

To standardize on a single model everywhere (recommended if you're on an
8GB-VRAM card — see the GPU section above): set `agent_defaults.model` to
your model of choice and delete or comment out the per-agent `model:`
lines under `agents:`.

---

## Known limitations worth knowing before you rely on this

- **No measured accuracy baseline exists for this tool against any real
  model.** Everything about "how good are the findings" is untested in
  the sense of a live model actually being scored against known-answer
  targets — see `archive/HANDOVER.md` for the full detail if you want it.
- The coordinator's fail-open-to-all-36-agents fallback (above) is real
  and currently silent — if you're watching for cost/latency spikes,
  that's the first place to look.
- `sqlmap`-based confirmation (used to validate SQLi hypotheses) has a
  known miss rate against real targets — see `archive/HANDOVER.md` §4.2. A
  "not confirmed" result from it is not strong evidence of absence.
- Full detail on everything found-but-not-yet-fixed lives in
  `archive/HANDOVER.md`; treat it as the more thorough companion to this file
  if you're planning to modify the harness rather than just run it.
