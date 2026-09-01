# Competitive & Architectural Landscape — where this harness stands

> **What this is:** a differential teardown of the agentic-AI-pentesting field
> (~35 projects) and an honest placement of *this* project within it. Written
> to be handed to a future agent so it doesn't re-derive the comparison from
> scratch, or — worse — position this tool against the wrong competitors.
>
> **Discipline (same as the other handover docs):** claims about *this project*
> are tied to files/docs already verified in-repo (README, `REVIEW.md`,
> `HANDOVER.md`, `SESSION_HANDOVER_2.md`). Claims about *competitors* come from
> a single secondary source (below) and are **NOT independently verified** —
> treat their benchmark numbers as "as reported," not as fact.
>
> **Primary source:** appsecsanta.com/research/ai-pentesting-agents-2026
> (surveyed 2026-09-01). **Human-facing version** of this same analysis (styled,
> with sortable tables): Artifact `Where the Harness Stands`
> — https://claude.ai/code/artifact/0760bd85-2509-4502-96c1-4096efcf6dc0
>
> **Related in-repo:** `archive/RESEARCH_NOTES.md` holds the *decision history*
> (why 36 agents, what was adopted from PentAGI/PentestGPT/VulnBot each round).
> This file is the *competitive placement*; that file is the *build log*. Keep
> them distinct.

---

## 0. The verdict, before the evidence

**This is the best-in-class member of a different, smaller category than the
one the field is mostly about.** The Tier-1 headliners (PentAGI, Shannon,
Strix, XBOW) are **autonomous exploitation engines** — they chain steps, send
live traffic, and produce a working proof-of-concept. This harness is an
**analyst-in-the-loop reasoning copilot that lives inside Burp**, looks at one
request/response exchange at a time, and tells you what to try next in Repeater.

- Judged **as an autonomous agent**, it loses on nearly every benchmarked axis,
  and its one fatal gap is unmissable: **it has never been scored** (no
  precision/recall exists; all 506 tests are mocked — see `REVIEW.md`).
- Judged **as a Burp copilot**, it is one of the most thoughtfully-architected
  things in the entire survey, largely because of its **epistemic discipline**:
  it refuses to let the model be the judge of "is this really vulnerable."

**Do not position this against XBOW / Shannon / PentAGI.** The right peer set is
**PentestGPT, Nebula, AI-OPS** (advisory/copilot class). Positioning it against
the autonomous engines is how you get an unfair, losing comparison — and it's
the mistake the source article's framing invites.

---

## 1. Five architectures, not thirty-five

Strip the branding and the field collapses into a handful of structural bets.
This project's lane is marked ★.

| Archetype | Who | Strength | Cost |
|---|---|---|---|
| Autonomous multi-agent orchestrator | PentAGI, Strix, Pentest Swarm, BlacksmithAI, CAI | End-to-end recon→exploit→report, parallelism, scales to real engagements | Orchestration overhead, multiplied API spend, infra (Docker/DB), hard-to-audit emergent behavior |
| Planner-executor + task graph | VulnBot, HackSynth, PentestGPT, ARACNE | Explicit plan/state separation tames context overflow; DAGs kill redundant work | Graph/plan construction is itself complex; only as good as the planner model |
| MCP tool-server | HexStrike (150+), AutoPentest-AI, PentestMCP, pentest-ai | Model-agnostic, huge tool ecosystems, composable with any MCP client | **No reasoning of its own** — all judgment offloaded to the client LLM |
| ★ **Copilot / advisory** | Nebula, AI-OPS, PentestGPT, **this harness** | Human keeps control & authorization; low blast radius; fits existing workflow | Throughput bounded by the human; no autonomous chaining; easy to dismiss as "a wrapper" |
| Static / binary discovery | VulnHuntr, VulHunt, Shannon (hybrid) | Sees whole call chain / binary; finds real zero-days; no live-traffic risk | Needs source or binary; blind to runtime/stateful behavior; language/format-bound |
| Hybrid symbolic + LLM (CRS) | Atlantis, Buttercup, Theori, ARTIPHISHELL (DARPA AIxCC) | Symbolic layer = ground-truth verification; auto-patching; highest assurance | Enormous complexity/compute; aimed at C/CWE code vulns, **not web pentest — a different sport** |

**Key synthesis for a future agent:** this project sits in the *copilot* lane
but quietly borrows the *CRS* lane's best idea — **a deterministic layer that
verifies rather than trusts the model** (GitHub Advisory DB, CISA KEV, sqlmap).
That combination — copilot ergonomics + symbolic-style verification — is
genuinely rare in the survey and is the thing worth protecting.

---

## 2. The differential (stated relative to what already exists)

### Edges this harness genuinely has

- **Hallucination discipline as a first-class design.** Three-axis findings
  (`confidence` = is it real, `severity` = does it matter, `basis` =
  derived/recalled/assumed), agents forbidden to assert CVEs from memory
  (`agents/base_agent.py` rules), adversarial critique pass before shipping.
  *vs. the whole MCP tier (HexStrike/PentestAgent), whose quality is "whatever
  the LLM said" with no epistemic guardrails.*
- **Verification by deterministic authority, not the model.** "Is it really
  vulnerable?" is answered by GHA / KEV / sqlmap — code, not vibes. Same
  philosophy as the AIxCC symbolic layer, at a tiny fraction of the complexity.
  *vs. most Tier 1/2 agents, which let the LLM self-assess exploitability.*
- **Native to the tool pentesters already live in.** Right-click in Burp → 36
  specialists on that exact exchange → results in a Burp tab. *vs. standalone
  Docker/CLI (PentAGI/Strix/Zen) and Claude-Code-locked terminals
  (Raptor/pentest-ai-agents) — none meet the analyst where they work.*
- **Local-first & genuinely air-gappable.** Ollama on a consumer GPU; no
  exchange data leaves the machine. *Shared with CAI/Nebula/AI-OPS, but those
  lack the epistemic layer above; XBOW/Mythos/Swarm-AI are cloud/API-bound.*
- **36 reasoning specialists, not 150 tool wrappers,** dispatched by a cheap
  deterministic fast-path with an LLM coordinator only for ambiguous exchanges;
  cost-controlled via content-hash cache (keyed on prompt version) + effort
  budget. *vs. Zen (72 tools) / HexStrike (150) — those are execution breadth;
  this is reasoning breadth with a spend ceiling.*
- **It threat-models itself.** Hard safety ceilings config can only tighten,
  deny-list patterns, GET-by-default, double opt-in for mutating replay,
  secret-header redaction before the model sees them (`safety_gate.py`,
  `security.py`). Mature dual-use hygiene the article doesn't even ask about.

### Where the field is ahead (and who)

- **No scored efficacy — at all.** No precision/recall against a known-answer
  corpus; 506 tests are all mocked (prove plumbing, not detection). *vs. Shannon
  (96.15% reported), PentestGPT (USENIX + Distinguished Artifact Award),
  HackSynth (200-challenge), AutoPentest ($96.20 cost-transparent run).*
  **This is the single biggest gap. The corpus + answer key already exist in
  `testing/` — they were just never tallied.**
- **Single-exchange scope on the vulns that matter most.** IDOR/authz/business-
  logic need multi-request, multi-identity differential testing; the core loop
  is single-shot. (The iterative agent, cross-identity IDOR, and missing-auth
  probe are *written but not wired in by default* — see `SESSION_HANDOVER_2.md`
  §1–2.) *vs. VulnBot's task-graph and every autonomous orchestrator.*
- **No autonomous execution, no working PoC.** It tells you what to try; it
  doesn't prove the bug. *vs. Shannon (PoCs), Strix/PentAGI/XBOW (autonomous
  exploitation, real filed vulns).*
- **8–9B local models on the hardest reasoning.** Business-logic/authz are
  exactly where `llama3.1:8b`/`gemma2:9b` are weakest — and the coordinator
  routing call (silently decides if an agent runs; fails open to all 36) is the
  highest-leverage, least-measured point. *vs. CAI (frontier-capable), PentAGI
  (12+ providers), XBOW/Mythos (frontier). `coordinator.cloud_primary` exists
  but defaults off.*
- **The "deterministic confirmation" leg degrades in practice.** GHA is 60/hr
  unauthenticated, KEV live-fetch "not verified working," sqlmap historically
  not installed (`REVIEW.md`, `HANDOVER.md` §4.2). The marketed strength often
  falls back to "unconfirmed." *vs. AIxCC CRS, where verification IS the product.*
- **Prototype, not a product.** Single squashed git commit, DBs + built `.jar`
  tracked in git, a full divergent duplicate harness under `testing/`, no CI, no
  pinned deps, no packaging. *vs. PentAGI (~14.7k★ product), Zen/Strix (GH
  Actions), AIxCC finalists (competition-hardened).*
- **History of "green tests, dead pipeline."** Detection has been silently zero
  multiple times while the mocked suite stayed green (a system-prompt validator
  rejected every agent; 12/13 active validators broken until first exercised —
  `HANDOVER.md` §0, §5i). A credibility gap until an end-to-end scored run exists.

---

## 3. Two-lens critique

### Software engineer / architect — "will this hold up as a system?"

1. **Core architecture is right, and rarely so — keep it.** "LLM as planner +
   evidence-extractor, deterministic layer as judge" is the correct answer to
   hallucination in security tooling. Fast-path/coordinator split, content-hash
   caching keyed on prompt version, effort budgets, plugin-loaded agent roster —
   all the choices of someone who thought about cost and determinism. **Do not
   rewrite.**
2. **The test strategy is inverted — fix first.** 506 mocked tests proved
   plumbing while real detection was silently zero *three separate times*. The
   missing test is one end-to-end smoke test against a **stub Ollama** returning
   canned JSON, asserting known findings on a known-vulnerable fixture. That one
   test catches every historical incident. Until it exists, the green suite is
   actively misleading.
3. **Repo hygiene is below the bar for a security tool.** Squashed history (no
   bisect/provenance), binaries + runtime DBs in git, a second source-of-truth
   harness copy under `testing/`, no CI, no pinned deps. Not architectural — but
   it's the difference between a prototype and something a second engineer can
   safely touch.
4. **Silent failure is the recurring enemy — instrument it.** Coordinator
   fails open to all 36 agents on a bad response (safe for recall, but silent,
   most-expensive, unmetered). ~26 broad `except Exception` sites, several
   log-and-drop. For a system whose failure mode is *quietly finding nothing*,
   observability is the primary safety property, not polish.

> Architecturally the most disciplined project in the survey. As an engineered
> artifact, a prototype wearing a product's confidence. The gap between those
> two sentences is the entire to-do list.

### Pentester / bug-bounty hunter — "would I run this on a live target?"

1. **Workflow fit is the real selling point — yes, for triage.** A right-click
   in Burp that fires 36 specialists on the exchange I'm staring at, with a
   suggested Repeater test and an honest "I'm guessing" flag, is genuinely
   useful for triage and for catching the bug I'd skim past at 2am. Nothing else
   in the survey meets me inside Burp.
2. **But it doesn't do what bounties pay for.** Bounties pay for a *demonstrated*
   cross-account IDOR, a chained SSRF→metadata, a working auth bypass — multi-
   request, stateful, proven. Single-exchange analysis is the wrong shape for
   the high-value categories, and "flagged IDOR on a 403-denied request" (which
   the blind eval actually caught — `SESSION_HANDOVER_2.md` §4) is the failure
   that burns signal-to-noise and program reputation. It hands hypotheses;
   XBOW/Shannon hand triagers a PoC.
3. **Local models mean I trust the flags less on hard bugs — verify everything.**
   For SQLi/XSS/misconfig with a deterministic confirmer behind them, fine. For
   business-logic/authz — 8B weakest, confirmer often unavailable — every
   finding is a lead, not a result. The `basis` tag genuinely helps: a
   `recalled`/`assumed` flag tells me not to waste an hour.
4. **The privacy story wins real engagements — underrated.** Many scopes forbid
   shipping request data to a third-party API. A local-only analyzer I can point
   at an NDA'd/regulated target with no data-egress conversation is a category
   the cloud autonomous agents structurally can't enter.

> As a hunter: run it as a smart triage lens over Burp traffic, never as the
> thing that finds and proves the bug. It sharpens judgment; it doesn't replace
> Repeater. Honest and useful — and worth less than a scored autonomous agent
> until it can prove even one bug end-to-end.

---

## 4. What closes the distance (priority order)

Short and concrete — and *not* more architecture:

1. **Score it.** Run the existing blind corpus + answer key (`testing/`) against
   a pinned local model; publish precision/recall per OWASP category; gate CI on
   it. Nothing else matters until this exists.
2. **Add the one end-to-end smoke test** against a stub Ollama, to permanently
   kill "green tests, dead pipeline."
3. **Wire in the multi-request capability that's already written** (iterative
   agent, cross-identity IDOR, missing-auth probe) so the high-value categories
   stop being single-shot.
4. **Impose release discipline** — real git history, untrack DBs/jar, delete the
   duplicate harness, add CI + pinned deps.
5. **Make the coordinator's fail-open path loud and metered,** and let routing
   use a stronger (or cloud) model where privacy allows.

---

*Competitor benchmark figures above are as reported by the source article and
are not independently verified. Everything about this project is grounded in
in-repo docs current as of the branch this file was committed on.*
