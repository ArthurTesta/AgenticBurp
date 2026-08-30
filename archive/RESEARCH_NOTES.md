# Research notes / project history

This file is the round-by-round research log behind the harness's design
decisions (why 36 agents, what got compared against other open-source and
commercial tools, what changed each round and why). It is **not** a setup
guide — see `README.md` for "what is this and how do I run it." Some
detail below (agent counts, specific setup commands) predates later
changes and may not match the current codebase; where the two disagree,
the code and `README.md` are current, this file is historical record.

## Comparison against similar projects on GitHub

Before this round of changes I looked at five comparable open-source
projects (search: "automated ai pentest github") plus one academic paper
that turned out to be directly relevant, and changed the harness based on
concrete gaps they exposed:

| Project | Relevant approach | What I took from it |
|---|---|---|
| [Strix](https://github.com/usestrix/strix) (54k★) | Structured findings with severity/CVSS/OWASP tags; spec-driven testing (point at an OpenAPI/Postman file, test declared endpoints) | Added `severity` + `owasp_category` to every `Finding`, distinct from `confidence` (impact vs. certainty are different axes) |
| [Xalgorix](https://github.com/xalgorix/xalgorix) | A separate verifier agent **re-exploits** every finding before it's reported, converting "a pile of maybes" into confirmed results | Named as the gap my critique pass doesn't close (see below) — mine argues in text, it doesn't touch the target |
| [PentAGI](https://github.com/vxcontrol/pentagi) | Sandboxed real tool execution, persistent run state across a session | Added SQLite persistence (`store.py`) — findings now survive past a single exchange |
| [PentestAgent](https://github.com/GH05TCREW/pentestagent) | "Shadow Graph": builds a knowledge graph from accumulated session notes so later findings are read in light of earlier ones | Added a scaled-down version: before dispatching agents, the orchestrator hands them a compact summary of prior findings on the same host, so a finding on `/admin/users` is read knowing `/admin` was already flagged |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) (USENIX Security 2024) | Staged pipeline with session persistence, pluggable local-model backend including Ollama | Confirms the local-Ollama-backend approach this project already took is a reasonable one, not an outlier |
| AEGIS (arXiv, graph-guided vulnerability reasoning) | A "Meta-Auditing" agent forms its own independent read of the evidence *before* seeing the first verifier's conclusion, specifically to avoid rubber-stamping | Rewrote the critique prompt: the reviewer must now state its own independent read of the raw evidence before comparing it to the specialist's stated finding — closes an anchoring bug in the original critique pass, where showing the reviewer the conclusion up front invited agreement-by-default |

**What I looked at and deliberately did not build:** both Strix and
Xalgorix validate findings by actually executing something against the
target — a sandboxed PoC runtime, or a verifier that re-exploits. My
critique pass is textual review only; it can catch a claim that doesn't
hold up to argument, but it cannot catch a claim that's wrong in a way
only the target itself would reveal. Closing that gap properly means the
extension sending at least one additional request to the target, which
is a meaningfully different capability than anything here so far —  it
turns this from a purely advisory tool into one that takes action against
the target, even if narrowly scoped and human-confirmed per request. I'd
rather name that tradeoff explicitly than blur it by half-implementing
it. If you want this: the shape I'd build is a "Verify" button on a
finding that sends exactly one analyst-approved diagnostic request
through Burp's own HTTP client (`api.http().sendRequest()` in Montoya)
and shows the raw before/after diff — never autonomous, never more than
the one request the analyst explicitly approved.

## Fourth round: broader survey, RAG, and finding-chaining

Widened the search to the specific projects named plus ten more found via
"best open source AI penetration testing frameworks" — a curated list
(insidetrust/awesome-ai-pentest), two 2026 comparison roundups (Strobes,
Contabo), and one academic benchmark (ARTEMIS, Dec 2025, 8,000-host live
network) turned out to matter more than most of the individual tools:

| Source | Relevant approach | What I took from it |
|---|---|---|
| **[0xSteph/pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents)** | 50 domain-specific Claude Code subagents spanning recon, Active Directory, cloud, mobile, wireless, social engineering | Mostly **out of scope for this tool on purpose** — this harness only ever sees HTTP traffic through Burp; AD/cloud/mobile/wireless testing needs different data sources entirely. Named here rather than silently ignored: breadth of agent *roster* isn't the gap, breadth of *what the agents can see* is, and that's a different, larger project. |
| **[PentestGPT](https://github.com/GreyDGL/PentestGPT)** (15k★, USENIX Security 2024) | Maintains a running "task tree" across an engagement — reasoning module tracks the big picture, generation module executes the next step | This tool now has a lighter analog: `store.py`'s per-host finding history plus the new chain detector effectively is a task tree scoped to "what's been found here", though nowhere near PentestGPT's full multi-step autonomous planning |
| **[PentAGI](https://github.com/vxcontrol/pentagi)** | Sandboxed real tool execution across a persistent session | Already incorporated last round (persistence via `store.py`) |
| **[Horizon3.ai / NodeZero](https://www.horizon3.ai/)** | Frames risk as three questions: "are you exploitable, what's the impact, are attackers actively using this" — chains harvested credentials + misconfigs + vulnerabilities into full attack paths, and re-verifies fixes | The third question (active exploitation in the wild) is a genuine gap this build still has — see "considered, not built" below. The chaining idea is now partially addressed (see below). |
| **VulnBot** (academic; several 2026 tools including xOffense fork from it) | Five-module architecture: Planner, **Memory Retriever**, Generator, Executor, Summarizer, plus a Penetration Task Graph (DAG) for dependency-aware parallel execution | Directly named what "RAG" should mean here — a dedicated retrieval module, not a vector-DB dependency bolted on for its own sake. Built `knowledge.py` as this harness's Memory Retriever (see below). |
| **ARTEMIS** (Dec 2025 benchmark, 8,000-host live network) | Best autonomous agent beat 9 of 10 human testers but lost to the top human, 9 findings to 13, specifically on "creative chaining and business logic" | This is the most important single data point from this round: it names exactly the gap already flagged in this README last round ("doesn't track relationships between findings"). Built `chaining.py` directly in response. |
| Deng et al. 2025 ("What Makes a Good LLM Agent for Real-World Pentesting?", arXiv:2602.17622) | Surveyed 28 LLM-pentesting systems, identifying Type A (capability gaps) and Type B (complexity-barrier) failure categories | Used as a framing check rather than a specific feature source — confirms this build's failures so far have mostly been Type B (process/verification gaps: anchoring, no persistence, no known-vuln check) rather than Type A (the underlying models can't do the reasoning at all), which is the more tractable category to keep improving. |

### RAG: `knowledge.py`

A small, hand-written methodology corpus (not copied from any external
source — paraphrasing OWASP/PortSwigger text closely enough to be useful
risks reproducing their structure, so this is original operational notes
per vulnerability class), retrieved by keyword overlap against the
agent's name and the exchange's URL/body, and injected into every
agent's prompt as a "METHODOLOGY NOTES" block. Deliberately **not**
embeddings/vector-search: keyword-overlap retrieval is inspectable (you
can read exactly why a note matched), has zero new runtime dependencies,
and fails safe — a miss just means no extra context, not a confidently
wrong context pulled in by a bad embedding match. Tested directly: an
IDOR-shaped exchange correctly retrieves the differential-testing note,
an AI/LLM-shaped exchange correctly retrieves the direct-vs-indirect
prompt injection note, and each agent always retrieves its own baseline
methodology note regardless of exchange content (agent name is always
part of the query).

### Finding-chaining: `chaining.py`

Rule-based — not another LLM call — matching accumulated findings on a
host against known dangerous combinations (open redirect + SSRF, exposed
admin surface + access-control gap, dependency exposure + confirmed
known-vulnerability, weak auth + sensitive action). Deliberately
rule-based rather than LLM-narrated: per ARTEMIS, chaining is exactly
where these systems currently produce their most confident-sounding,
hardest-to-verify claims, and a rule match over labeled categories is
auditable (you can see exactly which two findings and which rule fired)
where an LLM's free-text "these might chain into X" is not. The open
redirect → SSRF pattern specifically mirrors Intigriti's own published
triage guidance (an open redirect report that a second, separate SSRF
report later escalates through to RCE — documented in their public
triage-standards page).

**Tested end-to-end across three exchanges, not just unit-level:**
analyzed an open-redirect-shaped exchange (no chain yet, correctly),
then an SSRF-shaped exchange on the same host (chain correctly fires,
citing both URLs and the right rule), then a third, unrelated exchange
on the same host (chain correctly does *not* re-announce itself). All
three findings persist to the same SQLite store as everything else.

### Considered, not built

- **Active-exploitation prioritization** (Horizon3's "are attackers
  actively using this" question) — **built this round, see the "Sixth
  round" section below.**
- **Fix-verification loop** — NodeZero and Aikido both re-test after a
  fix is applied to confirm remediation. This tool has no concept of "was
  this fixed" at all; it would need the analyst to re-send the same
  exchange and a diffing step against the prior stored finding.
- **Multi-step autonomous planning** (PentestGPT's task tree, VulnBot's
  full Penetration Task Graph) — this harness still only analyzes one
  exchange at a time on explicit request; it does not decide what to
  test next or send its own traffic. That remains a deliberate scope
  boundary from earlier rounds (see the "Verify" button design that was
  proposed and not built), not an oversight.

## Fifth round: Safe Chain, opt-in rediscovery, and real-world testing

### Aikido Safe Chain (github.com/AikidoSec/safe-chain)

Read the actual repo rather than just the name. Safe Chain is a **malicious-package** detector — a local proxy that intercepts `npm`/`pip`/etc. installs and checks them against Aikido's own malware intelligence feed, plus a default 48-hour minimum-package-age gate. This is a genuinely different threat than what `github_advisories.py` already covers: a legitimate, non-malicious package with a disclosed CVE is not the same problem as a freshly-published, possibly-malicious or typosquatted package. Two honest constraints shaped what got built:

- Safe Chain's actual malware feed (`malware-list.aikido.dev`) isn't publicly documented at the schema level and isn't reachable from this environment — so this harness does not claim to query it, and doesn't fake an integration against something it can't verify.
- What **is** real, public, and directly checkable is the same minimum-package-age *concept* Safe Chain applies, against the actual npm and PyPI registries. Built `package_registry_checks.py` for exactly that — confirmed live against both registries (`left-pad`, `requests`) plus the not-found and unsupported-ecosystem paths, before it was ever wired into the orchestrator. It ships as its own finding stream (confidence capped at 0.3, deliberately weak) rather than merged into the known-vulnerability finding, since "recently published" and "has a disclosed CVE" are different kinds of evidence.

### Opt-in rediscovery

`AnalysisRequest.attempt_rediscovery` (default `False`, surfaced as a checkbox in the Burp tab: "Attempt rediscovery of known vulnerabilities"). When a component matches a known advisory, the harness stops there by default — spending an extra model call to re-derive something already established with more certainty than an LLM could add is waste. If the analyst opts in, one additional call runs per confirmed match, explicitly instructed *not* to re-confirm the advisory exists but to look for exchange-specific corroborating evidence (is the vulnerable path actually reachable here, does the version banner look like it might be misleading, etc.) — and explicitly told that "no additional evidence beyond the known advisory" is a complete, honest answer, not a failure. Tested end-to-end: with the flag off, zero rediscovery calls are made across a full `analyze()` run with a confirmed match present; with it on, exactly one call is made and its finding appears in the response under `rediscovery_attempt`.

### Testing against a real vulnerable-by-design app

Tried OWASP Juice Shop's official demo (`demo.owasp-juice.shop`) first — it returned a 503 both times it was tried during this session (the free-tier demo instance appears to be down, not a bug in anything here). Fell back to the other named target, **Altoro Mutual** (`altoro.testfire.net`), HCL's/IBM's long-running public AppScan demo bank, explicitly published "for the sole purpose of demonstrating the effectiveness of \[security] products" — fetched live, read-only (page loads only, no injection attempts, consistent with what the site's own docs invite).

**This actually found and fixed a real bug**, not a hypothetical one. Every synthetic test exchange used earlier in this build (by me, across all five rounds) was clean, modern, REST-style: `/admin/`, `/checkout`, `/api/user`. Every one of `PathScorer.java`'s URL rules was written assuming a path segment ends in `/` or end-of-string. Altoro Mutual is a legacy JSP-era app: `/login.jsp`, `/feedback.jsp`, `/cgi.exe`. Testing the rules (ported to Python, since Java still can't be compiled here) against the real captured URLs showed `/login.jsp` matched **nothing** — the auth-path rule never fired, because `.jsp` isn't `/` or end-of-string. `/cgi.exe` also matched nothing, because there was no rule at all for legacy executable extensions, which are themselves a real red flag independent of anything else. Both are now fixed (the segment-boundary group broadened from `(/|$)` to `(/|.|$)` across every rule, plus a new rule for `.exe/.cgi/.dll/.pl/.sh`), and re-tested against the same real URLs to confirm the fix actually closes the gap — `/login.jsp` now matches "auth path", `/cgi.exe` now matches "legacy dangerous extension".

The full harness pipeline was also run end-to-end against the real captured HTML (not a summary of it — the actual login form markup, the actual Swagger UI shell) through `orchestrator.analyze()` with a mocked-but-content-aware Ollama backend, confirming real-world HTML/headers flow through routing, dispatch, knowledge retrieval, and finding assembly without errors.

**Why this matters more than another synthetic test would have:** every prior round's tests used exchanges I invented myself, which means they could only catch bugs in logic I already knew to think about. A real, independently-built application is a route that could disagree with my own assumptions in ways I hadn't imagined — and it did, on the very first real target tried.

## Sixth round: CISA KEV cross-reference, and Juice Shop retried

Juice Shop's demo was retried at the start of this round and still returned a 503 — same failure, reproduced a second time on a separate turn, which is now a stable finding rather than a one-off blip. Not chasing it further; testing continues to rest on Altoro Mutual only, noted honestly below rather than silently dropped.

Closed the one item from "Considered, not built" above that already had a fully specified shape written down: Horizon3.ai's third framing question ("are attackers actively using this") from an earlier comparison round. `kev_check.py` cross-references a confirmed known-vulnerability match's CVE ID against CISA's Known Exploited Vulnerabilities catalog and, on a match, escalates the finding's severity to critical and flags it plainly (`[CISA KEV]` prefix, plus a ransomware-campaign note when CISA's own data indicates one) — a disclosed advisory is one thing, confirmed active in-the-wild exploitation is a meaningfully more urgent one.

**Honesty note more specific than usual for this integration.** Unlike `github_advisories.py` and `package_registry_checks.py`, the live-fetch path here has genuinely never succeeded from this build environment, for two independently confirmed reasons: fetching the real feed URL was blocked by cisa.gov's bot detection, and `cisa.gov` isn't in this sandbox's outbound network allowlist either. So this is *not* "tested live, works" the way the other two integrations are — it's "schema is well-documented and stable, client is defensively written and tested against realistic local data, but the actual network call has never executed here." A `local_file` config option exists specifically so an operator whose own network also can't reach cisa.gov directly isn't stuck — the real `cisa_kev` PyPI package (found during research for this feature) uses the same local-file-fallback pattern for the same reason, a reasonable independent confirmation this is a normal thing to need, not a workaround invented to paper over a gap.

**What testing against realistic local data actually caught:** a real bug, the same way testing against Altoro Mutual did last round. The first version of `_ensure_loaded()` used `raw.get("vulnerabilities", [])` — which doesn't raise on a missing key, it just silently returns an empty list. A response that didn't match the expected KEV schema at all would have been treated as "loaded successfully, catalog is just empty," and every subsequent CVE lookup would silently report "not exploited" instead of surfacing that the fetch returned garbage — exactly the dangerous failure mode this project has otherwise been careful to avoid. Caught by a test that deliberately fed the client JSON missing the `vulnerabilities` key and checked the result was `"error"`: it returned `"not_listed"` on the first attempt. Fixed (the key's presence is now checked explicitly before treating the load as successful) and re-tested to confirm the fix actually closes it, alongside re-confirming the happy path still works.

The full escalation path was tested end-to-end through `orchestrator.analyze()`: a mocked GitHub Advisory match on the real Log4Shell CVE ID (`CVE-2021-44228`), resolved against a local KEV file containing that same CVE with `knownRansomwareCampaignUse: Known`, correctly escalates the finding's severity from the advisory's own "high" to "critical", correctly prefixes the summary with `[CISA KEV]`, and correctly includes the ransomware-campaign note in the evidence text.

## Comparison against commercial/production AI security platforms

Beyond the open-source projects above, three commercial/production
platforms are worth comparing against directly, since they operate at a
different scale and answer the "known vs. rediscover" question in ways
that shaped what I built this round:

| Platform | Relevant approach | What I took from it |
|---|---|---|
| **[Aikido Security](https://www.aikido.dev/)** | Checks dependencies against NVD and the GitHub Advisory Database directly, and explicitly markets "detecting blind spots in NVD & GitHub Adv DB" as a distinct capability from AI reasoning; every finding pauses for validation before further action | Confirms deterministic advisory-DB matching should be a first-class, separate step from LLM reasoning — this is exactly what `github_advisories.py` now does |
| **[XBOW](https://xbow.com/)** | Uses "validators" to confirm every finding — explicitly, in their own words, "sometimes this process leverages a large language model; in other cases, we build custom programmatic checks" | Validated the design split already in this build: the critique pass (LLM validator) handles specialist *reasoning*, the new known-vulnerability lookup (programmatic validator) handles *external fact-checking* — these are different failure modes and need different tools, not one LLM doing both |
| **[CAI](https://github.com/aliasrobotics/cai)** (Alias Robotics, arXiv:2504.06017) | Open-source, supports local models including Ollama; maintains its own domain-specific vulnerability database (RVD, for robots) and scoring system (RVSS) rather than having agents reason about known issues from memory | Confirms the local-Ollama architecture isn't an outlier approach, and that pairing an agent framework with a dedicated, authoritative vulnerability database (rather than asking the model to recall CVEs) is the pattern serious tools converge on — same principle as GitHub Advisory DB integration here, just a different database for a different domain |

Aikido specifically also does **reachability analysis** — only flagging a
vulnerable dependency if the vulnerable code path is actually reachable
from the application's own code — which this tool cannot replicate: that
requires static analysis of source code, and this harness only ever sees
HTTP traffic. Worth naming as a structural limitation, not a bug: a
"known-vulnerable-dependency" finding here means *the version was
observed and a disclosed advisory exists for that package*, not that the
vulnerable function is provably invoked. The suggested_test text says as
much.

## Known-vulnerability lookup ("don't rediscover what's already known")

New in this round, directly implementing the idea that a component with
a disclosed, known vulnerability should be matched against an
authoritative source rather than have an LLM try to reason its way to
the same conclusion from memory (which is exactly the hallucination risk
`base_agent.py`'s common rules already warned against for CVE claims).

- **`supply_chain` agent** extracts component candidates (name + version,
  when visible) from version banners, JS library identifiers, and exposed
  dependency manifests/lockfiles — and separately flags GitHub Actions
  / CI supply-chain risk patterns (unpinned third-party actions, the
  "pwn request" `pull_request_target` pattern, secrets exposure) when a
  workflow file's content is actually visible in a response.
- **`github_advisories.py`** takes those candidates and queries GitHub's
  public Security Advisory REST API directly — a deterministic lookup,
  not a model call. A match ships as a `basis: "sourced"` finding with a
  citable GHSA/CVE ID, confidence 0.9, and an explicit instruction that
  the harness does **not** verify precise semver-range containment (that
  logic is easy to get subtly wrong across ecosystems, so it isn't
  attempted — the finding tells the analyst to confirm their exact
  version against the advisory's stated range themselves). No match
  produces no finding — silence, not a "this is safe" claim. A lookup
  failure (rate-limited, network error) produces neither: it's reported
  as its own labeled error, specifically so "couldn't check" is never
  confused with "checked, found nothing."
- These sourced findings **skip the critique pass** — critique exists to
  attack LLM reasoning, and a GitHub API response isn't LLM reasoning.

**This was tested against the real, live API, not just mocked.** While
building this I ran an actual query against `api.github.com/advisories`
and immediately hit GitHub's unauthenticated rate limit (60 requests/hour,
already exhausted by other traffic on this sandbox's shared IP) — which
directly shaped the design: the client distinguishes a rate-limit error
from a genuine "no advisory found" result, and the README/config make
the token requirement explicit rather than leaving it to be discovered
in production. I then verified the response-parsing logic separately
against a realistic mocked advisory payload (a real historical
lodash/GHSA-jf85-cpcp-j695 prototype-pollution advisory shape), confirming
both the match path and the no-match path. Get a token at
https://github.com/settings/tokens (no special scopes needed, this is a
public read endpoint) and set `GITHUB_TOKEN` in your environment, or the
feature will mostly report rate-limit errors rather than results.


## The next architectural step: agents propose, tools prove

The harness should not grow by adding a new LLM prompt for every familiar vulnerability class. That would recreate mature security tooling badly, and it would make every new agent another bespoke source of false positives. The architecture now has a **validator layer** for this reason.

A specialist agent is a hypothesis generator and test planner. A validator is the independent verification mechanism. For SQL injection, for example, the `sqli` agent identifies the likely surface while the optional `sqlmap` validator can consume the **original captured request** and independently test it. The model never supplies a shell command, URL, or arbitrary target to sqlmap. Active validators are disabled by default.

This creates a much stronger division of labor:

```
HTTP evidence
    │
    ├── deterministic extraction / passive checks
    │
    └── LLM specialists ──> hypotheses + suggested validation
                                  │
                                  ▼
                         validator registry
                         ├── sqlmap (SQLi)
                         ├── future nuclei/ZAP adapters
                         ├── differential replay
                         └── session-aware Burp validators
                                  │
                                  ▼
                         independent evidence
                                  │
                                  ▼
                         finding confidence/confirmation
```

The strategic goal is to turn this from an **LLM vulnerability classifier** into an **evidence-driven validation engine**. Mature tools should be adapters, not competitors to the agents.

### What would make this genuinely next-level

**1. Make Burp the active execution plane.** The harness currently sees isolated exchanges. The most valuable missing primitive is a session-aware request graph: request A as user 1, request B as user 2, replay, mutate, compare. Burp already owns cookies, authentication state, HTTP/2 details, extensions, and Repeater. The Python harness should generate structured test plans; the Java extension should execute them and return observations. This is the path to actually confirming IDOR, privilege escalation, race conditions, rate limits, OAuth issues, and business-logic flaws rather than merely describing the next manual step.

**2. Replace the flat finding list with an evidence graph.** Store observations, hypotheses, validations, components, requests, identities, and relationships as separate records. A finding should point to the exact observations that support it. A chain should be a graph relationship, not text assembled from summaries. This also gives the analyst an audit trail: *why* did the system believe this, *which tool* proved it, and *which request* produced the evidence?

**3. Build a reusable probe library.** Reflection detection, parameter extraction, content-type classification, cookie analysis, JSON/XML parsing, error-signature detection, redirect analysis, timing comparison, and authorization-differential comparison are not nine different LLM problems. They are shared primitives. Put them in deterministic Python/Java modules and let every specialist consume the same normalized evidence.

**4. Add a capability-based tool broker.** Agents should request capabilities such as `sql_injection_validation`, `same_request_replay`, `cross_identity_compare`, or `rate_limit_burst`, not commands. The broker maps capabilities to tools, enforces scope and risk level, records the exact invocation, and can require analyst approval for active actions.

**5. Introduce an explicit state machine.** Move from `observed → finding` to something like `observed → hypothesized → triaged → planned → executed → confirmed/rejected → reported`. This solves the audit's biggest correctness problem around findings that merely *look* confirmed.

**6. Treat models as replaceable workers.** Keep coordinator, specialist, and critic prompts behind interfaces; support a cheap routing model, a stronger reasoning model, and a local deterministic path without forcing every task through the largest model. Record model/version/prompt revision with each hypothesis so results remain reproducible.

**7. Benchmark it like a security product.** Build a regression corpus of vulnerable applications and deliberately poisoned responses. Measure precision, recall, confirmation rate, false-positive rate, time-to-confirm, tool-call count, and prompt-injection resistance. A green unit-test suite is necessary but nowhere near sufficient.

**8. Make scope and safety first-class.** Engagement scope, active-test policy, maximum request rate, maximum concurrency, excluded paths, authentication profiles, and analyst approval should be enforced by the execution broker—not merely mentioned in prompts.

**9. Add an analyst feedback loop.** `true_positive`, `false_positive`, `duplicate`, `not_applicable`, and `confirmed_by_analyst` should be persisted. That feedback can later tune routing and ranking without letting the model silently learn from untrusted target content.

**10. Build a provenance-first report.** A client-facing finding should be able to answer four questions: what was observed, what was inferred, what independently verified it, and what remains unverified. This is a much stronger differentiator than adding another ten LLM agents.

### Tooling philosophy

`sqlmap` is exactly the right example of the intended direction. The question is not "can an LLM write a better SQLi prompt?" It is "can the harness identify when SQLi is plausible, feed a mature validator the right captured request safely, interpret the result, and preserve provenance?"

The same principle should govern future integrations. Use mature scanners and analyzers where they are good; write deterministic glue where the existing tool does not solve the exact problem; use an LLM where interpretation, prioritization, or ambiguous workflow reasoning is genuinely valuable.

## Architecture

```
Burp (Proxy/Repeater/Target)
   │  "Attack Surface Map" tab: local heuristic scoring of every
   │  endpoint Burp has seen — no LLM call, ranks by promise
   │  right-click a promising one → "Send to LLM Harness"
   ▼
Burp extension (Java, Montoya API)
   │  HTTP POST /analyze  (localhost only)
   ▼
harness/server.py  (FastAPI)
   │
   ▼
orchestrator.py (coordinator)
   │  1. routing model picks which specialists apply to this exchange,
   │     using a prompt seeded with where reported vulnerabilities have
   │     actually concentrated over 2021-2025 (see "Trend grounding")
   │  2. dispatches those specialists concurrently
   │  3. adversarial critique pass attacks each high-confidence finding
   │     (rival explanation, fragility check) before it ships
   │  4. aggregates + ranks findings
   ├── agents/sqli_agent.py
   ├── agents/xss_agent.py
   ├── agents/idor_agent.py
   ├── agents/ssrf_agent.py
   ├── agents/auth_agent.py
   ├── agents/business_logic_agent.py   (broken access control / workflow)
   ├── agents/misconfig_agent.py        (headers, exposed admin/debug surface)
   ├── agents/ai_llm_agent.py           (prompt injection, insecure output handling)
   └── agents/supply_chain_agent.py     (dependency/CI exposure -- extracts
        │                                candidates, doesn't claim CVEs itself)
        │
        │  each agent's prompt is grounded by knowledge.py (RAG: keyword-
        │  retrieved methodology notes) and store.py (prior findings on
        │  this host), then calls Ollama with its own system prompt
        ▼
   Ollama (localhost:11434) — anything you've pulled, e.g. llama3.1:8b

   after critique:
   → component candidates go to github_advisories.py (known-vuln lookup,
     escalated to critical severity if kev_check.py finds an active-
     exploitation match in CISA's KEV catalog) and package_registry_checks.py
     (Safe-Chain-inspired recency check, real npm/PyPI registries) -- all
     deterministic, not LLM calls
   → if attempt_rediscovery is set (opt-in, off by default): one more
     model call per confirmed known-vuln match, explicitly told not to
     just re-confirm what's already established
   → accumulated host findings go to chaining.py (deterministic rule-
     based chain detection, not an LLM call)
```

Every agent is instructed to label each finding's `basis` as
`derived` (reasoned from this exchange), `recalled` (general knowledge
of the vuln class), or `assumed` (guessing about the app beyond what's
shown) — that label ships to the Burp UI so you can tell a real
observation from a plausible-sounding guess at a glance. Every finding
also carries `severity` (impact if real) separately from `confidence`
(certainty it's real) plus an optional OWASP Top 10 category, and
high-confidence findings additionally carry `review_verdict`/
`review_note` from the critique pass. Findings that survive review are
persisted to `harness/harness_state.db` (SQLite, created automatically)
keyed by host, and a compact summary of prior findings on the same host
is fed to every agent analyzing a new exchange there.

## Trend grounding (why these 10 agents, and why the routing prompt reads the way it does)

Pulled from HackerOne's 2025 Hacker-Powered Security Report (580,000+
validated reports, 9th edition), CWE/CVE frequency data, and Mandiant's
M-Trends 2025:

- **Access control and misconfiguration are rising and now outrank
  classic payload bugs in reported volume for many programs.** IDOR
  variations, missing authorization (CWE-862), and business-logic flaws
  climbed while XSS declined from its 2024 peak. This is why
  `business_logic` and `misconfig` exist as agents distinct from the
  narrower `idor` agent, and why the coordinator's routing prompt
  explicitly warns that these categories have no single payload
  signature to pattern-match — they require reading what the workflow
  is supposed to enforce.
- **AI/LLM-feature vulnerabilities are the fastest-growing category by
  a wide margin**: valid AI-related reports up 200%+ year over year,
  prompt injection specifically up 540%, as 1,100+ customer programs
  added AI features to scope in 2025 alone. The `ai_llm` agent exists
  for exactly this, gated so it only fires when an exchange actually
  looks like it touches a chat/completion/assistant feature.
- **XSS (CWE-79) and SQLi (CWE-89) remain common** — still at or near
  the top of CWE frequency lists through H1 2025 — but are no longer the
  automatic first guess; the routing prompt reflects that they're worth
  checking on relevant exchanges without dispatching them reflexively on
  everything.
- **The critique/reflection pass** applies this system's own epistemic
  framework to the harness's own output: each high-confidence finding
  gets attacked with a rival explanation and a fragility check before
  the analyst sees it, mirroring "verify by re-deriving, not
  recognizing" and "attack your conclusion" rather than letting a
  specialist's first answer ship unchallenged. It's capped to
  high-confidence findings and a max count per exchange — reviewing
  everything indiscriminately would just add latency without changing
  what the analyst does with the low-confidence findings, which are
  already labeled as guesses.

Sources: HackerOne's 2025 Hacker-Powered Security Report and researcher-
signals blog post, Recorded Future's H1 2025 vulnerability trends
(CWE frequency), Mandiant M-Trends 2025. These are directional priors
baked into prompts, not hard rules — the routing model is explicitly told
not to dispatch a trending category onto an exchange that doesn't show
signs of it.

## Attack Surface Map (Burp extension)

A new suite tab that scores every endpoint in Burp's site map locally —
no LLM call, so it scales to hundreds of entries — using pattern rules
in `PathScorer.java`: exposed admin/debug/actuator/git paths, numeric or
UUID object identifiers in the URL (classic IDOR surface), URL-shaped
parameters (SSRF surface), state-changing action verbs like
checkout/redeem/transfer (business logic surface), chat/assistant/
completion paths (AI surface), and state-changing HTTP methods weighted
slightly higher. Results are ranked into CRITICAL/HIGH/MEDIUM/LOW tiers
in a sortable, filterable table — that ranking *is* the map; the
highest-scored rows at the top are "the most promising parts." Selecting
a row and clicking "Send to LLM Harness" runs the full agent pipeline
against that specific request/response.

## Setup

### 1. Ollama
```
# install per https://ollama.com, then:
ollama pull llama3.1:8b
ollama serve
```
Swap the model name in `harness/config.yaml` if you use something else.
Smaller/faster models are fine for the narrow per-agent classification
tasks; give the coordinator the strongest model you can afford to run,
since a bad dispatch decision silently drops findings before any agent
sees the exchange.

### 2. Harness
```
cd harness
pip install -r requirements.txt
python server.py
# -> http://127.0.0.1:8787 , check http://127.0.0.1:8787/health
```

### 3. Burp extension
```
cd burp-extension
gradle shadowJar     # or: ./gradlew shadowJar if you generate a wrapper first
```
In Burp: Extensions → Installed → Add → Java → select
`build/libs/burp-extension-all.jar`. A new **LLM Harness** tab appears;
set the harness URL there (defaults to `http://localhost:8787`) and hit
Test Connection. Then right-click any request in Proxy history, Repeater,
or the Target site map → **Send to LLM Harness**.

## What's been verified vs not (read this before trusting it)

- **Harness (Python):** every module compiles and imports cleanly,
  including this round's `package_registry_checks.py`. That module was
  tested live against the real npm and PyPI registries (not mocked) —
  `left-pad@1.3.0` correctly resolved to ~3,063 days old, `requests`
  (latest) to ~105 days old, a nonexistent package correctly returned
  `not_found`, and an unsupported ecosystem correctly returned
  `unsupported_ecosystem` — before being wired into the orchestrator.
  The opt-in rediscovery path was tested end-to-end: `attempt_rediscovery
  =False` produces zero extra model calls even with a confirmed
  known-vuln match present; `=True` produces exactly one, and its
  finding shows up correctly under `rediscovery_attempt` in the
  response. Separately, the full pipeline was run against real captured
  HTML from a live external target (see "Testing against a real
  vulnerable-by-design app" above) rather than only synthetic fixtures —
  and that test caught a real, previously-unnoticed bug in the Java
  `PathScorer` rules (see below), which is exactly the kind of thing
  self-authored synthetic tests structurally can't catch. This round's
  `kev_check.py` compiles and was tested thoroughly against realistic
  local data (match, no-match, missing file, malformed JSON, and the
  schema-mismatch case that caught a real bug — see "Sixth round" above)
  and end-to-end through the full escalation path with a real CVE ID
  (Log4Shell), but its live network path against the actual CISA feed
  has never executed successfully in this environment — flagged
  explicitly, not glossed over, since that's a materially different
  confidence level than the other two external integrations this round.
  including this round's `knowledge.py` and `chaining.py`. Both were
  exercised for real, not just imported: `knowledge.retrieve()` was
  checked against three different exchange shapes (IDOR-shaped, AI/LLM-
  shaped, and an irrelevant static-asset request) and confirmed to
  return the right methodology note in each case. `chaining.py` was
  tested across a genuine three-exchange sequence through the full
  `orchestrator.analyze()` path with a mocked Ollama backend: exchange 1
  (open redirect finding) correctly produces no chain, exchange 2 (SSRF
  finding, same host) correctly triggers the chain detector with the
  right rule and both URLs cited, and exchange 3 (unrelated, same host)
  correctly does *not* re-announce the already-detected chain. That's
  the dedup logic (`store.is_chain_already_detected`/`mark_chain_detected`)
  actually working across calls, not just present in the code.
  including `store.py` and the new `github_advisories.py`. I ran a real
  two-exchange scenario against a mocked Ollama backend that exercises
  persistence specifically (see below), and a separate end-to-end
  scenario that exercises the full new known-vulnerability path: a
  mocked specialist emits a component candidate (`lodash` 4.17.11), the
  orchestrator resolves it through a mocked-but-realistic GitHub Advisory
  response, and the final `AnalysisResponse` correctly contains *both*
  the specialist's own finding (exposed lockfile, `basis: derived`) and
  the sourced known-vulnerability finding (`basis: sourced`, severity
  critical, citing the real GHSA/CVE IDs) — with the summary line
  correctly reporting "1 matched a known GitHub advisory." The
  `github_advisories.py` HTTP layer itself was tested twice: once for
  real, against the live GitHub API (which correctly returned a labeled
  rate-limit error, not a false "no advisory" result — see the
  known-vulnerability section above), and once with a mocked 200
  response shaped like a real advisory to confirm the parsing logic
  handles both the match and no-match cases. I also caught and fixed a
  real bug during this process worth naming: an earlier edit to
  `models.py` accidentally merged `Finding`'s fields into
  `ComponentCandidate` (a missing class declaration line), which
  `py_compile` did not catch because it was syntactically valid — only
  actually importing and instantiating both classes surfaced it. That's
  the exact justification for why this README distinguishes "compiles"
  from "was actually run."
  Persistence: analyzed `GET /admin` (finding: exposed admin panel,
  severity=medium), then `GET /admin/users?id=5` on the same host, and
  confirmed the second exchange's agent prompt contained a `PRIOR
  FINDINGS ON THIS HOST` block referencing the first finding, and that
  the SQLite store returned both records afterward.
  Still unexercised: the actual specialist/coordinator/critique prompts
  against a real Ollama model, since this sandbox has no route to one.
- **Burp extension (Java):** still **not compiled** — no Maven access in
  this sandbox. `PathScorer.java`'s regex logic specifically was
  re-verified this round via a Python port tested against real captured
  URLs from Altoro Mutual, both before the fix (confirming the bug: zero
  matches on `/login.jsp` and `/cgi.exe`) and after (confirming the fix:
  correct matches on both). That's a real, reproducible test of the
  logic even without a Java compiler — the actual `.java` file's regex
  strings were changed and the equivalent Python patterns re-derived
  from the changed file, not assumed to match. `AnalysisModels.java` and
  `HarnessPanel.java`/`HarnessContextMenu.java`/`LlmHarnessExtension.java`
  changed for the rediscovery checkbox this round; brace/paren balance
  re-checked across every file.

## Known gaps / natural next steps

- No caching/dedup — resending the same exchange re-runs every agent.
- No batch mode for Proxy traffic (deliberately: auto-analyzing every
  request would be noisy and slow; current design is opt-in per request).
- No persistence — findings live only in the Burp tab for the session.
  Easy to add: a "Save report" button in `HarnessPanel` that dumps the
  list model to JSON/Markdown.
- Coordinator routing failures fail open to "run every agent" rather than
  failing silently — cheap but not free; worth tightening once you've
  seen how often it actually happens against real traffic.
- Header collapsing on duplicate header names (e.g. multiple `Set-Cookie`)
  in `HarnessContextMenu.headersToMap` — fine for triage, would matter if
  you extend the auth agent to reason about multiple cookies precisely.
- `PathScorer`'s weights are hand-set, not calibrated against real
  traffic or real bounty data — treat the tiering as a reasonable prior
  for triage order, not a validated risk score. Worth logging analyst
  overrides (which LOW-scored endpoints actually got sent to the
  harness and found something) to recalibrate weights over time.
- The critique pass reviews at most 12 findings per exchange
  (`critique.max_findings`), highest-confidence first — on an exchange
  that legitimately has more than 12 findings above the threshold, the
  tail ships unreviewed. Raise the cap if your model/hardware can absorb
  the extra call latency.
- `AttackSurfacePanel`'s "send to harness" only sends the single selected
  row; multi-select + batch send is a natural follow-up once the single-
  row path is confirmed working against a real Burp instance.
- No real verification via execution — see the comparison table above.
  The critique pass is textual review, not re-exploitation; it can catch
  arguments that don't hold up, not claims that are simply wrong about
  the live target.
- No OpenAPI/Postman spec import for the Attack Surface Map, unlike
  Strix's "test declared endpoints, not just crawled ones" — the map
  only ever shows what Burp has actually observed. The `misconfig` agent
  already detects exposed `/swagger`, `/openapi`, `/api-docs` endpoints,
  so a natural next step is closing that loop: parse a discovered spec's
  response body and seed the map with declared-but-unobserved paths.
- The shadow-graph-lite context is per-host and confidence/severity/
  summary only — it doesn't track relationships between findings (e.g.
  "this SSRF plus that internal hostname reference might chain"), which
  is what a real graph structure (like PentestAgent's) would add.
- `github_advisories.py` matches on package name only, not precise
  version-range containment — deliberately, see above. It also doesn't
  attempt to guess a package's ecosystem when the `supply_chain` agent's
  extraction is ambiguous (e.g. a bare name with no clear language
  context); GitHub's API will simply return nothing for a wrong
  ecosystem guess, which is safe (no false match) but means real misses
  are possible. It has no local caching, so re-analyzing the same
  exchange re-queries the API every time — worth adding before pointing
  it at a target with a large, repeatedly-observed dependency surface.
- No reachability analysis (see the Aikido comparison above) — a
  known-vulnerable-dependency finding means the version was observed and
  a disclosed advisory exists, not that the vulnerable code path is
  provably reachable from this application's actual usage.
- `chaining.py`'s rules are hand-written and few (4) — real value would
  come from growing this list against actual findings this tool
  produces over time, the same way the misconfig/business_logic agent
  prompts were informed by real trend data rather than guessed at.
- `knowledge.py`'s corpus is similarly small and hand-written; it has no
  mechanism to grow from what agents actually encounter. A natural next
  step, once there's real usage: log which corpus entries get retrieved
  and how often, to see which are dead weight and where coverage gaps
  actually are, rather than guessing at both from first principles.
- CISA KEV cross-reference is built (see "Sixth round") but its live
  network path is unverified in this environment — no fix-verification
  loop, no multi-step autonomous planning remain unbuilt; see
  "Considered, not built" above for the reasoning on those two.
- `package_registry_checks.py` only covers npm and PyPI (matching what
  Safe Chain itself supports as of this round) — no Maven, RubyGems, Go,
  NuGet, Composer, or Cargo equivalents, even though `github_advisories.py`
  covers all of those for the known-vulnerability side.
- The `PathScorer` regex fix this round was validated via a Python port
  against real URLs, not an actual Java compile — the underlying logic
  is now much more likely correct, but "the Python port matches" and
  "the Java compiles and behaves identically" are still two different
  claims. A real Gradle build remains the one part of this whole system
  that has never touched a compiler.
- Juice Shop's own demo instance was unreachable across three attempts
  now, spanning two separate rounds (503 both times in round five, 503
  again when retried at the start of round six) — the testing above
  covers Altoro Mutual only. This is now a stable finding, not a
  transient blip, so it's not being retried again without a reason to
  expect a different result; a local Docker instance would be the
  reliable way to actually get Juice Shop coverage. Worth doing
  eventually since it's a modern Angular/REST SPA rather than legacy
  JSP, and might expose a different class of gap than the one found
  against Altoro Mutual.

## If you're resuming this after running out of context

Everything above is already on disk under `burp-llm-harness/`. The next
concrete step is: install a JDK + Gradle locally, run `gradle shadowJar`
in `burp-extension/`, and fix whatever Montoya API method-name mismatches
the compiler reports — that's the one part of this system that hasn't
touched a real compiler yet.


## Validation execution plane (next-level architecture)

The harness is now organized around a strict hypothesis/evidence boundary:
LLMs propose findings and declarative `TestPlan` capabilities; Burp or a
mature local security tool generates independent evidence; only explicit
validation results can set `Finding.confirmed=true`.

Plans are bound to a SHA-256 fingerprint of the exact captured request.
The Burp extension retains that original request and requires explicit analyst
approval before executing a plan. The first Burp executor intentionally
supports only a safe baseline replay primitive; unsupported active mutation
capabilities are reported as inconclusive rather than being approximated.

See `EXECUTION_PLANE.md` and `ARCHITECTURE_NEXT_LEVEL.md`.
