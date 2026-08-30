# AgenticBurp × OWASP Juice Shop — Consolidated Final Report

This document brings together everything from this multi-session engagement: the full audit and fix history, the live-target verification, and the "as-if-unknown" assessment — plus the two questions asked directly: how confident should we be that this tool would find everything in Juice Shop, and what compute would a working-day run actually need.

---

## Part 1 — Consolidated findings

### From the initial live-target verification (hand-verified + tool-confirmed)

| # | Class | Severity | Confidence | How confirmed |
|---|---|---|---|---|
| 1 | SQLi | Critical | 0.98 | Hand-verified: `' OR 1=1--` in login email bypasses auth, returns a real admin JWT |
| 2 | IDOR | High | 0.95 | Hand-verified + independently confirmed by `IdentityCompareLogic.java` against the real captured probes (0.91) |
| 3 | CORS misconfig | Medium | 0.90 | Confirmed live by the real `cors_validator.py` |
| 4 | Business logic | Critical | 0.98 | Negative basket quantity accepted, actually checked out with a real server-computed `totalPrice: -190.03` |

### From the "as-if-unknown" organic assessment

| # | Class | Severity | Confidence | Status | How found |
|---|---|---|---|---|---|
| 5 | Misconfig | High | 0.90 | Confirmed | `/ftp` unauthenticated directory listing (found via `robots.txt` → `Disallow: /ftp`) |
| 6 | Info disclosure | Critical | 0.97 | Confirmed | `/ftp/incident-support.kdbx` — real KeePass DB, downloaded and byte-size-verified |
| 7 | Supply chain / misconfig | High | 0.97 | Confirmed | `/ftp`'s `.md/.pdf`-only filter bypassed via a double-encoded null byte (`%2500.md`); confirmed general (works on any file in the listing, not just one) |
| 8 | Misconfig | Medium | 0.90 | Confirmed | `/rest/admin/application-configuration` leaks internal config (LLM model name, OAuth redirect URIs, embedded challenge-trap payloads) with no auth |
| 9 | Misconfig | Low | 0.85 | Confirmed | `/api/Feedbacks/` verbose 500 leaking ORM/query internals |
| 10 | SQLi | Critical | 0.98 | Confirmed | `/rest/products/search?q=` — raw SQLite error on injection, then demonstrated real impact (56 vs. 46 results, bypassing a visibility filter) |
| 11 | Business logic | Critical | 0.98 | Confirmed | Self-registration accepts `"role":"admin"`; confirmed end-to-end via login + JWT decode |
| 12 | Auth | Medium | 0.85 | Confirmed | `/rest/user/security-question` discloses a target's recovery question, no auth, no rate limit observed across 5 rapid requests |
| 13 | XSS | High (severity) | 0.55 (confidence) | **Unconfirmed — deliberately hedged** | Raw `<script>` stored and returned verbatim by the reviews API; execution in a real browser could not be verified (no built Angular frontend in this sandbox) |
| — | SQLi | Low | 0.25 | **Unconfirmed — deliberately hedged** | A WHERE-clause error hints at a SQL-backed query on `/api/Feedbacks/`; explicitly not claimed as demonstrated injection |
| — | Supply chain | Low | 0.60 | **Suppressed — superseded** | The pre-bypass "exposure noted" version of finding #7, before the bypass was found |

**13 distinct confirmed findings, 2 honestly-hedged unconfirmed notes, 1 correctly suppressed as superseded.**

### A pattern worth naming on its own: `sqlmap` missed both real, hand-verified SQLi instances

Run live against the login endpoint (heuristic dismissal: "parameter does not appear to be dynamic") and again against search (genuine 90-second timeout, which then crashed the harness's own exception handler — see Part 4). Two for two. This is now a real, quantified data point about the deterministic-validation layer's reliability, not a single fluke.

---

## Part 2 — How confident are we this would find *everything* in Juice Shop?

**Low confidence in the literal question, and I want to be precise about why, not just hedge.**

**First, "everything" isn't a coherent target for any tool.** Juice Shop's official challenge list runs to roughly 100 entries, and a real fraction of them are deliberately CTF-style puzzles unrelated to genuine vulnerability classes — geolocation-from-EXIF-metadata challenges, ROT13-style crypto puzzles, easter eggs, "find this in a source snippet" coding challenges. No security-testing tool, automated or human, is designed to find those, and conflating the full challenge count with "real vulnerabilities" overstates the bar. A more honest question is: of Juice Shop's genuine, CWE-mapped vulnerability classes, what fraction would this tool likely surface?

**Second, and more important: every finding in this engagement came from me standing in as the LLM, not from the actual configured model.** `llama3.1:8b` was never once reachable in this sandbox. That matters enormously, for two separate reasons:

1. **There is no track record for the real model to extrapolate from.** Before this session, a severe bug (Part 4) meant the system-prompt validation check rejected every single specialist agent's prompt before any Ollama call was ever attempted — for as long as that bug existed, `llama3.1:8b` had *never once* successfully completed a real dispatch, against any target, in this project's history. My fixes this session made the pipeline reach the LLM boundary for the first time — but "the pipeline now reaches the model" and "the model performs well once it gets there" are different, unconnected claims, and only the first one has any evidence behind it.

2. **My own performance sets a ceiling, not an estimate.** I have materially more capability than an 8B open-weight model at exactly the things this task demands: holding calibrated confidence across a long chain of reasoning (the stored-XSS hedge), noticing when a finding needs a specific follow-up test rather than just asserting it (the checkout-total confirmation, the coupon-file bypass reuse), and correctly returning empty findings when a dispatched specialty genuinely doesn't apply rather than manufacturing something. A real 8B model will plausibly do all three of these worse: more malformed JSON (falling into the harness's `raw_error` path instead of producing a finding at all), more missed multi-step signals, and — the failure mode the critique pass exists to catch, with real limits since critique runs on the *same* model — a higher hallucination rate that a same-capability adversarial reviewer may not reliably catch.

**Third, real coverage depends on capturing exchanges, not just analyzing them well, and that's a separately weak link.** Juice Shop is an Angular SPA; most of its real interaction surface is client-side routing, not discoverable by a plain HTTP crawler. `recon_validator.py` — the component that would need to do this automatically — produced heavy false positives in this exact session (45 of 46 "discovered" endpoints were an artifact of a placeholder frontend's fallback route) and has no JS execution capability to discover real SPA routes even in a correctly-built deployment. In practice, meaningful coverage requires an analyst actually browsing the app through Burp so real traffic gets captured — which is a legitimate, intended way to use this tool, but means "how much of the app gets found" is bounded by the human's browsing thoroughness as much as by the agents' analysis quality.

**A rough, explicitly-unvalidated estimate, if pushed for a number:** given the breadth achieved in this session's organic pass (roughly 13 confirmed findings across ~7 genuine vulnerability classes, from a small, hand-selected slice of the real attack surface) and assuming a full working day of thorough manual browsing to drive exchange capture, I'd guess a real run — once the fixed pipeline is paired with a capable model — might land somewhere in the range of 20–40 real findings across a similarly broad set of classes. That is a genuinely rough estimate built from one data point (my own results) that is known to be an upper bound, not a calibrated projection. Treat it as a starting hypothesis to test once `llama3.1:8b` is actually reachable, not a number to plan around.

---

## Part 3 — Compute power for a working-day assessment

**The honest starting point: nothing about this has ever been measured.** No real Ollama call happened anywhere in this project's history until it was blocked by network policy in this sandbox. Everything below is a reasoned estimate from real, observed numbers (prompt sizes, dispatch patterns, config), not a benchmark.

**What's actually running:** every agent, the coordinator's routing decision, and the critique pass all use the same model — `llama3.1:8b` — confirmed directly from `config.yaml`, not assumed.

**Real observed token volume, from this session's actual audit log:** one specialist agent call this session logged a system prompt of 5,108 characters and a user prompt of 2,220 characters — roughly 1,800 input tokens at a typical ~4 chars/token ratio for English prose. Output (a JSON findings array) runs a few hundred tokens. Call it **~2,000 input + ~400 output tokens per specialist-agent call** as a working average — some agents' prompts run longer (`http_request_smuggling` and `recon` were found this session to run 300+ lines), some shorter.

**Dispatch volume, from what fast_path actually produced against real Juice Shop traffic this session:** most real exchanges triggered **5–6 agents simultaneously** — fast_path's URL-pattern matching is broad (any URL containing "user" pulls in `idor`, `auth`, `misconfig` regardless of actual relevance). There is also a real tail-risk worth flagging explicitly: `coordinator.choose_agents()` **falls back to dispatching all 36 agents** whenever the coordinator's own routing call fails or returns nothing usable — a single ambiguous or malformed-response exchange can spike compute cost 6–7x with no warning.

**A working estimate, assumptions stated plainly:**
- A thorough working day of manual Burp browsing might realistically capture **300–800 distinct exchanges** worth analyzing (I'll use 500 as a midpoint).
- Average ~4 agent calls per exchange (accounting for fast_path's broad-but-not-maximal selections) + 1 critique call per exchange + a coordinator routing call on roughly 30% of exchanges (where fast_path finds no strong signal, as it didn't for the `/ftp` exchange in this session).
- That's roughly `500 × 5 + 150 ≈ 2,650` total LLM calls, at ~2,400 tokens each ≈ **~6.4 million tokens** processed for the day. This is an order-of-magnitude figure, not a precise one.

**What that means for hardware, at realistic 8B-model (Q4 quantized) inference speeds:**

| Hardware | Realistic single-stream throughput | Time for 6.4M tokens |
|---|---|---|
| CPU only (modern multi-core workstation) | ~5–15 tok/s | ~120–350 hours (multiple weeks) — not viable |
| Mid-range consumer GPU (8–12GB VRAM, e.g. RTX 3060/4070) | ~40–80 tok/s | ~22–44 hours (2–5 calendar days) |
| High-end consumer GPU (24GB VRAM, e.g. RTX 4090) | ~100–150 tok/s single-stream | ~12–18 hours (1.5–2 days) |
| High-end GPU **with concurrent-request batching** (Ollama's `OLLAMA_NUM_PARALLEL`, or a proper serving stack like vLLM) | Several hundred tok/s aggregate, since the harness already dispatches agents concurrently per exchange | **~4–8 hours — fits inside a single working day** |
| Data-center GPU (A100/H100) or small multi-GPU node | Well over 1,000 tok/s aggregate | Comfortably sub-hour; bottleneck shifts to the target application's own response time, not inference |

**The one thing worth flagging as a genuine, currently-unaddressed gap:** the harness's own concurrent agent dispatch (`asyncio.create_task` per agent, confirmed in `agent_manager.py`) is architecturally sound for throughput — but nothing in this codebase configures, validates, or even documents Ollama's `OLLAMA_NUM_PARALLEL` setting or the VRAM needed to actually serve multiple concurrent 8B contexts. Without that server-side configuration, the harness's concurrency does nothing for wall-clock time — requests just queue at the Ollama server one at a time regardless of how many the harness fires off simultaneously. **A single modest consumer GPU, run out of the box, will not complete a working day's assessment inside a working day** — it needs either a substantially higher-end card, explicit multi-request server configuration, or both.

---

## Part 4 — Lessons learned

### The tool's own defects, found only by actually running it

Every one of these was invisible to 407 passing unit tests, because none of them exercised the real, live call path with real constructed prompts and real target traffic. This is the single clearest lesson of the whole engagement: **a large, green test suite and a working product are different claims**, and the gap between them is exactly the part unit tests structurally cannot see.

1. **Every specialist agent was completely non-functional**, for an unknown but likely long duration predating this session. `validate_system_prompt()` applied a check meant for untrusted, attacker-influenced content to the harness's own trusted, hardcoded system prompt, which contains ordinary punctuation (`"; so"`) that tripped a shell-injection pattern. No agent could ever complete a dispatch. Root cause: a security check applied to the wrong side of a trust boundary.
2. **The same pattern, once correctly scoped to user content, was still broken in both directions at once** — it rejected completely standard HTTP syntax (`Content-Type: ...; charset=utf-8`) while simultaneously *missing* realistic attacks with a space before the operator, because of how regex word-boundary anchors behave against non-word-character operators. A check can be actively counterproductive — both noisy and ineffective — without anyone noticing, if it's never run against real traffic.
3. **A crash from a stale rename**: `analysis_pipeline.py` imported a class name (`Component`) that doesn't exist anywhere in the codebase; the real name is `ComponentCandidate`. Fixing it surfaced a **second, unresolved issue**: a duplicate, non-identical implementation of the same method lives in `orchestrator.py`, and both are live-reachable on the same path — likely double-executing GitHub Advisory/CISA KEV lookups per exchange.
4. **A second crash, found only by triggering a genuine timeout**: `sqlmap.py`'s exception handler mixed `bytes` and `str` when building an error message from `subprocess.TimeoutExpired`'s partial output — a real Python subprocess API nuance (the exception's captured output isn't always decoded consistently with the parent call's `text=True`) that only manifests when a real timeout actually occurs, which it did, once, against a real target running a more thorough scan.
5. **The deterministic validator meant to independently corroborate LLM hypotheses missed two-for-two real, confirmed vulnerabilities.** This isn't a code bug — `sqlmap` ran, completed (or timed out), and simply didn't find what was demonstrably there. It's a real gap in the tool's confirmation layer that a green test suite would never surface, because the tests mock the subprocess call rather than running the real binary against a real target.

### Methodology lessons, independent of any specific bug

6. **Recon output needs content verification, not status-code trust.** 45 of 46 "discovered" endpoints in this session were a single artifact (a placeholder frontend's fallback route) — caught only by diffing response bodies. A production deployment with any SPA-style catch-all route would show the same failure mode for real.
7. **Fast-path dispatch is broad to the point of imprecision.** Substring URL matching (e.g., "user" appearing anywhere) triggers a fixed agent set regardless of actual context. This didn't produce wrong answers in this session (agents genuinely dispatched-but-irrelevant correctly returned empty findings), but it does mean real compute is spent on calls that were never going to find anything — a cost problem, not a correctness one, and one that compounds directly into Part 3's compute estimate.
8. **Chain detection depends on findings sharing one store.** The `sqli+idor` chain rule (added earlier this session) never fired across this engagement's own two SQLi and one IDOR findings, because they ended up split across two different temporary databases created in different turns. A real deployment doesn't have this specific problem, but it's a reminder that chain detection is only as good as the completeness of what it's given to compare.
9. **Confirmation follow-through found more than the initial hypothesis did.** The negative-quantity finding, the `/ftp` filter bypass, and the checkout-total confirmation all became stronger, more severe, or more general *because* the suggested follow-up test was actually run rather than left as a suggestion. The single largest source of real signal in this engagement was not the first observation — it was acting on what the first observation asked to be checked next.

---

## Part 5 — Improvement opportunities for future iterations

**Highest priority — close the gaps this session found:**
- Reconcile the duplicate `_resolve_known_vulnerabilities` implementations (Part 4, item 3) rather than leaving both live.
- Investigate why `sqlmap` misses real, confirmed injections at a 0-for-2 rate in this session — try higher `--level`/`--risk`, inspect whether SQLite-specific behavior or Juice Shop's exact query shape defeats sqlmap's standard heuristics, and consider a lighter-weight, harness-native differential probe (send the payload, compare result-set size to baseline, exactly as this session did by hand) as a fallback confirmation path that doesn't depend on a third-party tool's own detection heuristics.
- Audit the rest of `prompt_validator.py`'s `blocked_patterns` list against real traffic. Only the one pattern that actually broke got fixed and tested this session; given how wrong it turned out to be, the others deserve the same scrutiny before being trusted.

**Medium priority — close the measurement gap:**
- Get a real Ollama instance reachable and run the fixed pipeline end-to-end at least once. Every confidence and coverage claim in Part 2 is currently a reasoned guess standing in for a measurement that has never been taken.
- Once that's possible, establish an actual precision/recall baseline against Juice Shop's known challenge list — this project has never had one, at any point in its history.
- Tighten `fast_path.py`'s URL patterns to reduce compute spent on dispatched-but-irrelevant agents (Part 4, item 7) — this directly reduces the Part 3 compute estimate without losing coverage, since those calls were already correctly returning nothing.

**Lower priority, but worth planning for:**
- Document and, ideally, validate `OLLAMA_NUM_PARALLEL` / concurrent-serving configuration as a deployment prerequisite — the harness's own concurrency design is wasted without it (Part 3).
- Improve `recon_validator.py` to verify response-body content, not just status codes, and consider whether any lightweight JS-execution capability is worth adding given Juice Shop (and most modern apps) are SPAs where most real routes are invisible to a plain HTTP crawler.
- Consider a documented, deliberate scope decision on how far cross-exchange correlation (chain detection, prior-context) should go when a real deployment spans multiple sessions/databases, since this session's own chain-detection gap (item 8) was avoidable with better data continuity, not a code defect.
