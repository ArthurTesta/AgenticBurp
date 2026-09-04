> **HISTORICAL (session 1).** For the current project state read
> **SESSION_HANDOVER_3.md** first — it is the authoritative handover. This file
> is kept for the session-1 decision/research history only.

# Session handover — FP reduction, detection benchmarking, coordinator architecture

Same discipline as HANDOVER.md §0: every claim is either (a) verified this
session by the exact command shown, or (b) explicitly marked
reported/unverified. Don't blur the two.

## 0. Read this first — coordination + environment

- **A parallel coding-agent session is editing this same repo.** Division of
  labour this session: *I* (the session being handed over) edited
  `harness/anomaly_detector.py` + `harness/test_anomaly_detector.py` only. The
  *coding agent* did the `ollama_client.py` JSON fix, the Burp-extension Java
  edits (UX + gating), and a `known_vuln_lookup` **dedup** fix. Different files,
  no known conflict — but **do not run two LLM benchmarks at once**: single
  consumer GPU, `concurrency.max_parallel_agents: 1`; two processes hitting
  Ollama simultaneously contend and start timing out, corrupting both runs.
- **Ollama is directly reachable** here (`curl -s -m3 http://localhost:11434/api/tags`
  → `qwen3:8b`, `gemma2:9B`, `llama3.1:8b`, `gemma4:latest`, plus cloud models
  `gemma4:31b-cloud`, `gpt-oss:120b-cloud`). Every agent is configured to
  `qwen3:8b`. LLM calls here are REAL, not substituted.
- **Verify the suite is green before trusting anything:**
  ```bash
  cd harness && python -m unittest discover -p "test_*.py"   # expect: Ran 598 tests, OK
  ```

## 1. What I changed this session — `anomaly_detector.py` (VERIFIED)

Goal: cut the anomaly agent's false positives on benign traffic, recall-safely.
All four changes verified **deterministically** (the anomaly agent is pure
Python — no LLM run needed):

1. **Responses scan only evidence patterns, not attack-input syntax.**
   `_check_patterns` now selects `self.suspicious_patterns` for request fields
   (url/request_body/request_header_*) and a new narrower
   `self.response_evidence_patterns` for responses. Killed the universal FP
   where `\b(...|python|...)\b` matched `Server: Werkzeug Python` on every
   response. The JWT pattern was removed entirely (only ever FP'd on the
   `Authorization` header).
2. **`sensitive_parameter` scoped to URL query + body** (new
   `_query_and_body_param_names`). The normal `Authorization` header is no
   longer flagged as a high-severity finding.
3. **`information_disclosure_header` → `severity="info"`, `confidence=0.3`**
   (version banners are minor + fire on every response → below the reporting
   gate).
4. **Cluster severity capped at its strongest member** (`generate_findings`).
   Six `low` missing-header notes no longer escalate to a `high`
   `security_misconfiguration` cluster; a real multi-signal attack still does.

**Verification (deterministic, instant):**
```bash
cd harness && python -m unittest test_anomaly_detector   # 12 tests (was 9), OK
```
- TN "scary" findings (conf≥0.5 & sev≥medium) from the anomaly agent: **6/6 → 0**
  across TN1-6 (TN4 keeps ONE — a real `<script>` stored-XSS payload visible in
  that response, not noise).
- **Recall preserved:** every TP's real anomaly contribution survives — TP10
  (`../` in url — the one TP that depends on the anomaly agent), TP9 (`file://`),
  TP5/TP6 (XSS). The TP anomaly findings that disappeared were ALL noise
  (`Server` header, JWT-in-`Authorization`), never real detections.

## 2. THE key insight — the FP metric is miscounting (IMPORTANT, don't chase 6/6 blindly)

`fp_benchmark.py`'s headline "TN false-positive exchanges @conf≥0.7 = 6/6" is a
**crude metric that counts real findings as FPs.** I read the actual ≥0.7
drivers (from a PRE-my-changes `C:\tmp\fp_benchmark_results.json` — numbers are
stale, categories are still informative):

- **TN1** = 10× `known_vuln_lookup` **real Werkzeug CVEs** → a legitimate
  supply-chain finding, NOT an FP. The metric can never hit 0 without
  suppressing this.
- **TN2** = derivative Werkzeug misconfig note → real-ish.
- **TN4** = `xss` + one anomaly `<script>` → the real stored-XSS payload is
  genuinely present → real/gray, not pure noise.
- **TN3** = `api_security`/`misconfig` "Excessive Data Exposure" on a user's
  OWN self-profile → **GENUINE FP (LLM)**.
- **TN5** = `auth`/`business_logic` "missing CSRF protection" on a request the
  server **403'd for missing CSRF** (i.e. protection WORKING) → **GENUINE FP (LLM)**.
- **TN6** = `misconfig` "/health may be an exposed debug/actuator endpoint"
  (pure speculation) → **GENUINE FP (LLM)**.

Two takeaways: (a) the **genuine remaining FPs are all LLM-prompt issues**
(TN3/5/6), NOT anomaly-detector issues — my anomaly work cleaned a *different*
noise layer; (b) **the metric itself needs fixing** to count only findings that
misrepresent the exchange's behavior (misread a working control, speculate
without evidence), not real component CVEs.

## 3. Tools built this session (all in `testing/test-target/`)

- **`detection_fixture.py` + `bench.py`** — the SWIFT detection benchmark.
  Caches deterministic agent outputs keyed by `(exchange, agent, model,
  prompt_version)`, so editing one agent's prompt auto-invalidates only it, and
  anomaly/routing/gating changes cost **zero LLM calls (~seconds)**. `bench.py`
  prints recall + FP + a **flip-diff** vs the previous run. Needs a one-time
  `python detection_fixture.py build` (~2h) to warm the cache. Full how-to
  (written for weaker models): **`DETECTION_BENCH_METHODOLOGY.md`**.
- **`fp_benchmark.py`** — post-critique FP measurement through the REAL
  `orch.analyze` (active-validation/discovery force-disabled; temp DBs; no
  target traffic). ~20 min.
- **`ab_routing_recall.py`** — the noise-free routing A/B (union-once,
  set-select). ~1.5h. This is the authoritative RECALL gate.
- Task specs (for the coding agent, precise find/replace): `FP_REDUCTION_TASK.md`,
  `AGENT_PICKER_SWINGWORKER_TASK.md`, `burp-extension/UX_FIXES_TASK.md` (root/burp-extension).

## 4. Measured facts about the architecture (VERIFIED this session)

- Agents are **deterministic** at temp 0.1: `sqli` on a fixed SQLi exchange →
  6/6 fired, conf 0.95, zero spread. (This is what makes the fixture cache valid.)
- **Latency ~55s per local `qwen3:8b` agent call** (26–85s range). Single GPU,
  can't parallelize → full fresh runs are ~1.5–2h. The fixture cache is the
  only way to make iteration fast.
- **Routing:** `fast_path` dispatches mean **5.8 agents/exchange** and reaches
  the LLM coordinator **0/90** times on real captured traffic — the regex router
  is the de-facto brain; the LLM coordinator is effectively dead code today.
- **Cloud `gemma4:31b-cloud` coordinator** routes tighter (**4.0 vs 5.8, 31%
  fewer agents**) at **~2s/call**, and the labeled A/B confirmed the cut costs
  **zero detections** (TP recall **9/11 for both** fast_path and coordinator;
  the 2 misses are TP3/TP4 IDOR, missed by both — a single-exchange limitation,
  not routing).

## 5. Open items / next steps (prioritized)

1. **RECALL GATE NOT YET RUN against current state.** `ab_routing_recall.py`
   (~1.5h) must confirm TP recall held at **9/11** after my anomaly changes +
   the agent's dedup. Low risk (anomaly verified recall-safe deterministically;
   dedup can't touch TP recall — no PixelMart TP is graded on a Werkzeug CVE),
   but **TP10 rides on the anomaly agent I changed**, so run it. The coding
   agent was about to launch this.
2. **Fresh authenticated `fp_benchmark.py`** for the TRUE current FP numbers.
   MUST be run by whoever has the **GitHub token authenticated** (else
   `known_vuln_lookup` rate-limits at 60/hr unauth and skews results). Run it
   AFTER the recall gate, NOT concurrently.
3. **Fix the FP metric** (see §2) so it stops counting real CVEs / real evidence
   as false positives.
4. **LLM-prompt hardening for the 3 genuine FPs** (TN3 self-profile ≠ excessive
   exposure; TN5 403-CSRF-enforcement ≠ missing CSRF; TN6 /health ≠ debug
   endpoint). This is `FP_REDUCTION_TASK.md` Task 4 — gate EACH change with
   `bench.py` (FP) AND `ab_routing_recall.py` (recall); revert anything that
   drops recall.
5. **`ollama_client.py` JSON/breaker fix + Burp UX/gating edits** were applied
   by the coding agent and reported passing; I verified `Finding.confidence` is
   a primitive `double` so the Java gating can't NPE. Not independently re-run
   in Burp (no live Burp here — same boundary as all Java in this project). The
   real jar builds in the user's Codespace via Gradle.

## 6. Standing concern (NOT mine to fix without the user — flag it)

`harness/config.yaml` is armed for live testing: `validators.active_enabled: true`,
`validators.allow_mutating_replay: true`, `autonomous_discovery.enabled: true`.
The config's own comments say to revert these to `false` once done testing.
`autonomous_discovery.enabled: true` also contradicts its own §5p docs
("off by default, not yet live-verified"). Confirm with:
```bash
grep -nE "active_enabled|allow_mutating_replay|enabled:" harness/config.yaml
```

## 7. Bigger architectural direction (discussed, partially validated)

Target design (the user's, refined): **cloud-32B coordinator as the PRIMARY
router** (dispatching a small precise agent set, on a minimal on-prem-anonymized
feature projection — method/URL-path/param-NAMES/status/response-shape, NOT raw
bodies) → **cheap local 8B specialists** for depth (keeps the point-1
anti-hallucination specialization) → **an adaptive "challenge the agent / spin
another if it found nothing" loop** the big model drives, bounded by the
existing `effort_budget`. Reuses unused machinery (`retry_policy.py`,
`active_verification.py`, the `analysis_pipeline._critique` pass). Routing
precision is validated (§4); the loop + anonymization projection are NOT built.
The `fast_path` regex router should be DEMOTED to a thin deterministic
safety-net floor, not deleted (it guarantees e.g. `sqli` fires on a login even
if the coordinator misses).
```
