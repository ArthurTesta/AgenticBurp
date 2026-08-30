# Commercial-platform spec vs. this project: gap analysis

## Framing, first — because it changes every recommendation below

The spec describes a **multi-tenant SaaS autonomous pentesting platform**
(Postgres+RLS, Kubernetes, Kafka, a coordinator microservice fleet, web
app, remediation tracking across customers, continuous re-testing on
every deploy). This project is a **single-operator local Burp Suite
companion tool** (SQLite, one process, one analyst, one engagement at a
time). Those are different classes of system serving different threat
models and different economics. A lot of the spec's infrastructure
section doesn't transfer at all, and pretending it does would make this
tool worse (slower, harder to run, solving a problem it doesn't have).

The parts that *do* transfer are the **data-modeling and control-flow
principles** (P1-P9 especially) — and the useful discovery here is that
several of them are **already implemented**, just not named the way the
spec names them. That's worth saying plainly rather than either
overclaiming novelty or underselling what exists.

---

## Already aligned — validated, not gaps

| Spec principle | Where it already exists here |
|---|---|
| P1 — model never executes directly | Agents (LLM) only ever produce `Finding`/`TestPlan` objects. All actual HTTP/tool execution happens in `ValidationExecutor.java`'s typed capability methods or `sqlmap.py` — never model-generated shell/request construction. This is the spec's single most-repeated principle, and it's the one this project already gets right. |
| P2 — evidence is first-class, never finding-from-reasoning-alone | `Finding.confirmed` can only be set by a validator (`store.py`'s `persist_validation_submission`, gated by an explicit `confirmation_capabilities` allowlist). LLM reasoning alone cannot flip this flag. Direct match to the spec's P2. |
| P4 — deterministic tests + agentic reasoning coexist, agent picks the capability, doesn't perform it | `planner.py`'s `_CAPABILITIES` mapping + the switch statement in `ValidationExecutor.execute()` is exactly this pattern already. |
| P6 — specialized agents over one giant agent | 10 narrow specialist agents + a coordinator (routing) + a separate adversarial critique pass. Already matches the spec's minimum agent roster in spirit, though role names differ (no dedicated Recon/Browser/Code agents — see "Add" below). |
| P7 (partial) — scope enforced outside the model | `ValidationExecutor.java` checks `request.isInScope()` — Burp's own scope engine — before any Burp-plane action executes. This is arguably a *better* fit than building a bespoke scope engine, since Burp already has one and the analyst is already using it. The Python-only side (`allowed_hosts`) is weaker — see "Rework." |
| Coordinator `stop`/`stopReason` | `retry_policy.py`'s `Action.STOP_INCONCLUSIVE` / `HANDOVER_MANUAL` / `STOP_CONFIRMED` is a smaller-scale version of the spec's `AgentPlan.stop` — same idea, already built. |
| Task priority formula | `risk_allocator.py`'s `expected_risk = P(vulnerable) x severity_weight` is a simplified version of the spec's priority formula — see "Rework" for the one term worth adding. |

---

## Should ADD — real gaps, worth the effort, right-sized for this project

1. **Observation as a first-class object, distinct from Finding.** Right now everything an agent notices becomes a `Finding` (a claim) directly — there's no raw "I observed X" record independent of "I'm claiming X means Y." The spec's separation (`Observation` -> agents reason over observations -> produce `Hypothesis` -> validated -> `Finding`) would let the coordinator reuse observations across categories (e.g. "this response set a `Set-Cookie` without `HttpOnly`" is one observation multiple agents could use) instead of each agent re-deriving it. Cheap to add as one more SQLite table + a `store.persist_observations()` function; doesn't need a graph database.

2. **Credential/secret handling in agent prompts — this is a real, fixable exposure.** `base_agent.py`'s `_user_prompt` includes `request_headers`/`response_headers` verbatim, which means `Authorization` and `Cookie` header **values** (real session tokens, when testing a live target) currently go into the LLM prompt. The spec's "the model sees `credential_reference: cred_123`, never the raw secret" principle is directly actionable here even without building a whole Identity/Session subsystem: redact `Authorization` and `Cookie` **values** before building the prompt (keep the header *names* — an agent needs to know a session exists — just not the token). This is a small, concrete fix with a real security benefit, independent of everything else in this document.

3. **Capability registry with input validation.** Capabilities are currently a hardcoded string switch in Java + a dict in `planner.py`, matched by exact string. This project has already been bitten once by exactly this class of bug (`categories.py`'s free-text-vs-exact-match fix, and the `profileImage` SSRF param-name miss). A lightweight registry — capability name -> pydantic input schema + declared risk class — would catch a malformed `TestPlan.mutation` before it reaches an executor, and make "what capabilities exist and what do they need" self-describing instead of tribal knowledge spread across two languages.

4. **Fold `estimated_cost` into `risk_allocator.py`'s ranking, not just `effort.py`'s separate budget check.** The spec's priority formula divides by `estimated_cost`; this project currently ranks by risk alone and applies the token budget as a *separate* downstream gate. Practical effect: two findings with identical `expected_risk` but very different retry cost (say, a `sql_injection_validation` finding, which is one bounded `sqlmap` subprocess call, vs. an XSS finding now needing up to 4 payload rounds x N parameters) are currently treated as equal priority. Dividing `expected_risk` by a rough per-category cost estimate (already available from `effort.EffortLedger.average_tokens`) would fix this cheaply — no new infrastructure, just a formula change plus wiring the ledger into `risk_allocator.rank()`.

5. **Identity as a first-class object.** Already flagged as open work in this project's own handover *before* this document existed — this document independently arrives at the same conclusion (its `Identity`/`Session` interfaces), which is a good cross-check that it's worth doing. Scoped down for this project: doesn't need multi-tenant secret-reference infrastructure, just named identities + their captured sessions, replacing the current ad hoc `JOptionPane` picker in `identityCompare()`.

6. **A small declarative rule format for the cheap, pattern-based checks — not a full Nuclei clone.** `PathScorer.java`'s regex rules and the misconfig agent's judgment overlap in purpose but live in different languages and neither is analyst-editable without a rebuild. A short YAML/JSON rule list (pattern -> category -> weight -> reason) that `PathScorer` loads at runtime would let an analyst add a rule for a client-specific path pattern without touching Java. This is a fraction of the spec's full template engine (no matchers/extractors/multi-step sequences needed) — just enough to stop the "recompile Java to add one detection rule" friction.

## Should REWORK — right concept, current implementation is thinner than it should be

7. **Scope enforcement on the Python-only path.** `orchestrator.py`'s `allowed_hosts` is a flat hostname allowlist — no port/method/environment granularity, and nothing enforces it for the *sqlmap* validator path specifically beyond the same hostname check. Doesn't need the spec's full rule-matching engine; does need at minimum: port-level scope, and an explicit deny-by-default for anything sqlmap would touch outside the configured host set (currently relies on the same check as everything else, which is adequate but worth a dedicated test asserting sqlmap specifically can't be pointed off-scope even if a plan's `source_exchange_url` is spoofed).

8. **"Failures are knowledge" (spec P9) — currently true only within a single request's lifetime.** `retry_policy.Attempt` history exists but isn't persisted; once an `/analyze` call returns, the fact that three payloads already failed for a given parameter is gone. A future re-test of the same endpoint re-tries payloads already known to fail. Persisting attempt history per `(url, category, payload)` — even just a small `attempted_payloads` table — would let `payload_library.next_candidate()` skip known-dead payloads across sessions, not just within one retry loop.

9. **Reproducibility metadata (spec P8) is partial.** `store.py` persists findings, plans, and validation runs, but not the model name/version or prompt version that produced a given finding — only `AgentReport.model` exists at the API-response level, not written to the `findings` table. For a tool whose whole selling point is "verify, don't hallucinate," being able to answer "which model, which prompt version, said this" months later is worth the one extra column.

## Should NOT adopt, and why — right idea, wrong scale for this project

- **Kubernetes, Kafka, Postgres+RLS, multi-tenant isolation, OpenTelemetry/Prometheus/Grafana, a TypeScript/Go/Python polyglot monorepo, a separate web app.** All of this exists in the spec to serve *many customers concurrently, safely, at scale*. This project serves one analyst, one engagement, one process, on their own machine. Adopting this infrastructure would add enormous operational weight (a database server, a message broker, container orchestration) to solve a multi-tenancy problem this tool doesn't have, while making the actual thing analysts want — "clone this zip, run two Python commands, load a Burp extension" — no longer true.
- **Ephemeral sandboxed runners / container isolation for every capability execution.** The spec's threat model is *many customers' arbitrary task submissions* running on shared infrastructure. This tool's threat model is *one trusted analyst's own machine*. Container-per-action isolation would slow down an already-interactive workflow (Burp Repeater-adjacent) for a risk that doesn't really apply here. The one place this genuinely matters — `sqlmap` as a raw subprocess with potential `--os-shell` capability — is worth a narrower fix (explicitly disable OS-shell/file-write sqlmap flags in the validator, which is already implicitly true since the current invocation never passes them) rather than full sandboxing infrastructure.
- **Remediation tracking + continuous retest-on-deploy (spec P10).** This is a program-level, always-on exposure-management feature (Aikido/Hadrian's actual product category). This tool is used *during* an engagement, not as an always-on service watching a CI pipeline. Worth reconsidering only if this project's mission changes from "Burp companion for one assessment" to "always-on continuous testing service" — a substantially different product, not a natural extension.
- **Attack-path graph as a general graph database concept.** `chaining.py`'s rule-based chain detection (specific, named, reviewable patterns) is arguably more trustworthy for this tool's size than a generic graph-traversal engine would be — a general graph invites the LLM to assert path edges that aren't really evidence-linked, which is exactly the failure mode this project's whole design otherwise guards against. Worth adding *specific new chain rules* as they're found (as already happened this session), not replacing the mechanism.

---

## If only three things get built next

1. **#2 (redact session credentials from LLM prompts)** — smallest change, real security fix, no dependencies on anything else.
2. **#4 (cost-weighted risk ranking)** — a formula change to code that already exists (`risk_allocator.py`, `effort.py`), not new infrastructure.
3. **#5 (Identity as a first-class object)** — already independently flagged as this project's own next priority before this document arrived; the document is corroborating evidence, not new information, which is exactly the kind of cross-check worth acting on.
