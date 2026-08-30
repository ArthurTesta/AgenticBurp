# HANDOVER — read this before touching anything

Written at the end of a session that ran the specialist-agent pipeline
end-to-end for the first time against a real, purpose-built target
(instead of Juice Shop), fixed two bugs that broke immediately on first
real use, fixed three real detection-coverage gaps found by that run,
and built a reusable blind-testing kit. Every claim below was verified
by actually running something in this sandbox — re-verification commands
are given inline. This supersedes `HANDOVER_PRIOR.md` (the previous
version, archived, not deleted, in case something here is wrong and the
prior detail is needed).

---

## 0. The one thing to internalize before anything else

**This session ran `orchestrator.analyze()` end-to-end for the first
time in this project's history and it crashed immediately, twice, on
two different bugs, neither previously known.** Both were in code paths
(`cache`'s hit/write cycle) that no existing test exercises — every
existing test either mocks past that layer or never reaches a real
cache round-trip. The lesson is the same one the prior handover already
named and it bears repeating because it just proved itself again: **a
green test suite is not evidence that the full call path works.**
Running the real thing, even with a substitute LLM, found bugs that
reading the code or running unit tests never would have.

The second lesson this session adds: **testing against a famous target
teaches you about your own training data, not about your tool.** OWASP
Juice Shop has been written up, blogged, and walked through so many
times that any LLM's "success" against it is contaminated — you can't
tell if it reasoned from evidence or recognized a target it already
knows the answers to. This session built `test-target/` (a small,
never-published app called PixelMart) specifically to remove that
confound, plus `blind-test-kit/` so a *different* agent — one who didn't
build the app and doesn't have the answer key — can get a real signal
too. Both directions matter: the contamination risk isn't just "the
model has seen this app," it's also "the person grading the run already
knows the answers." Use the kit, not just the self-graded target, when
you want a real number.

---

## 1. Current environment state — verify before assuming

```bash
cd /home/claude/project/project/harness && python3 -m unittest discover -p "test_*.py"
# Expected: Ran 432 tests, OK

python3 -m pytest test_plugin_system.py -q
# Expected: 26 passed

ls agents/*.py | grep -vc -E "__init__|base_agent|plugin.py"    # expect 36
ls validators/*.py | grep -vc -E "__init__|base.py"              # expect 15
```

**If any of these numbers differ from what's stated, something changed
since this was written — trust the command output, not this document.**

Ollama is still not reachable in this sandbox (same as every prior
session — network policy blocks it). Everything in this session that
needed a model call used the same substitution the prior session used:
constructing the harness's real prompts via its own code, then having
Claude read them and produce the JSON a real call would need to. See §5
for exactly how, and §5's own honesty section for what that does and
doesn't prove.

---

## 2. Bugs found and FIXED this session

### 2a. Two bugs that broke `orchestrator.analyze()` immediately, on first real end-to-end run

| # | File | Bug | Fix | How it was found |
|---|---|---|---|---|
| 1 | `orchestrator.py` (2 call sites) | `cache.compute_exchange_hash(...)` — that function doesn't exist at module level, only as `cache.ExchangeCache.compute_exchange_hash`. Crashed **every** successful, non-bypassed call to `analyze()`, on both the cache-hit and cache-write paths. | Both call sites corrected to `cache.ExchangeCache.compute_exchange_hash(...)` | First-ever real call to `orchestrator.analyze()` through a full cache write |
| 2 | `orchestrator.py` (cache-hit branch) | `AnalysisResponse(**cached_result.model_dump(exclude={...}), summary=f"...", ...)` — `summary` wasn't in the exclude set, so it got passed twice | Added `"summary"` to the exclude set | First-ever real cache **hit** (replaying an identical exchange) |

No existing test constructs a real `Orchestrator` and calls `analyze()`
through a full cache read/write cycle — `test_hardening.py` uses
`object.__new__` to skip `__init__` entirely for its narrow unit test.
**These two bugs would fire on literally every real request in
production.** If you're auditing further: this is the same shape of gap
the very first session found in `prompt_validator.py` — invisible to
unit tests, immediate on first live call.

### 2b. Three real detection-coverage gaps, found by a live discovery run against PixelMart, now fixed

Full detail and before/after evidence: `test-target/DISCOVERY_RUN_RESULTS.md`.

| # | Gap | Root cause | Fix |
|---|---|---|---|
| 3 | IDOR never dispatched for order/invoice/booking-shaped URLs | `fast_path.py` had a URL pattern for `/user`, `/profile`, `/account`, `/me` → `idor` but nothing for `/order`, `/invoice`, `/booking`, `/ticket`, `/transaction`, `/reservation` | Added a matching URL pattern → `idor, auth, misconfig` |
| 4 | `business_logic` never dispatched for a negative-quantity/negative-total exploit, even though the exact negative number was sitting in the response | `fast_path.py`'s response-body checks are all text/regex — nothing inspects numeric JSON values, and nothing looks at the **request** body at all | Added `select_agents_by_body_anomalies()`: a structural (JSON-parsing, not regex) check for a negative value in a money/quantity-shaped field (`price`, `total`, `quantity`, `balance`, etc.), checked against both request and response body |
| 5 | `alg:none` JWT forgery structurally invisible to every agent | `security.redact_headers()` fully redacted `Authorization`, hiding the token's algorithm field along with the payload and signature | `redact_headers()` now discloses *only* the JWT header segment (e.g. `{"alg":"none"}`) for JWT-shaped bearer tokens. Payload and signature stay fully redacted. Non-JWT tokens (opaque API keys, Basic auth) are completely unaffected — verified directly. |

**Re-ran the full discovery suite after all three fixes: 11 of 12 true
positives now hit** (up from 8; the 12th, a race condition, is
conditional on capturing the rejection response — inherent to the
category, not a bug), **all 6 true negatives still correctly clean, zero
new false positives introduced.** 11 new regression tests added across
`test_fast_path.py` and `test_base_agent.py`.

**A caution before you extrapolate these fixes to other apps:** fix #5
in particular was verified against exactly one thing — a JWT with a
standard three-segment structure. If a target uses a different token
format (opaque session tokens, PASETO, a custom scheme), this fix does
nothing for it, silently. It's not a general "auth token visibility"
fix, it's a narrow, JWT-shaped one.

---

## 3. Also fixed this session — efficiency, not correctness

Full detail: `harness/CACHE_HASH_VOLATILITY.md`, `harness/FAST_PATH_EFFICIENCY.md`.

- **Cache almost never actually cached.** `ExchangeCache.compute_exchange_hash()` hashed every header verbatim, including `Date`, `ETag`, `X-Request-Id` — headers that change on every single request regardless of content. Any two "same" requests in a real session were a guaranteed cache miss. Fixed: strip 13 pure-transport headers before hashing. **Deliberately did NOT touch** `Cookie`/`Authorization`/CSRF-token values — those are identity-bearing, and this harness's IDOR detection depends on being able to tell "same request, different user" apart. Verified directly both ways: noise-only diffs now hit; identity/CSRF diffs still correctly miss.
- **`fast_path.py` was dispatching ~6 agents on almost every exchange regardless of content** — `GET`/`POST` methods and `200`/`201` statuses were mapped to broad agent lists that fired unconditionally once *any* signal existed, which was nearly always. Removed those four blanket entries; kept every entry that's actually discriminating (3xx/4xx/5xx statuses, mutating-verb→idor/auth). A follow-up review caught that this went too far in one place — search functionality using an uncommon param name (`?s=`, `?text=` instead of `?q=`) lost `sqli`/`xss` coverage entirely. Fixed: any non-empty query parameter now carries an `sqli`/`xss` baseline regardless of its name.
- **26 of 36 agents silently inherited the coordinator's model.** Added a dedicated `agent_defaults` config section (default: `gemma2:9b`) so agent model choice is no longer coupled to a routing-quality decision that has nothing to do with it. The 10 agents already explicitly pinned to `llama3.1:8b` in `config.yaml` are untouched.

---

## 4. New this session: a real test target, a real discovery run, and a blind-test kit

### 4a. `test-target/` — PixelMart

A small, single-file Flask app (`app.py`, one dependency, SQLite,
`python app.py` → `http://127.0.0.1:5001`) with 12 real, independently
hand-exploited vulnerabilities (SQLi ×2, IDOR ×2, XSS ×2, business logic,
race condition, SSRF, path traversal, JWT forgery, unauthenticated admin
config leak) plus 6 correctly-implemented true negatives specifically
shaped to look like the vulnerable endpoints (a safe parameterized
lookup next to the vulnerable search, an allowlisted `sort` param that
pattern-matches fast-path's own trigger words). Full ground truth,
with the exact proof-of-concept for each item: `test-target/ANSWER_KEY.md`
— **don't read it before running the harness against the app, including
if that's you again in a future session.**

### 4b. The discovery run and how to reproduce it

`test-target/capture_exchanges.py` sends real exploit traffic to a live
PixelMart instance and saves the resulting request/response pairs.
`test-target/phase1_record.py` runs those exchanges through the REAL
`orchestrator.py` with a fake LLM client that only records what it would
have sent (dispatch is real/deterministic; nothing about it is
simulated). `test-target/phase2_answers.py` has genuine, evidence-only
answers for every dispatched agent, written by reading the real recorded
prompts. `test-target/phase3_run.py` re-runs everything with those
answers wired in, producing real end-to-end output — real critique
gating, real chaining, real known-vulnerability lookups (a genuine call
to `api.github.com`), real caching.

To reproduce:
```bash
cd test-target
rm -f pixelmart.db && python3 app.py &
sleep 2
python3 capture_exchanges.py
rm -f /tmp/pixelmart_test_state.db /tmp/pixelmart_test_cache.db
python3 phase1_record.py       # dispatch summary + real prompts
rm -f /tmp/pixelmart_test_state_p3.db /tmp/pixelmart_test_cache_p3.db
python3 phase3_run.py          # real end-to-end findings
```
Full scored results already exist in `test-target/DISCOVERY_RUN_RESULTS.md`
— re-run only if you want to re-verify or if you've changed something.

**The honest limit of this, stated plainly because it's easy to
forget:** Claude substituted for the LLM *and* built the app *and*
wrote the answer key, in the same session, on the same target. Recall
numbers from this specific run are a ceiling on what careful reasoning
over the shown evidence could find, not a prediction of what
`llama3.1:8b`/`gemma2:9b` actually would. The three coverage-gap fixes
in §2b are real regardless of that caveat (they're properties of
`fast_path.py`'s pattern tables and `security.py`'s redaction list, not
of anyone's reasoning quality) — but "8 of 12, then 11 of 12" is not a
number to quote as this tool's real-world detection rate.

### 4c. `blind-test-kit/` — for a genuinely blind run

This is the fix for the limitation just named. It's a self-contained
package (its own copy of the harness, a sanitized copy of PixelMart with
every hint stripped out, a generalized version of the phase1/phase3
driver with none of the specific exploit payloads, and a template
answers file) meant to be handed to a **different agent who did not
build the target and does not have the answer key.**

```bash
cd blind-test-kit
cat METHODOLOGY.md   # full instructions for whoever runs this
```

The target app in `blind-test-kit/target/app.py` has had every `# BUG`
comment and the original's contamination-framing docstring stripped —
verified byte-for-byte behaviorally identical to `test-target/app.py`
(same SQLi, same IDOR, same everything; just no comments telling you
where). `blind-test-kit/harness_driver.py record`/`run` were smoke-tested
against this restructured layout in this session (a trivial 3-exchange,
1-finding round trip, confirmed real dispatch, real answer lookup, real
critique gating all work) — **it has not been run as an actual blind
test yet.** That's the next thing to do with it, ideally by someone
other than whoever wrote this document.

**Do not open `blind-test-kit/target/app.py` yourself if you're the one
about to hand this kit to another agent or run it "blind."** You already
know what's in it from this document. If you want a genuinely blind
result, get someone (or something) that hasn't read this handover.

---

## 5. What "do a full test" means going forward — the actual procedure

1. **If you want to sanity-check that a change didn't break dispatch or
   the pipeline:** re-run `test-target/phase1_record.py` and
   `phase3_run.py` per §4b. You already know the answers, so this is a
   regression check, not a real measurement — treat it exactly like
   that.
2. **If you want an actual signal on detection quality:** use
   `blind-test-kit/` per §4c, handed to an agent (or person) with no
   prior exposure to this session or to PixelMart's source. Compare
   their real, honestly-reasoned findings against
   `test-target/ANSWER_KEY.md` yourself afterward — don't let the person
   running the blind test see the answer key first or after, if you want
   to run it again later with a different tester.
3. **If Ollama ever becomes reachable in this sandbox:** everything in
   §4 works unmodified with the real model — just don't patch
   `chat_json`/`chat_json_metered` on the `OllamaClient` instance, and
   let the real HTTP calls happen. This would finally answer the
   question every session including this one has had to leave open:
   what does the actually-configured model really find. Do this before
   trusting any specific recall/precision number from this project.
4. **Before adding a fourth fast_path pattern or agent-dispatch rule
   because it seems obviously right:** run it through PixelMart or the
   blind kit first. Two of this session's three fixes (order-URL pattern,
   body anomaly check) were each individually obvious in retrospect and
   neither existed until a live run surfaced the gap. "Obviously should
   dispatch X here" is not the same as "verified to dispatch X here."

---

## 6. Found, but NOT fixed — don't assume these are resolved

Carried forward from the prior handover, still open (see
`HANDOVER_PRIOR.md` for original detail):

1. **`coordinator.py`'s fail-open-to-all-36-agents fallback.** Confirmed
   still present. Across all 22 real exchanges in this session's
   discovery run, fast_path was confident every single time and the
   coordinator was never invoked once — good for cost, but means this
   fallback's behavior in practice is still unverified by live traffic.
2. **`sqlmap` missed real, hand-confirmed SQL injections** in the
   original session's live-target work. Not re-tested this session
   (PixelMart's SQLi was confirmed via UNION-based exfiltration
   directly, not via `sqlmap`).
3. **Duplicate `_resolve_known_vulnerabilities` implementations** in
   `analysis_pipeline.py` and `orchestrator.py`. Not touched this
   session.
4. **No real precision/recall baseline against a live model still
   exists.** This session added the infrastructure to get one
   (`blind-test-kit/`) but has not actually run it against a reachable
   Ollama instance or a genuinely blind tester. This is still the single
   biggest gap between "the pipeline works" (increasingly well-verified
   now) and "the product works" (still unmeasured).

New from this session:

5. **`jwt` and `csrf` agents have zero entries anywhere in
   `fast_path.py`'s pattern tables.** They can only be reached via the
   coordinator, which (see #1) essentially never fires in practice. Not
   fixed this session — the JWT-forgery gap was closed by making the
   evidence visible (§2b #5), which let the more commonly-dispatched
   `auth` agent catch it, not by giving `jwt` itself a way to be
   reached. `jwt` and `csrf` as standalone agents are still effectively
   dead code. Adding URL/header patterns for these (JWT-shaped bearer
   tokens → `jwt`; CSRF-token-named headers/fields → `csrf`) is a
   reasonable, bounded next fix.
6. **The body-anomaly check (§2b #4) only understands "negative number
   in a money/quantity-shaped field name."** A business-logic exploit
   that manifests differently (a role field flipped to `"admin"`, a
   price field set to `0` instead of negative, a quantity that's
   suspiciously large rather than negative) will not trigger it. This
   is a narrow, verified fix for the specific pattern PixelMart's
   discovery run exposed, not a general "detect business logic
   anomalies" capability.

---

## 7. Priority order for whoever picks this up next

1. **Run `blind-test-kit/` for real**, with an agent who has never seen
   this document. This is the highest-value next step by a wide margin
   — everything else in this project has been graded by whoever built
   the thing being graded, including this session.
2. **Get Ollama reachable, even once**, and re-run `test-target/`'s
   three-phase discovery against the real configured models instead of
   Claude-as-substitute. Compare the real model's findings against
   `test-target/ANSWER_KEY.md` directly. This is the single biggest
   remaining gap named in every handover this project has had.
3. **Add fast_path coverage for `jwt` and `csrf`** (§6.5) — bounded,
   well-scoped, and the discovery run gives you a ready-made test case
   for the JWT half already.
4. Everything in §6 items 1–3 (coordinator fail-open, sqlmap miss rate,
   duplicate known-vuln resolution) — still open, still real, not
   touched this session because this session's live-target work
   happened to not need them.

**Don't start by re-reading old handovers and building a mental model
from prose.** Start with §1's verification commands, confirm the
numbers match, and go from there. That's the whole point of this
document existing.
