# Handover: AgenticBurp Security Testing Harness

**STOP — this file is superseded. Read `HANDOVER_LATEST.md` first, not this one.**
Everything below predates a major session that fixed severe, previously-undetected
bugs (the entire specialist-agent pipeline was non-functional until that session)
and ran real live-target testing against OWASP Juice Shop. `HANDOVER_LATEST.md`
supersedes this document's claims about current state; this file is kept for
historical context on earlier sessions' reasoning, not as a source of current facts.

---

**Read this first.** This document exists because two previous agents on
this project made false progress claims that weren't caught until a
later session audited the actual code: one claimed a "Web Cache
Poisoning agent... Created (19KB)" that never existed anywhere in either
branch; another claimed a `git push` that was never confirmed to have
executed. Both claims were written with full confidence and no
verification command attached. Do not repeat that pattern.

## The one rule for this handover

**Every factual claim below has a command next to it that reproduces
the evidence for that claim. Run the command before relying on the
claim, every time, even if this document looks careful.** If what you
observe disagrees with what this document says, trust what you
observe, not this document -- and say so explicitly rather than
quietly reconciling the discrepancy in your own head. This document
was accurate when written; it will not stay accurate if the code
changes and nobody updates it.

Never write "X is done" or "X works" without one of:
- A test that passed, with the actual test output shown, not summarized.
- A specific, named limitation of what was and wasn't checked (e.g.
  "compiles cleanly; never run against a live Burp session").

"I wrote the code" and "I verified the code" are different claims.
Keep them visibly different in anything you write, including your own
internal reasoning before you write it.

---

## What this project is

A Burp Suite extension (Java) + local analysis harness (Python, calls
a local Ollama LLM) for semi-automated web security testing. The
Python side runs specialist "agents" (one per vulnerability class)
against captured HTTP exchanges, then independently confirms
high-value findings with "validators" (deterministic checks, active
probes, or external tools like sqlmap). The Java side is a Burp
extension UI that captures traffic and can run a small number of
live, session-aware active tests (e.g. comparing two authenticated
identities) that need a real Burp session, which the headless Python
side structurally can't do.

## Verified current state (re-run these, don't trust the numbers)

```bash
cd harness
python3 -m unittest discover -p "test_*.py"   # expect: Ran 325 tests ... OK
python3 -m pytest test_plugin_system.py -q     # expect: 26 passed
```

Java side (needs a JDK; `apt-get install openjdk-21-jdk-headless` if
missing -- this environment has no real Montoya API jar or Gradle/Maven
network access, so this compiles against `dev-tools/stubs/`, a
hand-written partial stub of the Montoya API):

```bash
find dev-tools/stubs burp-extension/src/main/java -name "*.java" > /tmp/src.txt
javac -d /tmp/out -nowarn @/tmp/src.txt 2>&1 | grep -c "error:"
# expect: 16 -- ALL FIVE categories below, nothing else. If you see a
# NEW category of error, or a count that changed because of something
# YOU touched (not because you fixed one of these), investigate before
# assuming it's fine.
#   - package burp.api.montoya.core does not exist
#   - package burp.api.montoya.ui.contextmenu does not exist
#   - package com.google.gson does not exist
#   - cannot find symbol (cascades from the above two missing packages)
#   - method does not override or implement a method from a supertype (same cascade)
```

**This 16-error state means the Java extension has never been run.**
Every claim about Java-side behavior in this document (and in any
prior session's) is "compiles cleanly against an incomplete stub" or
"logic verified via a Montoya-free unit test," never "confirmed working
in Burp." Building a real environment with the actual Montoya jar and a
Gradle build (needs network access to Maven Central, which this
sandbox's allowlist doesn't include) and testing against a live target
is the single highest-value verification gap in this project.

The one thing that IS actually executed, not just compiled, on the Java
side is the decision-logic classes in `burp-extension/src/main/java/com/harness/llm/logic/`,
via this repo's own reflection-based test runner (no Maven/JUnit needed):

```bash
find dev-tools/stubs burp-extension/src/main/java/com/harness/llm/logic \
     burp-extension/src/test/java/com/harness/llm/logic -name "*.java" > /tmp/src2.txt
echo "dev-tools/RunTests.java" >> /tmp/src2.txt
javac -d /tmp/out2 @/tmp/src2.txt
cd /tmp/out2 && java RunTests \
  com.harness.llm.logic.SessionLifecycleLogicTest \
  com.harness.llm.logic.IdentityCompareLogicTest \
  com.harness.llm.logic.SsrfCallbackLogicTest \
  com.harness.llm.logic.XssPayloadLogicTest \
  com.harness.llm.logic.WorkflowReplayLogicTest
# expect: === TOTAL: 48 passed, 0 failed ===
```

Agent/validator inventory (also re-verifiable):

```bash
cd harness
ls agents/*.py | grep -vc -E "__init__|base_agent|plugin.py"       # expect: 36
ls validators/*.py | grep -vc -E "__init__|base.py"                 # expect: 15
```

## What was done this session, and how each claim was actually checked

**Merged two divergent branches** (`vibe-juice-shop-testing-merged`,
`vibe-juice-shop-report`) into one tree. Verified via diff, not
assumption -- the two branches had genuinely different agent sets
(one had CORS/recon/HTTP-smuggling agents the other lacked entirely),
so this was a real three-way reconciliation, not a fast-forward.

**Built 10 new agent+validator pairs** this session: web cache
poisoning, OAuth, subdomain takeover, crypto/TLS, CSP+clickjacking,
header injection, API security, WebSocket (CSWSH), race condition,
insecure deserialization. Each was individually compiled, instantiated,
and functionally unit-tested (not just imported) before being wired
into the four integration points (`categories.py`, `planner.py`,
`validators/registry.py`, `fast_path.py`). Confirmed end-to-end via
constructed `HttpExchange` objects hitting real fast-path selection
logic, not just "the file exists."

**Found and fixed a safety-critical bug class**: 13 validators
(including pre-existing ones from before this session, e.g. the CORS
validator) blindly reused whatever HTTP method the originally captured
exchange used, meaning any of them could replay a captured DELETE or
mutating POST while testing something unrelated. `sqlmap.py` had the
same category of risk for any non-GET target (SQLi fuzzing sends many
requests to the same endpoint; if that endpoint is a real checkout
action, fuzzing fires it repeatedly). Fixed at the root for everything
that didn't need it (hardcoded a safe method), and built
`harness/safety_gate.py` -- a centralized, mandatory checkpoint, with
hard-coded ceilings that no config value can exceed -- for the two
techniques that legitimately need mutating replay (API mass-assignment
probing, the race-condition burst). This is enforced by a structural
test (`test_safety_gate.py::TestNoValidatorBypassesTheGate`) that greps
every validator file for the exact bypass pattern, so a future edit
that reintroduces it fails the test suite, not a code review someone
might skip. **Read `test_safety_gate.py` before touching any
validator's HTTP-sending code** -- it documents exactly which files are
allowed to use `exchange.method` and why.

**Fixed a pre-existing, previously undetected bug**:
`select_agents_by_response_headers` in `fast_path.py` only ever matched
header *values*, never header *names* -- meaning the CORS agent's own
fast-path pattern (which matches on header names like
`Access-Control-Allow-Origin`) could never fire, silently, since before
this session. Confirmed via a before/after test against realistic CORS
response headers, not just code reading.

**Fixed `CANONICAL_CATEGORIES` missing `recon` and
`http_request_smuggling`** despite both having fully working agents --
their findings were invisible to `store.py`'s coverage ledger. Found
by tracing `CANONICAL_CATEGORIES`'s actual usages, not by assumption.

**Audited and fixed `chaining.py`**: 30 of 36 canonical categories,
including `sqli`, had zero path into any chain rule before this
session, and the existing `open_redirect+oauth_redirect` rule was
permanently unreachable (referenced a tag string the real OAuth agent
never emits). Fixed by making every finding's canonical category
automatically a valid chain tag (reusing `categories.py`'s synonym
table via a new `all_known_phrases()` accessor, not a third duplicate
list), plus a word-boundary-safe substring fallback justified by
chaining's own low-confidence, human-reviewed output. Added 7 new
chain rules for this session's new categories. 18 tests in
`test_chaining.py`, including precision tests proving short category
names like `auth` don't false-match inside unrelated words like
`unauthorized`.

**Found the `findings` database table never persisted `evidence`,
`suggested_test`, or `owasp_category`** -- only a one-line summary --
which would have made a report generator useless for actual
reproduction steps. Fixed via the project's existing
`PRAGMA table_info` + `ALTER TABLE` migration pattern, verified with a
real write-then-read round-trip test (`test_store.py`), before building
`report_generator.py` on top of it.

`test_safety_gate.py` -- the highest-stakes file in this project --
has 34 tests. Verify with `python3 -m unittest test_safety_gate` and
read its own `Ran N tests` summary line; don't grep verbose test-name
output for `... ok` lines to count them, since multi-line test names
(the ones with a docstring under `@` or as the first line of the
method) split across lines and make that undercount silently. This
was caught by fact-checking a draft of this very document.

**Built `report_generator.py`**: turns stored findings into a
submission-ready Markdown report, separating confirmed from
unconfirmed findings, surfacing `basis` (derived/recalled/assumed) with
a visible warning on non-derived findings, keeping chain hypotheses in
their own clearly-disclaimed section, and generic category-keyed
remediation explicitly labeled as a starting point rather than a claim
about the target's actual code. 20 tests including a full
persist-then-generate pipeline test.

**Extended session-lifecycle coverage**: `auth_agent.py`'s prompt was
read in full (not assumed from its docstring) and confirmed to have no
session-fixation or logout-invalidation guidance. Fixed the prompt, and
built `SessionLifecycleLogic.java` (Montoya-free, 9 tests, actually run
via `RunTests`) wired into `ValidationExecutor.java` as two new
capabilities. This is Java-side, not a Python validator, because -- like
the existing cross-identity comparison capability it sits next to --
confirming it needs the analyst's own live, authenticated session
pairs, which the headless harness structurally doesn't hold.

## What is explicitly NOT done -- don't assume otherwise

- **The forced-egress safety proxy is not built.** Fully designed in
  `PROXY_WATCHER_TODO.md`, including the specific reasons the in-process
  `safety_gate.py` can't cover process boundaries (sqlmap's subprocess),
  runtime boundaries (the JVM), or code that never calls the gate. Read
  that file before starting; it documents an honest, unresolved cost
  (live TLS interception can't be verified without a real target to
  point it at).
- **No live Burp session has ever run this extension.** Every Java-side
  claim in this project, from any session, is compile-verified or
  Montoya-free-unit-test-verified, never runtime-verified. Treat any
  claim about actual Burp UI behavior (does the progress bar render
  correctly, does the unified view's JSplitPane divider work, does the
  session-fixation dialog actually pop up) as **unverified** until
  someone runs it in real Burp.
- **sqlmap's actual binary was never invoked** in this sandbox (no
  sqlmap installed). The safety-gate integration was verified by
  constructing a fake binary path and confirming the gate blocks/allows
  correctly *before* the subprocess call -- not by watching sqlmap
  itself run.
- **The report generator's remediation hints are generic security
  best practice, written from general knowledge, not verified against
  any specific framework's documentation.** `ai_llm` and `anomaly`
  categories deliberately have no remediation hint (they're not
  vulnerability classes with a single fix, they're catch-alls) -- see
  `test_report_generator.py::test_every_canonical_category_has_a_remediation_hint`
  for the exact exclusion list; don't silently add more exclusions
  without updating that test.
- **No cross-run finding triage/suppression exists.** A finding marked
  false-positive today has no persistence to suppress it on a future
  scan of the same target. This was flagged as a "next level" priority
  and not started.
- **No login/session automation exists.** The harness analyzes
  whatever traffic the analyst manually drives through Burp. This may
  be an intentional architecture boundary rather than a gap -- it was
  never resolved which, just documented as ambiguous.

## Before you claim anything is fixed

1. Find the actual, current code -- not a summary of it, not what a
   previous handover said about it. Read the file.
2. Reproduce the bug or the missing behavior yourself, with a command
   or a constructed test case, before writing the fix. If you can't
   reproduce it, say "I could not reproduce X" rather than fixing
   something you're inferring might be the cause.
3. After fixing, re-run the *exact* same reproduction from step 2 and
   show that it now behaves differently. "I changed the code that
   looked responsible" is not the same claim as "I confirmed the fix."
4. Run the full test suite (`python3 -m unittest discover -p "test_*.py"`)
   and diff the count against 325. A dropped test count with no
   explanation is a red flag, not a rounding error.
5. If you're about to write a config default, a numeric ceiling, or a
   security-relevant boolean, check whether `safety_gate.py` already
   has an opinion about it before inventing a new one.
