# Review instructions

You're reviewing `REVIEW_HANDOVER.md` and the actual code it describes,
in this project. You're more capable and more expensive than the model
that did this work — spend your budget on judgment, not on re-deriving
things already checked. Below is what to verify, in priority order, and
what to explicitly not re-litigate.

## Don't re-litigate these — already decided, with reasoning given

- **Whether to adopt the SaaS platform's infrastructure** (Kubernetes,
  Kafka, Postgres+RLS, multi-tenancy). Already analyzed and declined,
  reasoning is in `platform-spec-gap-analysis.md` if you want it — the
  short version is this is a single-operator local tool, not a
  multi-tenant service, and that's a real fact about the project, not a
  cost-cutting excuse. Re-litigating this from scratch wastes your
  budget on a settled question. If you think the reasoning itself was
  wrong, say so — but read it first.
- **Whether Python/Java/SQLite is the right stack.** Also already
  decided for this project, for the same reason. Not in scope for this
  review round.

## Verify these — in priority order

### 1. Run the tests yourself. Don't trust the "94/94" claim without checking.

```
cd harness && python3 -m pytest -q
```

If this doesn't show `94 passed`, everything else in the handover is
suspect and you should say so immediately rather than reviewing code
whose test claims don't hold.

### 2. The credential redaction fix (`base_agent.py`) — check for bypass paths, not just the happy path

The claim is: `Authorization`/`Cookie`/etc. header *values* never reach
the LLM prompt. Things to actually check, not assume:
- Does `_redact_headers()` get applied everywhere a header could reach a
  prompt, or only in `_user_prompt()`? Check `knowledge.retrieve()` and
  the `prior_context` string built in `orchestrator.py` — do either of
  those ever carry raw header values through a different path (e.g. a
  prior finding's `evidence` field quoting a header verbatim)?
- Is `request_body`/`response_body` a bypass? A session token in a
  response *body* (not header) is untouched by this fix — the handover
  admits this. Judge whether that's an acceptable scope boundary or a
  hole worth calling a defect.
- Does the redaction placeholder itself leak length/shape information
  that matters? (Probably not security-relevant here, but worth 10
  seconds of thought.)

### 3. The reproducibility metadata migration path — already checked once, worth a fast independent confirmation

`store.py`'s `ALTER TABLE ... ADD COLUMN` pattern only runs `if col not
in cols`. This was checked this session (see `REVIEW_HANDOVER.md`): built
an old-schema DB with a populated row, opened it with the new `store.py`,
confirmed the row survives with `model=''`/`prompt_version=''` and no
exception. Worth a fast independent re-run rather than trusting a
single self-reported check on a migration path — this is exactly the
kind of claim cheap to verify and expensive to be wrong about:

```python
# rebuild the old-schema DB + row, then open with current store.py,
# confirm no exception and old data survives (see REVIEW_HANDOVER.md
# for the exact script used).
```

### 4. Cost-weighted ranking — check the math, not just that tests pass

`value_density = expected_risk / max(cost, 1e-9)`. Verify this is the
right formula for the stated goal (avoid ZeroDivisionError while not
letting `cost=0` produce an absurdly huge/effectively-infinite
`value_density` that would always dominate ranking regardless of risk).
Trace through: what does a `cost=0` finding's `value_density` actually
evaluate to, and is that defensible, or is it a latent bug the tests
happened not to probe hard enough? (The existing test
`test_zero_cost_does_not_divide_by_zero` only checks `> 0`, not
magnitude — that's a real gap in the tests, not just the code, worth
noting either way.)

### 5. Identity/Session — judge whether "half-wired" was the right call to ship

The handover is explicit that this doesn't integrate with the Java side
at all yet. Decide: is a persisted, tested, but disconnected-from-Burp
Identity model actually useful to ship as-is, or should it have waited
until the Java integration existed too (avoiding a "looks done, isn't
actually usable yet" trap)? This is a judgment call about scoping, not a
correctness question — form your own view rather than deferring to the
handover's framing of it as a reasonable stopping point.

### 6. Spot-check for the class of bug this project has been bitten by twice already

Per `HANDOVER.md`'s own history, this project has shipped silent-mismatch
bugs before (`categories.py`'s free-text-vs-exact-match fix, the
`profileImage` SSRF param-name miss). Check the new code for the same
pattern: e.g. `IdentityCreateRequest.role` is validated against
`identity.IdentityRole` in `server.py` (raises 400 on bad input) — good.
But does anything downstream assume a role string without going through
that enum? Check `store.save_identity`'s `identity.role.value if
hasattr(...) else identity.role` — that fallback exists because
`save_identity` might receive either an enum or a raw string depending
on caller. Decide whether that's defensive programming done right, or a
sign the type contract between `identity.py` and `store.py` is looser
than it should be.

## What "fit for purpose" should mean for your verdict

This tool's purpose: help one analyst, using Burp, avoid shipping
hallucinated findings, during a single engagement, on their own machine.
Judge everything against that — not against "would this pass a SOC 2
audit at a 50-person security company," which is a different product
with a different purpose the user has already explicitly ruled out for
this project.

## Format of your response

State a verdict per item (1-6 above), each as one of: **sound**,
**sound but incomplete** (say what's missing), or **defect** (say the
concrete failure case, not just "this could be better"). End with
whether you'd ship this session's changes as-is, ship with specific
fixes first (name them), or hold pending more work (name what).
