# Blind test kit — methodology

You're being asked to run a full discovery test against the target in
`target/`, standing in for the LLM the harness would normally call
(Ollama isn't required for this). You were not involved in building the
target and don't have its answer key. That's intentional — it's what
makes the results meaningful.

## Why this exists

Testing a security tool against a target whose vulnerabilities are
already publicly documented makes it impossible to tell whether a
"confirmed" finding came from genuine reasoning over the evidence or
from recognizing a familiar target from training data. This target has
no public write-up. Don't undermine that by reading `target/app.py` —
see `target/README.md`.

## What you're doing, in one paragraph

You'll explore the target like any black-box REST API, capture the
requests/responses that seem worth analyzing, run them through the real
harness orchestrator (which will tell you which specialist agents it
would dispatch — that part is real, deterministic code, not simulated),
then read each dispatched agent's *actual, harness-constructed* prompt
and write a genuine answer for it, exactly as a careful model call would.
Feeding those answers back through the real pipeline gives you real
end-to-end results: real critique, real known-vulnerability lookups,
real cross-finding chaining, real caching.

## Step 1 — run the target

```
cd target
pip install flask
python app.py
```

Leave it running on `http://127.0.0.1:5001`. Don't open `app.py`.

## Step 2 — explore and capture

Use `capture_helper.py` (or Burp, or plain `curl` and hand-write the
JSON — see `exchange_template.json` for the shape) to build up a set of
request/response pairs worth analyzing. Approach this like a real
engagement:

- Enumerate what endpoints exist and what each one does. **Guessing
  plausible endpoint names is a legitimate first step, but it is not
  exploration by itself — a page of 404s tells you nothing about the
  application.** The moment something returns 200, follow it: if a list
  response contains objects with ids, fetch one of those ids directly.
  If a resource looks nested (a product having comments, an order
  having line items), try its sub-resources. Let the application's own
  responses tell you where to go next, rather than working from a fixed
  list of common path names.
- Try normal use first, so you know what a "boring" response looks like
  — you'll want that contrast later, both for writing genuine agent
  answers and for judging whether a finding is actually warranted.
- **Get authenticated, for real, before concluding anything about
  authorization.** If there's a login/register flow, get it to actually
  succeed at least once and capture what a valid session looks like
  (a token, a cookie, whatever the app issues). A 401 on every request
  you send is not evidence the app protects anything — it's evidence
  you never got past the front door. Only once you have a real,
  working session does it become meaningful to test *authorization*
  (does this valid session let me see data that isn't mine?) as
  distinct from *authentication* (does the app require credentials at
  all?) — those are two different questions and testing only the
  second one tells you nothing about the first.
- Vary identity: with a real session in hand, capture requests made as
  different users, and requests made against another user's apparent
  resources (an id, a filename, a reference you saw in one user's
  response, requested again under a different identity).
- Try the standard things you'd try against any REST API: injection
  characters in parameters, unexpected parameter values (negative
  numbers, unexpected types), path traversal sequences in anything that
  looks like a filename, URLs in anything that looks like it might be
  fetched server-side, malformed or tampered auth tokens. **Send these
  to endpoints and parameters you've actually confirmed exist and
  accept input** — a payload sent to a 404 route tested nothing.
- Capture both the interesting case and a matching normal case where you
  can — a true-negative sample tells you as much about the harness as a
  true positive does, maybe more, since a tool that flags everything is
  as useless as one that flags nothing.

**Before moving on, check your own work against this list. If you can't
answer yes to most of these, you've done a reachability check, not a
security-relevant exploration — and a tool shown only reachability
evidence cannot report anything beyond that, which is not the same
thing as the tool failing to detect something:**

- [ ] Did you obtain at least one genuinely working authenticated
      session — not just attempt one?
- [ ] Did you use that session on more than one request, including at
      least one where you're checking whether it can see something that
      might not be "yours"?
- [ ] Is your 404/failure rate low relative to your total requests? (If
      most of what you sent bounced off nonexistent routes or
      unauthenticated 401s, you were mapping the outside of the
      building, not testing what's inside it.)
- [ ] Did you send at least one request where the *value* of a
      parameter or body field was something the endpoint plausibly
      doesn't expect (not just a guess at whether the endpoint exists)?
- [ ] For every "this looks correctly protected" observation you're
      about to write down: would the response have looked any different
      if the protection didn't exist? If the answer is no — if an
      unauthenticated request would have produced the identical 401
      whether or not the endpoint has a real authorization bug behind
      it — that request didn't actually test the thing you think it
      tested.

Save your captures as one JSON file matching `exchange_template.json`'s
shape.

## Step 3 — record real dispatch

```
python harness_driver.py record --exchanges your_exchanges.json
```

This runs your exchanges through the real orchestrator with a stand-in
LLM client that just records what it would have sent and returns an
empty placeholder. Look at the printed dispatch summary and at
`/tmp/harness_driver_transcript.json` — that file has the exact system
and user prompt every dispatched agent (and the coordinator/critique, if
reached) would actually receive.

## Step 4 — answer genuinely

Copy `answers_template.py`, read the transcript, and fill in an answer
for each `(exchange_index, agent_name)` pair that got dispatched. The
template file has the full rules and schema — the short version: answer
only from what's shown in that specific prompt, be honest about
uncertainty (a plausible-looking finding with no way to confirm it from
one exchange is a moderate-confidence candidate, not a slam dunk), and
return an empty findings list when nothing in the evidence supports your
agent's specialty. Manufacturing findings to look thorough defeats the
entire point of this exercise.

## Step 5 — run for real

**Before running the real pipeline, sanity-check your own answers file
in isolation:**
```
python3 -c "import your_answers; print(your_answers.get_answer(0, 'sqli'))"
```
If this raises an exception, fix it before continuing. This matters
more than it sounds like it should: the harness's per-agent error
handling catches exceptions from a failed agent call and quietly
records an empty result rather than crashing the whole run — which
means a broken answers file (a typo, a stray `null` where Python needs
`None`, a missing key) produces a *clean-looking* run with zero
findings, indistinguishable from "the harness found nothing" unless you
check the answers file itself runs cleanly first.

```
python harness_driver.py run --exchanges your_exchanges.json --answers your_answers.py
```

This is the real end-to-end result: your answers, run through the
harness's actual critique pass, known-vulnerability lookup, chaining,
and caching. Check `/tmp/harness_driver_results.json` (or wherever you
pointed `--out-results`) for the full detail.

**If you get zero findings and expected some, don't conclude the
harness failed — check, in order: (1) did your answers file just run
cleanly per the sanity check above; (2) does `dispatch.json` from Step
3 actually show the agent you wrote an answer for being dispatched on
that exchange at all — an answer keyed to an (exchange, agent) pair
that was never dispatched will never be called, silently.**

## When you're done

Report back: what you found, at what confidence, with what evidence —
and anything that struck you as odd about dispatch (an agent that never
seemed to fire when you expected it to, or one that fired on everything
regardless of content). You don't have the answer key, so don't try to
score yourself against a target number; just report what the real
pipeline actually produced from your own honest reasoning. Whoever built
the target will compare it against the real answer key on their end.

**Include your Step 2 checklist results in your report, explicitly** —
how many requests you sent, what fraction were 404/401, whether you
obtained a working session, whether you sent any payload-bearing
requests. This isn't busywork: without it, a shallow run (all
reachability checks, no real exploitation attempts) and a genuine one
are indistinguishable from the summary alone, and whoever reads your
report has no way to tell which kind of result they're looking at.
