# Harness improvement notes — gaps observed on a live max-coverage run

These are capability gaps in the harness itself, written target-agnostically on
purpose. They come from analyzing the request log and report of one full run
against a local test target, but nothing below names that target, its routes,
or its planted bugs — the point is to fix the harness's general capabilities,
not to patch a fixed list of endpoints. Whoever picks these up should **not**
go looking for the specific target or its answer key; treat each item as a
capability the harness should have regardless of what it's pointed at, and
validate against a throwaway fixture you build yourself if you need a live
target to test against.

## 1. Discovery breadth is narrower than the raw request count suggests

A large fraction of a run's total request volume is mutation/fuzzing repeated
against an already-small set of routes, not genuine expansion of the known
surface. Before tuning anything else, get an honest measure of *distinct
routes discovered* vs. *total requests sent* on a run, separate from whatever
the summary report shows.

Specific angles worth checking, each independently of any particular target:

- Is route discovery scoped to a single naming/path convention (e.g. assumes
  everything of interest lives under one prefix)? If a target serves a
  meaningfully different namespace — a different prefix, a non-JSON surface,
  a separate rendering path — would current discovery ever reach it, or does
  it need to be told the namespace exists up front?
- Is there a probe list for generically sensitive artifacts (config files,
  backups, dotfiles, etc.), distinct from the REST-resource-noun wordlist?
  If not, is that a deliberate scoping decision, and should it stay one?
- Does anything mine response *bodies* (not just JS assets) for path-like
  strings or URLs and feed them back into the candidate-route set? If a
  target's own content ever references an internal path in plain text
  (docs, help content, an error message, etc.), does discovery pick that up
  anywhere outside the JS-specific extractor?
- Is there a step that guesses "action" endpoints nested under a resource
  (verbs/sub-actions beyond a small fixed list), or is the nested/subresource
  guesser limited to a short hardcoded set of names?

## 2. Not every successful discovery probe turns into something reviewable

The role/identity-comparison discovery pass is structurally built to answer
one question: *does this response differ across identities?* That's the
right lens for object-level access control, but it has a blind spot: an
endpoint that returns a substantive, sensitive response *consistently* for
the identity that's supposed to have it will produce no signal from that
lens at all — access is "correctly" scoped, but the content itself might
still be a problem.

Check whether every substantive (non-trivial, 2xx-ish) response encountered
anywhere during discovery gets a chance at deeper, content-level review by
an analysis agent — or whether some responses are consumed only for a
narrower purpose (like an access-control comparison) and then dropped
without ever becoming an analyzable exchange. If some discovery paths
produce responses that never reach agent review, that's worth fixing
independent of what those specific responses contain.

## 3. Confirmation legs share one shape, and some bug classes don't fit it

The existing confirmation legs mostly follow the same pattern: replay
(approximately) the same request under a different condition — different
identity, forged signature, injected payload — and diff the result against a
baseline. That pattern doesn't cover:

- Bugs that require a *sequence*: do action A, then separately re-check
  whether a different action's behavior or authorization changed as a
  result.
- Bugs that only manifest under *concurrency* — interleaved/overlapping
  requests racing a check against a later write.
- Bugs where a value is accepted and stored safely now, but reused unsafely
  somewhere else, later, on an unrelated code path.

When a bug class gets correctly labeled by an analysis agent but never
progresses past "unconfirmed," check first whether it's *structurally
impossible* for any current leg to confirm — wrong request shape entirely —
before assuming it just needs a tuning pass on an existing leg.

## 4. Category-attribution reliability is a separate axis from coverage

On at least one endpoint that genuinely had exactly one specific class of
problem, the analysis agent emitted several different, mutually exclusive
class labels for that endpoint — none of which matched the problem it
actually had — while a label matching the *correct* general class landed
instead on a different, structurally similar endpoint that didn't have that
problem.

Implication: counting "was this class ever mentioned, anywhere in the
report" overstates how well categorization works, because a correct-sounding
label doesn't guarantee it's attached to the right target. A precision check
worth building: given a pair of structurally similar endpoints known (on a
fixture you control) to differ in exactly one security property, does the
harness's label land on the one that actually has it, not just somewhere in
the same report?

## 5. Chain hypotheses silently inherit their inputs' errors

The rule-based chain-composer builds "potential attack chain" narratives out
of pairs of independently-flagged findings. If either input finding is
itself misattributed (see #4), the resulting chain narrative is a
plausible-sounding story built on a false premise, and nothing in the output
currently flags that this could have happened. Consider requiring some
minimum verification/confidence on chain inputs, or at least surfacing when
an input's basis is speculative (`assumed`/`recalled`) rather than something
already directly observed.

## Suggested way to validate fixes without touching the real answer key

Build a small, disposable fixture with a few *paired* endpoints — for each
pair, structurally similar, differing in exactly one deliberately-introduced
property (one member of the pair has it, the other doesn't) — and use it to
exercise items 1–4 above in isolation. That gives a repeatable check for each
capability gap without needing the existing benchmark target or any
foreknowledge of what it contains.
