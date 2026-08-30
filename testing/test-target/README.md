# PixelMart — a clean test target for the Burp LLM Harness

A small, deliberately-vulnerable e-commerce API, built specifically so
you have something to test the harness against that isn't OWASP Juice
Shop. Juice Shop's vulnerabilities and exact exploit steps are
extensively documented, blogged, and walked through publicly — which
means any model has almost certainly seen detailed write-ups of it during
training. A "confirmed" finding against Juice Shop can't tell you whether
the model reasoned from the actual evidence in front of it or recognized
a target it already knows the answers to. This app has no public write-up
anywhere, so a finding against it has to come from genuine reasoning over
the real request/response content.

## Run it

```bash
pip install flask
python app.py
```

Starts on `http://127.0.0.1:5001`. It rebuilds its SQLite database from
scratch every time it starts (`pixelmart.db` in this directory) — nothing
persists between runs, so you always start from the same known state.

Point Burp's proxy at it, browse/exercise the API a bit (or just replay
requests directly in Repeater), and send exchanges to the LLM Harness
the way you normally would.

## What's in it

12 real, independently-verified vulnerabilities across SQL injection
(auth bypass and data exfiltration), IDOR, reflected and stored XSS, a
business-logic price-manipulation bug, a genuine race condition, SSRF
(with real local file disclosure via `file://`), path traversal, a
forgeable JWT (`alg:none`), and an unauthenticated admin endpoint that
leaks the JWT signing secret — plus 6 correctly-implemented endpoints
designed to look similar to the vulnerable ones, specifically to test
whether the harness over-flags things that merely *look* suspicious.

Full ground-truth list, with the exact proof-of-concept command for each
one: **`ANSWER_KEY.md`** — don't read it before you've run the harness
and looked at its findings, or you'll bias your own review.

## A note on realism

This isn't trying to be exhaustive (it doesn't cover all 36 of the
harness's specialist agents — some categories like GraphQL, WebSocket, or
OAuth genuinely don't apply to a small REST API like this one). It's
trying to be a clean, unbiased sample: real bugs with real exploitability
you can verify yourself, sitting next to deliberately similar-looking
safe code, so a run against it tells you something about actual detection
quality rather than recall of a famous target.
