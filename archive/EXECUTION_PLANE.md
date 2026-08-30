# Execution Plane

The execution plane is intentionally capability-based. An LLM may propose a `TestPlan`, but it never supplies a URL, shell command, credential, or arbitrary request mutation.

## Implemented typed capabilities

- `reflection_context_validation` — Burp generates a unique non-script canary and updates parsed URL/body parameters. A positive result is **supporting evidence**, not an XSS confirmation.
- `bounded_rate_limit_probe` — sends at most five baseline requests. A 429/503 response is **supporting evidence of throttling**, not proof of a rate-limit vulnerability.
- `cross_identity_compare` / `authorization_boundary_compare` — requires the analyst to select a second captured request as the comparison identity. For `cross_identity_compare` the candidate must reference a *different* object identifier for the same endpoint shape (found automatically, refused if more than one token differs); for `authorization_boundary_compare` it must be the same URL. Confirmation additionally requires an unauthenticated probe of the resource to come back denied/different from the protected response — this is what rules out "the resource is just public" rather than treating a same-URL, similar-response match alone as proof (that was the v4 flaw; corrected in v4.1). The identity labels remain an explicit analyst assertion; the decision logic itself lives in `IdentityCompareLogic` and has its own executable test suite independent of Burp.
- `workflow_replay_compare` — intentionally remains inconclusive until a typed state-sequence executor exists.

## Safety invariants

1. The source request must still exist and its SHA-256 fingerprint must exactly match the plan.
2. Burp's own scope decision must allow the source request.
3. Active plans require explicit analyst approval in the UI.
4. No generic model-controlled mutation API exists.
5. The harness accepts `confirmed=true` only from the exact registered `burp:<capability>` executor and only for capabilities currently authorized to confirm.
6. Reflection and throttling results are evidence states, not vulnerability confirmations.
7. Missing comparison identity produces `inconclusive`, never a guessed identity or synthesized credentials.

The current Burp API supports immutable request transformations such as `withParameter`, request construction, and `sendRequest`; the extension uses those typed APIs rather than hand-building arbitrary HTTP. See the official Montoya API documentation for `HttpRequest` and `Http.sendRequest`. 
