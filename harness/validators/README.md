# Validator layer

The harness deliberately separates **hypothesis generation** from **verification**.

Agents are allowed to say:

> "This exchange looks like a SQL injection candidate."

They are not allowed to turn that hypothesis into an arbitrary shell command,
URL, or autonomous scan. A validator receives the original `HttpExchange` and
the structured finding and decides whether an independent test can confirm it.

## Why this exists

This is the main architectural step beyond "one LLM per vulnerability class":
LLMs become planners/evidence extractors while mature security tooling and
small deterministic programs do the repetitive, high-confidence work.

The registry is intentionally generic. `SqlmapValidator` was the first adapter;
the registry now holds ~20 (`registry.py` is the source of truth) — sqlmap plus
cross-identity, browser-XSS, JWT-forge, XXE, and SSRF (the six "confirmation legs"),
and further checks for CORS, CSP/clickjacking, crypto/TLS, OAuth/OIDC, header
injection/CRLF, HTTP request smuggling, web cache poisoning, subdomain takeover,
WebSocket/CSWSH, race conditions, API security/mass-assignment, and (passive-only)
deserialization. New adapters should follow the same contract rather than adding
another agent prompt that reimplements an existing security tool.

Each validator declares a `finding_classes` set and an `active` flag (`base.py`).
All are `active` (send live requests, gated by `validators.active_enabled`) except
`deserialization`, which is passive local inspection. The `analyze()` path runs the
whole registry via `ValidatorRegistry.for_finding`; the engagement graph loop's
`_confirm` dispatcher uses the six legs only.

Active validators are disabled by default. When enabled, they must:

1. operate on the captured exchange, not model-generated targets;
2. obey the engagement scope;
3. have bounded time/resource settings;
4. return evidence and an explicit confirmation status;
5. never raise severity merely because a model requested a validation.

The long-term direction is for Burp itself to become the execution plane for
session-aware/differential tests, with the harness acting as the reasoning and
planning control plane. That would let validators reuse Burp's authenticated
sessions, cookies, proxy configuration, Collaborator context, and Repeater
request machinery instead of building a second HTTP client stack.
