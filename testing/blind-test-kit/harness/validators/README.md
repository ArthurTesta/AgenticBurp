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

The registry is intentionally generic. `SqlmapValidator` is the first adapter.
Future adapters should follow the same contract rather than adding another
agent prompt that reimplements an existing security tool.

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
