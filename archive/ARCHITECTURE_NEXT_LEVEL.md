# Next-level architecture

The harness is deliberately moving away from “one LLM agent per vulnerability class”.
The durable abstraction is **hypothesis → capability → controlled execution → evidence → verdict**.

## Division of labor

- **Deterministic analyzers** parse HTTP, normalize parameters, identify reflection, cookies, redirects, content types, and fingerprints. They should not spend tokens rediscovering facts a parser can establish.
- **LLM agents** interpret those observations, form hypotheses, identify likely attack surfaces, and propose safe capabilities. They do not generate shell commands or arbitrary destinations.
- **Mature security tools** perform repetitive specialist validation when they are better than an LLM. sqlmap is the first example.
- **Burp** should become the execution plane for session-aware tests: identity comparison, authorization boundaries, workflow replay, race testing, bounded rate-limit probes, OAuth mutation, and Collaborator-backed callbacks.
- **The control plane** owns scope, approval, capabilities, provenance, evidence, and final verdicts.

## Test plans

An agent can produce a hypothesis such as “this looks like an IDOR”, but the durable output is a declarative `TestPlan`:

```text
capability: cross_identity_compare
source: captured exchange
execution_plane: burp
requires_approval: true
mutation: validator-defined
success_signals: independent evidence
```

There is intentionally no model-generated command, shell syntax, or arbitrary URL in a plan. The execution plane decides how the capability is implemented.

## Why this scales

Adding a new vulnerability methodology should usually mean adding either:

1. a deterministic observation primitive;
2. a reusable capability; or
3. an adapter for an established security tool.

It should **not** mean copying another large prompt and teaching an agent how to operate a scanner.

## Evidence model

A finding is a hypothesis until an independent validator produces evidence. `confirmed=true` is therefore a property of the evidence pipeline, not an LLM confidence score. A real advisory can establish that a package/version is vulnerable without establishing that the target actually deploys that package/version; deployment observation remains a separate claim.

## Execution safety

Active capabilities are approval-gated by default. Every active execution must inherit engagement scope, use the original captured exchange or Burp-managed state, have bounded resources, and return an explicit `confirmed`, `not_confirmed`, `skipped`, or `error` result.

## Long-term target

```text
Burp evidence
    ↓
Normalization / attack-surface graph
    ↓
LLM hypotheses + test plans
    ↓
Capability broker + scope/policy
    ↓
Burp replay / mature tools / deterministic validators
    ↓
Evidence graph
    ↓
Verdict + attack chains + analyst feedback
    ↓
Report
```

This is the architectural distinction between an LLM wrapper around scanners and a security-testing platform that uses an LLM where reasoning is genuinely useful.

## v3 execution-plane hardening

The Burp execution plane now uses typed capability executors. `reflection_context_validation` and `bounded_rate_limit_probe` produce supporting evidence without setting `confirmed=true`. `cross_identity_compare` / `authorization_boundary_compare` can confirm only after the analyst selects a comparison identity, an object-identifier mutation (IDOR) or same-URL replay (authz boundary) is executed with identity A's own session, and an unauthenticated baseline probe of the same resource comes back denied -- ruling out a public/non-personalized resource, which a same-URL-plus-similar-response match alone cannot do. The server additionally checks that the submitted executor exactly matches the registered capability. This keeps model-generated prose and arbitrary mutation values outside the confirmation boundary.
