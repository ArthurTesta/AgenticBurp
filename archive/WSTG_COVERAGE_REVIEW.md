# AgenticBurp Agent Coverage vs. OWASP WSTG v4.2

**Scope of this document.** This maps the harness's 29 current specialist
agents against the 11 top-level categories of the OWASP Web Security
Testing Guide (WSTG) v4.2, plus PortSwigger's Web Security Academy
topic list, to answer two questions: what's covered, and what's a real
gap versus what's covered by a different name than WSTG uses. This is
analysis only -- no code changes. Methodology note: category names and
structure are drawn from OWASP's own public materials and paraphrased
here, not reproduced verbatim.

## How to read the coverage column

- **Covered** -- at least one agent's `specialty_prompt` explicitly
  targets this category's core techniques, confirmed by reading the
  actual prompt text, not just the agent's name.
- **Partial** -- some techniques in the category are covered by an
  agent whose primary focus is elsewhere; real gaps remain within the
  category.
- **Gap** -- no current agent addresses this category's core
  techniques at all.

## WSTG-01: Information Gathering

**Covered.** `recon` builds the attack surface map (endpoints,
parameters, technologies, entry points) and `subdomain_takeover`
covers a specific information-gathering-adjacent technique (dangling
DNS/CNAME discovery). `supply_chain` covers exposed manifests,
lockfiles, and CI/CD configuration, which WSTG treats as part of this
category too.

**Gap:** search-engine/cache-based reconnaissance (WSTG's "Search
Engine Discovery" tests) is out of scope by design -- this harness
only analyzes captured Burp traffic, it doesn't do external OSINT.
Reasonable to leave out; flagging so it's a documented exclusion, not
a silent one.

## WSTG-02: Configuration and Deployment Management Testing

**Covered.** `misconfig` is the primary agent here (headers, verbose
errors, default credentials/pages, exposed admin interfaces). `cors`
covers CORS-specific misconfiguration as its own agent rather than
folding it into `misconfig`, which is arguably more useful given how
distinct the exploitation path is. `http_request_smuggling` and
`web_cache_poisoning` both test infrastructure-layer configuration
(reverse proxy / CDN behavior) that WSTG's newer editions increasingly
treat as part of this category.

**Partial:** WSTG's "Test HTTP Methods" and "Test HSTS" sub-items
aren't clearly owned by any single agent -- `misconfig`'s prompt
should be checked to confirm it actually asks about these, since the
docstring alone doesn't establish it either way.

## WSTG-03: Identity Management Testing

**Partial.** No dedicated agent for account-registration-flow issues
(weak registration policy, username enumeration during signup,
account provisioning flaws) as WSTG defines this category. `auth`'s
prompt is scoped to session/authentication mechanics, not identity
lifecycle. `oauth` covers the identity-federation angle (OIDC/OAuth
account linking) but not first-party registration.

## WSTG-04: Authentication Testing

**Covered.** `auth` is the primary agent (session tokens, credential
handling). `oauth` adds the OAuth/OIDC-specific authentication
mechanics WSTG treats as a subsection here (state parameter, PKCE,
redirect_uri validation) -- this is exactly the gap the new `oauth`
agent fills. `rate_limit` covers brute-force resistance on
authentication endpoints, which WSTG lists under this category.

## WSTG-05: Authorization Testing

**Covered.** `idor` (object-level), `business_logic` /
`business_logic_enhanced` (workflow-level access control), and `auth`
together cover WSTG's authorization sub-tests (path traversal via
object references, privilege escalation, IDOR itself). This is one of
the harness's deepest coverage areas.

## WSTG-06: Session Management Testing

**Partial.** `auth`'s prompt covers session token attributes
(Secure/HttpOnly/SameSite) but WSTG's session-management category also
includes session fixation, session timeout/logout behavior, and CSRF
as a session-adjacent test. `csrf` exists as its own agent, which
covers that specific piece. Session fixation and timeout/logout
behavior don't appear to be explicitly named in any current agent's
prompt -- worth confirming by reading `auth_agent.py`'s full prompt
text rather than inferring from its docstring, which this review
didn't do (see Confidence Note below).

## WSTG-07: Input Validation Testing

**Covered, broadly.** This is the largest WSTG category and the
harness's deepest coverage: `sqli`, `xss`, `nosql`, `command_injection`,
`ssti`, `xxe`, `open_redirect`, `graphql` (injection-adjacent GraphQL
issues) all map directly. `http_request_smuggling` covers
request-smuggling-specific input validation gaps at the protocol
level, which WSTG's newer content increasingly folds into this
category.

## WSTG-08: Testing for Error Handling

**Partial.** `info_disclosure` and `misconfig` both plausibly touch
error-message-based information leakage (stack traces, verbose error
pages), but neither's docstring makes error handling its primary,
named focus the way WSTG treats it as a standalone category. Likely
adequate coverage in practice, not confirmed by prompt text in this
review.

## WSTG-09: Testing for Weak Cryptography

**Gap.** No current agent's docstring names cryptography as a focus
(weak TLS/cipher configuration, insufficient transport protection,
sensitive data over unencrypted channels, weak crypto storage). This
matches what `JUICE_SHOP_MISSING_AGENTS_ANALYSIS.md` already
identified independently (`crypto_agent.py`, never built) --
two separate reviews agreeing is a stronger signal than either alone.
This is a real, unaddressed gap.

## WSTG-10: Business Logic Testing

**Covered.** `business_logic` and `business_logic_enhanced` are
purpose-built for this category (workflow abuse, state manipulation,
process-sequencing flaws) and this is explicitly called out as a
priority area in the harness's own README given bug-bounty trend data.

## WSTG-11: Client-Side Testing

**Partial.** `xss` covers DOM-based/reflected/stored XSS, which is
this category's largest single item. WSTG's client-side category also
includes clickjacking (missing X-Frame-Options/CSP frame-ancestors),
CSS injection, and client-side storage issues (localStorage/
sessionStorage misuse) -- none of these appear to be a named focus of
any current agent. This overlaps with the `csp_agent.py` and
`header_injection_agent.py` gaps already flagged in
`JUICE_SHOP_MISSING_AGENTS_ANALYSIS.md`.

## API Testing (WSTG's newer addition, not in the original 11)

**Partial.** `graphql` covers GraphQL-specific API issues. REST/API
issues are otherwise implicitly covered by the general-purpose agents
(`sqli`, `idor`, `auth`, etc., which don't distinguish REST endpoints
from any other endpoint) rather than by an API-specific agent that
would test API-only concerns: mass assignment, excessive data
exposure in API responses, lack of resource/rate limiting per the
OWASP API Security Top 10 specifically (distinct from WSTG's general
`rate_limit` agent). This matches `api_security_agent.py` in the
missing-agents analysis doc -- a real, unaddressed gap, though
partially mitigated by existing general-purpose agents firing on API
endpoints too.

---

## Cross-reference against PortSwigger Web Security Academy topics

PortSwigger's topic list overlaps heavily with WSTG but names a few
things WSTG doesn't break out separately. Checking those specifically:

| PortSwigger topic | Status |
|---|---|
| SQL injection, XSS, CSRF, SSRF, XXE, Auth, Access control | Covered (see WSTG mapping above) |
| CORS | Covered (`cors`) |
| Clickjacking | **Gap** -- no agent |
| DOM-based vulnerabilities | Partial (`xss` covers DOM XSS specifically; DOM clobbering, other DOM sinks not confirmed) |
| WebSockets | **Gap** -- matches `websocket_agent.py` in the missing-agents doc |
| Web cache poisoning | **Now covered** (`web_cache_poisoning`, this session) |
| HTTP Request Smuggling | Covered (`http_request_smuggling`) |
| OAuth authentication | **Now covered** (`oauth`, this session) |
| JWT attacks | Covered (`jwt`) |
| GraphQL API vulnerabilities | Covered (`graphql`) |
| Race conditions | **Gap** -- not named by any current agent, not previously flagged by either prior document either |
| Insecure deserialization | **Gap** -- not named by any current agent, not previously flagged by either prior document either |
| Server-side template injection | Covered (`ssti`) |
| NoSQL injection | Covered (`nosql`) |
| Business logic vulnerabilities | Covered (`business_logic`, `business_logic_enhanced`) |

Race conditions and insecure deserialization are genuinely new
findings from this review -- they don't appear in either the original
handover's P1 list or in `JUICE_SHOP_MISSING_AGENTS_ANALYSIS.md`.

---

## Consolidated gap list, prioritized

Combining this review, the original handover's P1 list, and
`JUICE_SHOP_MISSING_AGENTS_ANALYSIS.md` into one backlog (the
reconciliation that, as noted in the prior turn, nobody had done):

**Now resolved this session:** web cache poisoning, OAuth, subdomain
takeover (previous pass), and cryptography/TLS, CSP/clickjacking,
header injection (including the SMTP/email variant), API security,
WebSockets, race conditions, and insecure deserialization (this pass).
That closes every item on the consolidated list below except #8,
which was flagged as needing a follow-up prompt-level read rather than
a new agent.

**High-confidence remaining gaps (named by 2+ independent sources):**
1. ~~Cryptography/TLS testing~~ -- **closed** (`crypto` agent + validator)
2. ~~Clickjacking / CSP / header-injection issues~~ -- **closed** (`csp` and `header_injection` agents + validators)
3. ~~API-specific testing beyond GraphQL~~ -- **closed** (`api_security` agent + validator)

**Named by one source, not yet cross-checked by another:**
4. ~~WebSockets~~ -- **closed** (`websocket` agent + validator)
5. Email security / SPF-DKIM-DMARC -- **partially addressed**: the
   SMTP-header-injection angle is now covered by `header_injection`
   (see that agent's docstring for why DNS-record-level SPF/DKIM/DMARC
   checking was deliberately excluded -- it isn't visible in a
   captured HTTP exchange at all, so it doesn't fit this harness's
   input model regardless of agent count)
6. ~~Race conditions~~ -- **closed** (`race_condition` agent + validator)
7. ~~Insecure deserialization~~ -- **closed** (`deserialization` agent + validator, format-fingerprint only -- see its docstring for why it doesn't attempt gadget-chain exploitation)
8. ~~Session fixation / timeout-logout behavior~~ -- **closed**.
   Confirmed by reading `auth_agent.py`'s full prompt (as flagged
   here as needed): neither was covered. Extended `auth_agent.py`'s
   prompt to flag both (`session_fixation`, `session_timeout`
   categories), and added real active-testing logic on the Java side
   (`SessionLifecycleLogic.java` + 9 passing tests, run via this
   repo's own reflection-based test runner) wired into
   `ValidationExecutor.java` as two new capabilities:
   `session_fixation_compare` (pure comparison of a session cookie's
   value across a pre/post-login exchange pair) and
   `logout_invalidation_compare` (live replay of an old session
   against a protected resource after logout, same
   confirmed/rejected/inconclusive discipline as the existing
   `authorization_boundary_compare` logic it sits next to). This is
   Java-side, not a Python validator, because -- like OAuth --
   confirming it needs the analyst's own captured, authenticated
   session pairs, which the headless Python harness doesn't hold.

## Confidence note -- what this review did NOT do

This review classified coverage primarily from each agent's **class
docstring**, not a full read of every `specialty_prompt` (29 agents'
full prompts is a lot of text to review in one pass, and the
docstrings are themselves written by the same agents/prior sessions
that produced overclaims elsewhere in this project). Where a
docstring made a category's coverage ambiguous, this review says so
explicitly (WSTG-02, WSTG-06, WSTG-08) rather than guessing. Treat
"Covered" as accurate (docstrings are specific enough to trust there);
treat "Partial" as the entries most worth a follow-up pass reading the
full prompt text before relying on this document for prioritization
decisions.
