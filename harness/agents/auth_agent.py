from .base_agent import BaseAgent


class AuthAgent(BaseAgent):
    name = "auth"

    @property
    def specialty_prompt(self) -> str:
        return """
Authentication and session management. Look for:
- Session tokens/cookies missing Secure, HttpOnly, or SameSite attributes
  (only assess what's actually visible in the response headers shown).
- Predictable-looking tokens (short, sequential, low-entropy, timestamp-
  based) versus opaque high-entropy ones.
- Sensitive actions (login, password reset, MFA, account changes) that
  appear to lack CSRF protection (no token/nonce field visible in a
  state-changing form/request).
- Verbose authentication error responses that could support username
  enumeration (different messages/timing/status for "user not found" vs
  "wrong password" -- note if this exchange alone can't establish that,
  since it requires comparing two different login attempts).
- Password reset or token endpoints where the token appears in the URL
  (and therefore in logs/referrer headers) rather than the body.
- Trust-boundary bypasses involving security-sensitive headers or middleware:
  Referer/Origin/Host-derived authorization assumptions, internal-only
  headers such as X-Forwarded-For/X-Original-URL/X-Rewrite-URL, and route
  middleware that appears to make an authorization decision from client-
  supplied metadata. Do not claim a bypass from the header's presence alone;
  suggest removing/spoofing the header and comparing the authorization result.

Be explicit when a finding requires a second exchange to confirm (e.g.
enumeration requires comparing two different usernames) versus when it's
visible in this exchange alone (e.g. missing Secure flag on a cookie over
HTTPS).
"""
