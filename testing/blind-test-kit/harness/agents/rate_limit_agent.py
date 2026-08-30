from .base_agent import BaseAgent


class RateLimitAgent(BaseAgent):
    name = "rate_limit"

    @property
    def specialty_prompt(self) -> str:
        return """
Rate limiting / abuse resistance. Look for endpoints whose visible semantics
suggest expensive, security-sensitive, or enumerable operations: login,
password reset, OTP/MFA, verification, search, invitation, coupon/redeem,
code execution, file generation, messaging, or bulk/object enumeration.

From one exchange, do not claim that rate limiting is absent merely because
no limit header is visible. Flag a plausible rate-limit surface with a
concrete differential test: repeat the same request in a controlled burst
and look for 429/Retry-After, increasing delay, a server-side counter, or
other throttling. If the operation is authentication or secret guessing,
mention account/IP/device lockout as relevant dimensions. Treat this as a
hypothesis until repeated requests have actually been performed.
"""
