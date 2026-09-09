"""
Rate-limit / lockout absence confirmation leg (V4, WSTG-ATHN-03 / WSTG-BUSL-07).

Oracle (LEG_DECISIONS.md #4): N rapid attempts against an authentication (or
other should-be-limited) endpoint all reach the server with no 429 / lockout /
Retry-After after a threshold -> the endpoint enforces no rate limit.

The decision this leg encodes: "how many attempts = no rate limit, reconciled
with the mutating-burst ceiling." It requests a burst of `min_attempts` via the
safety gate's authorize_burst (so the operator's max_burst_size + the hard
ceiling still cap it), and confirms ONLY when it actually reached `min_attempts`
un-throttled -- otherwise it skips as inconclusive rather than claim "no limit"
from a burst the gate clamped below the floor. min_attempts defaults to 12
(> typical lockout thresholds of 5-10, <= the hard burst ceiling of 20).

SAFE subset: it REPLAYS THE CAPTURED REQUEST UNCHANGED, N times. A captured login
carries valid credentials, so N successful logins with no throttle is the finding
-- and valid logins don't lock the real account. It deliberately does NOT hammer
wrong credentials (that would risk locking a legitimate account -- the destructive
lockout-trigger variant needs explicit authorization). Mutating; the burst is
authorised once through the gate (needs allow_mutating_replay) then fired via a
plain client, exactly like the race-condition leg.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

import global_throttle
from models import Finding, HttpExchange
from safety_gate import get_default_gate
from .base import Validator, ValidationResult

# Language / signals that a rate limit or lockout DID engage -- any of these on
# any attempt refutes "no rate limiting".
_THROTTLE_MARKERS = re.compile(
    r"rate ?limit|too many (requests|attempts)|slow down|try again later|"
    r"temporarily (locked|blocked)|account (locked|is locked)|lockout|"
    r"throttl|429|retry.?after",
    re.IGNORECASE,
)


class RateLimitValidator(Validator):
    name = "rate_limit"
    finding_classes = {"rate_limit", "rate limit", "no rate limiting", "missing rate limit",
                       "missing rate limiting", "brute force", "brute_force", "brute-force",
                       "account lockout", "weak lockout", "lockout", "no lockout"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 min_attempts: int = 12):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self.min_attempts = max(2, int(min_attempts))

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        # A rate-limit/lockout test is about repeated ATTEMPTS -- a mutating auth
        # send (login/register/reset), not an idempotent GET.
        return (exchange.method or "GET").upper() not in ("GET", "HEAD", "OPTIONS")

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "rate_limit", summary=why)

    def _throttled(self, resp) -> bool:
        if resp is None:
            return False
        if resp.status_code in (429, 503):
            return True
        headers = getattr(resp, "headers", {}) or {}
        if any(k.lower() == "retry-after" for k in headers):
            return True
        return bool(_THROTTLE_MARKERS.search(resp.text or ""))

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        method = (exchange.method or "POST").upper()

        # Authorise the whole burst once -- respects the operator's max_burst_size
        # and the hard ceiling. If the gate clamps below the floor, we can't make
        # a "no rate limit after N" claim, so skip as inconclusive.
        decision = get_default_gate().authorize_burst(
            validator_name=self.name, method=method, url=exchange.url,
            requested_burst_size=self.min_attempts, body=exchange.request_body)
        if not decision.allowed:
            return self._skip(f"burst not authorized by safety gate: {decision.reason}")
        allowed = decision.allowed_burst_size
        if allowed < self.min_attempts:
            return self._skip(
                f"burst ceiling {allowed} is below min_attempts {self.min_attempts} -- raise "
                f"validators.max_burst_size to test rate limiting meaningfully (inconclusive)")

        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        content = exchange.request_body.encode() if exchange.request_body else None
        completed = 0
        statuses: dict[int, int] = {}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False,
                                         verify=False) as client:
                for _ in range(allowed):
                    await global_throttle.acquire()
                    try:
                        resp = await client.request(method, exchange.url,
                                                    headers=headers or None, content=content)
                    except httpx.HTTPError:
                        continue
                    completed += 1
                    statuses[resp.status_code] = statuses.get(resp.status_code, 0) + 1
                    if self._throttled(resp):
                        return ValidationResult(
                            self.name, "not_confirmed", "rate_limit", confidence=0.2, confirmed=False,
                            summary=f"Rate limiting / lockout engaged after {completed} attempt(s) -- "
                                    f"the endpoint IS limited.",
                            evidence=f"Attempt {completed} returned a throttle signal "
                                     f"(status/Retry-After/marker). Status distribution: {statuses}.")
        except Exception as e:
            return self._skip(f"burst failed: {e.__class__.__name__}")

        if completed >= self.min_attempts:
            return ValidationResult(
                self.name, "confirmed", "rate_limit", confidence=0.85, confirmed=True,
                summary=f"No rate limiting / lockout: {completed} rapid {method} attempts to "
                        f"{exchange.url} all reached the server with no 429, Retry-After, or "
                        f"lockout signal.",
                evidence=f"Replayed the captured request {completed} times un-throttled "
                         f"(>= min_attempts {self.min_attempts}). Status distribution: {statuses}. "
                         f"An endpoint enforcing a limit would have returned 429 / a lockout "
                         f"before this many attempts.")
        return self._skip(f"only {completed}/{allowed} attempts completed -- too few for a "
                          f"conclusive no-rate-limit claim")
