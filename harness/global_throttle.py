"""
Global outbound-request throttle.

A single process-wide ceiling on how fast the harness sends requests to a
TARGET -- across every active path at once: the validators (CORS, sqlmap's
own excepted, recon, web-cache, etc.), active verification, autonomous
scope discovery, and (once it exists) the iterative agent loop. Unlike
rate_limiter.py, which paces Ollama/model calls, this paces the traffic the
harness aims at the application under test.

Why global, not per-validator: an engagement's real blast radius is the
aggregate request rate hitting the target, not any one component's rate.
Five agents and three validators each "politely" capped at 10 req/s still add
up to 80 req/s at the target. The tester sets one number -- a global ceiling --
and every outbound path draws from the same bucket.

The limiter BLOCKS (awaits) rather than rejecting: a throttled caller waits
its turn, so behavior is "slower", never "requests silently dropped". A rate
of 0 (or None) means unlimited -- the throttle is off and acquire() returns
immediately, so the default costs nothing.

Async token bucket, serialized by an asyncio.Lock. Configure once (from
config / the Burp setting); every send site does `await throttle.acquire()`
immediately before it sends.
"""
from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass


@dataclass
class _ThrottleStats:
    acquired: int = 0
    total_wait_s: float = 0.0
    max_wait_s: float = 0.0


class GlobalRequestThrottle:
    """Process-wide blocking token bucket for outbound target requests."""

    def __init__(self) -> None:
        self._rate: float = 0.0          # tokens (requests) per second; 0 = unlimited
        self._burst: float = 0.0         # bucket capacity
        self._tokens: float = 0.0
        self._last: float = time.monotonic()
        self._lock = asyncio.Lock()
        self._stats = _ThrottleStats()

    def configure(self, max_requests_per_second: float | None, burst: float | None = None) -> None:
        """Set the global ceiling. `max_requests_per_second` <= 0 or None turns
        the throttle OFF (unlimited). `burst` defaults to one second's worth of
        capacity (at least 1) so a short cluster of near-simultaneous callers
        isn't serialized more strictly than the sustained rate requires."""
        rate = float(max_requests_per_second or 0.0)
        self._rate = max(0.0, rate)
        if self._rate <= 0.0:
            self._burst = 0.0
            self._tokens = 0.0
            return
        self._burst = float(burst) if burst and burst > 0 else max(1.0, self._rate)
        # Start full so the first burst isn't penalized.
        self._tokens = self._burst
        self._last = time.monotonic()

    @property
    def enabled(self) -> bool:
        return self._rate > 0.0

    def _refill(self, now: float) -> None:
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last = now

    async def acquire(self) -> None:
        """Block until one request slot is available, then consume it. No-op
        (returns immediately) when the throttle is disabled."""
        if self._rate <= 0.0:
            return
        waited = 0.0
        async with self._lock:
            while True:
                now = time.monotonic()
                self._refill(now)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._stats.acquired += 1
                    self._stats.total_wait_s += waited
                    self._stats.max_wait_s = max(self._stats.max_wait_s, waited)
                    return
                # Sleep exactly until the next whole token accrues.
                deficit = 1.0 - self._tokens
                sleep_for = deficit / self._rate
                waited += sleep_for
                await asyncio.sleep(sleep_for)

    def stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "rate_per_second": self._rate,
            "burst": self._burst,
            "acquired": self._stats.acquired,
            "total_wait_s": round(self._stats.total_wait_s, 3),
            "max_wait_s": round(self._stats.max_wait_s, 3),
        }


# The process-wide singleton every outbound send site shares.
throttle = GlobalRequestThrottle()


async def acquire() -> None:
    """Module-level convenience: `await global_throttle.acquire()`."""
    await throttle.acquire()


def configure(max_requests_per_second: float | None, burst: float | None = None) -> None:
    throttle.configure(max_requests_per_second, burst)
