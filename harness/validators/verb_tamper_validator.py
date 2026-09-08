"""
Verb-tampering / HTTP method access-control bypass (V15, WSTG-CONF-06).

Safe subset: read-only method alternates (HEAD, OPTIONS, GET) + method-override
headers (X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method). Confirms a
denial→2xx transition: an endpoint that denies the intended method (401/403) but
serves a substantive 2xx for a different method or override has a method-scoped
authorization hole.

Does NOT send blind PUT/DELETE (the mutating-method case is gated behind a
separate opt-in per LEG_DECISIONS.md). Active; scope-gated.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx

import global_throttle
from models import Finding, HttpExchange
from safety_gate import GatedAsyncClient, get_default_gate
from .base import Validator, ValidationResult
from .injection_targets import replay_headers

_OVERRIDE_HEADERS = ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method")
_SAFE_METHODS = ("HEAD", "OPTIONS", "GET")


class VerbTamperValidator(Validator):
    name = "verb_tamper"
    finding_classes = {"misconfig", "misconfiguration", "verb tamper", "verb_tamper",
                       "method tampering", "http method", "http_method"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange)

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "misconfig", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        url = exchange.url
        orig_method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        orig_status = exchange.response_status or 0

        if 200 <= orig_status < 300:
            return self._skip("original request already succeeded (2xx) — no denial to bypass")

        if orig_status not in (401, 403, 405):
            return self._skip(f"original status {orig_status} is not a denial (401/403/405)")

        for method in _SAFE_METHODS:
            if method == orig_method:
                continue
            try:
                await global_throttle.acquire()
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    resp = await client.request(method, url, headers=headers or None)
            except httpx.HTTPError:
                continue
            except Exception:
                continue
            if 200 <= resp.status_code < 300 and len(resp.text or "") > 10:
                return ValidationResult(
                    self.name, "confirmed", "misconfig", confidence=0.85, confirmed=True,
                    summary=f"Verb tamper bypass: {orig_method} returns {orig_status} but "
                            f"{method} returns {resp.status_code} with a substantive body.",
                    evidence=f"Original: {orig_method} {url} → {orig_status}. "
                             f"Alternate: {method} → {resp.status_code} ({len(resp.text)} bytes).")

        for override_header in _OVERRIDE_HEADERS:
            try:
                await global_throttle.acquire()
                h = dict(headers or {})
                h[override_header] = orig_method
                async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                            follow_redirects=False, verify=False) as client:
                    resp = await client.request("POST", url, headers=h)
            except httpx.HTTPError:
                continue
            except Exception:
                continue
            if 200 <= resp.status_code < 300 and len(resp.text or "") > 10:
                return ValidationResult(
                    self.name, "confirmed", "misconfig", confidence=0.80, confirmed=True,
                    summary=f"Method override bypass: POST with {override_header}: {orig_method} "
                            f"returns {resp.status_code} (original {orig_method} returns {orig_status}).",
                    evidence=f"Original: {orig_method} {url} → {orig_status}. "
                             f"Override: POST + {override_header}: {orig_method} → {resp.status_code}.")

        return ValidationResult(
            self.name, "not_confirmed", "misconfig", confidence=0.0, confirmed=False,
            summary="No verb-tamper bypass found with safe methods and override headers.",
            evidence=f"Tried {len(_SAFE_METHODS)-1} safe alternate methods + {len(_OVERRIDE_HEADERS)} "
                     f"override headers; none returned a substantive 2xx.")
