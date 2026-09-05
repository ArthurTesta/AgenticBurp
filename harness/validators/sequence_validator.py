"""
Stateful sequence leg -- Phase 3 (the missing confirmation SHAPE).

Every existing leg confirms by replaying ~one request and diffing the response.
That shape structurally cannot catch a bug whose effect shows up on a LATER,
DIFFERENT request: mass-assignment where a privileged field is silently accepted
(not echoed in the write's own response), self-assignment escalation, or a value
stored now and read back with new authority. The single-shot mass-assignment
probe in api_security even documents its own blind spot -- "a field silently
accepted but not echoed back would not be caught."

This leg is the A->verify-B differential that closes it:
  1. BASELINE read  -- GET the resource, record whether the privileged fields are set.
  2. MUTATE (A)     -- send the write with canonical privileged fields injected.
  3. VERIFY read (B)-- GET the resource AGAIN; if a privileged field is now set that
                       was not set in the baseline, the write both took AND persisted,
                       proven by an INDEPENDENT read -- not the mutation's own echo.

One mutating write (all candidate fields injected at once), bracketed by two
GETs, so it respects max_mutating_requests_per_finding. Scope-gated; the mutating
send is routed through the safety gate (needs validators.allow_mutating_replay).
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

import httpx

import global_throttle
from models import Finding, HttpExchange
from safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from validators.sqlmap import _looks_like_json, _content_type_of

# Canonical privilege/authority fields to inject. value = the privileged value.
_PRIV_FIELDS = {
    "role": "admin", "roles": "admin", "account_type": "admin", "privilege": "admin",
    "is_admin": True, "isAdmin": True, "admin": True, "is_staff": True, "isStaff": True,
    "is_superuser": True, "superuser": True, "verified": True, "isVerified": True,
    "email_verified": True, "approved": True,
}


def _is_priv(value, priv) -> bool:
    """Whether a response value counts as the privileged value we injected --
    tolerant of bool vs "true" string and case."""
    if value is None:
        return False
    if isinstance(priv, bool):
        return value is True or str(value).strip().lower() == "true"
    return str(value).strip().lower() == str(priv).strip().lower()


class SequenceValidator(Validator):
    name = "sequence"
    finding_classes = {"mass_assignment", "mass assignment", "privilege_escalation",
                       "privilege escalation", "api_security", "api security",
                       "broken_access_control"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def _json_object(self, body: str):
        try:
            obj = json.loads(body)
        except (ValueError, TypeError):
            return None
        return obj if isinstance(obj, dict) else None

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        if not super().applies(finding, exchange):
            return False
        if (exchange.method or "").upper() not in ("POST", "PUT", "PATCH"):
            return False
        return (_looks_like_json(exchange.request_body or "", _content_type_of(exchange))
                and self._json_object(exchange.request_body or "") is not None)

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "mass_assignment", summary=why)

    def _not_confirmed(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "not_confirmed", "mass_assignment",
                                confidence=0.0, confirmed=False, summary=why)

    async def _get_json(self, client, url, headers):
        await global_throttle.acquire()
        resp = await client.request("GET", url, headers=headers or None)
        try:
            return resp.status_code, json.loads(resp.text or "")
        except (ValueError, TypeError):
            return resp.status_code, None

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        method = (exchange.method or "").upper()
        base_body = self._json_object(exchange.request_body or "")
        if base_body is None:
            return self._skip("request body is not a JSON object")
        # Fields not already privileged in the ORIGINAL request body.
        candidates = {f: v for f, v in _PRIV_FIELDS.items() if not _is_priv(base_body.get(f), v)}
        if not candidates:
            return self._skip("request already carries the privileged fields")

        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("content-length", "host")}
        headers.setdefault("Content-Type", "application/json")
        try:
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                # 1. baseline read
                b_status, baseline = await self._get_json(client, exchange.url, headers)
                if not isinstance(baseline, dict):
                    return self._skip(f"resource not readable as a JSON object for a "
                                      f"differential (GET -> {b_status})")
                cands = {f: v for f, v in candidates.items() if not _is_priv(baseline.get(f), v)}
                if not cands:
                    return self._skip("privileged fields already set on the resource; "
                                      "no differential to observe")
                # 2. mutate (A): inject all candidate privileged fields in ONE write.
                try:
                    await global_throttle.acquire()
                    await client.request(method, exchange.url, headers=headers,
                                         content=json.dumps({**base_body, **cands}))
                except SafetyGateBlocked as e:
                    return self._skip(f"mutating replay not authorized: {e.decision.reason}")
                # 3. verify read (B): independent GET -- did any field persist?
                v_status, after = await self._get_json(client, exchange.url, headers)
                if not isinstance(after, dict):
                    return self._not_confirmed(f"verification read returned no JSON object "
                                               f"(GET -> {v_status})")
                flipped = [f for f, v in cands.items()
                           if _is_priv(after.get(f), v) and not _is_priv(baseline.get(f), v)]
        except httpx.HTTPError as e:
            return self._skip(f"request failed: {e.__class__.__name__}")

        if flipped:
            return ValidationResult(
                self.name, "confirmed", "mass_assignment", confidence=0.9, confirmed=True,
                summary=f"Mass-assignment / privilege escalation confirmed: field(s) {flipped} "
                        f"became privileged after a write and PERSISTED across an independent re-read.",
                evidence=f"Baseline GET showed {flipped} not privileged; after a {method} with those "
                         f"field(s) injected, a fresh GET shows them set. Proven by the write->re-read "
                         f"differential -- catching a silent accept the single-shot echo check misses.")
        return self._not_confirmed(
            "no injected privileged field persisted across the write->re-read differential")
