"""
Iterative (active) agent: bounded send -> observe -> adapt loop.

The specialist agents elsewhere in this harness are single-shot: one LLM call
over one captured exchange. This is the other mode -- an agent that actually
drives the target, adapting its payload to what it sees, the way a human tester
iterates. One "step" is a full send-a-request / read-the-response / decide
cycle. When it runs out of steps (or budget, or ideas) it HANDS BACK to the
orchestrator a structured result -- findings plus a handoff note of what it
tried and what still looks promising -- so another agent can pick up the thread
(the input the pivot/remember layer consumes).

Safety is the whole design, because an LLM in a loop against a live target is
exactly where blast radius gets away from you:

  - The model NEVER controls a raw URL or command. It emits a constrained
    action (mutate this param / set this header / stop) which the harness
    translates into a request DERIVED FROM THE CAPTURED EXCHANGE -- the same
    endpoint the tester already authorized analyzing. The model chooses payload
    *values* and *which bounded knob* to turn, not arbitrary destinations.
  - Every request is scope-checked against allowed_hosts, gated by safety_gate
    for mutating methods (inheriting the allow_mutating_replay opt-in), and
    paced by the global request throttle -- identical to the validator path.
  - Bounded three independent ways: step_budget (~250 cycles), the token
    effort_budget, and the global rate throttle.

Off by default; this is a fundamentally more active mode than the passive
pipeline and is opt-in per run.
"""
from __future__ import annotations
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

import global_throttle
from models import Finding, HttpExchange
from safety_gate import get_default_gate
# Reuse the exact, tested mutation helpers the sqlmap validator already uses --
# same bounded "change one param value on the captured request" envelope.
from validators.sqlmap import (
    _mutate_query_param, _mutate_json_param, _mutate_form_param,
    _query_top_level_params, _json_top_level_params, _form_top_level_params,
    _looks_like_json, _content_type_of,
)

if TYPE_CHECKING:
    from effort import EffortBudget

log = logging.getLogger("harness.iterative_agent")

_MAX_RESP_CHARS = 1200  # response summary fed back to the model, per step


@dataclass
class IterativeStep:
    n: int
    action: dict
    request_summary: str
    response_status: int | None
    response_summary: str
    blocked: str | None = None


@dataclass
class IterativeResult:
    agent: str
    findings: list[Finding] = field(default_factory=list)
    handoff_note: str = ""
    steps_used: int = 0
    stop_reason: str = ""            # "found" | "exhausted_steps" | "gave_up" | "budget" | "error"
    transcript: list[IterativeStep] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "findings": [f.model_dump() for f in self.findings],
            "handoff_note": self.handoff_note,
            "steps_used": self.steps_used,
            "stop_reason": self.stop_reason,
            "transcript": [
                {"n": s.n, "action": s.action, "request": s.request_summary,
                 "status": s.response_status, "response": s.response_summary, "blocked": s.blocked}
                for s in self.transcript
            ],
        }


_SYSTEM_PROMPT = """You are an iterative security-testing agent specializing in {specialty}.
You probe ONE captured HTTP endpoint by adapting your payload to each response.

Each turn, respond with ONLY a JSON object choosing exactly one action:

  {{"action":"mutate","location":"query|body","param":"<name>","value":"<payload>","thought":"<one line>"}}
     -- resend the captured request with one parameter's value replaced by your payload.
  {{"action":"set_header","name":"<header>","value":"<value>","thought":"<one line>"}}
     -- resend with a request header set/overridden (persists for later steps).
  {{"action":"stop","verdict":"found|not_found","thought":"<one line>",
    "finding":{{"vulnerability_class":"...","confidence":0.0-1.0,"severity":"info|low|medium|high|critical",
               "summary":"...","evidence":"...","suggested_test":"...","basis":"derived"}}}}
     -- stop. Include "finding" ONLY when verdict is "found".

Rules:
- You cannot choose the URL, host, or method -- only payload values and which bounded knob to turn.
- Adapt: read each response (status, length, body markers) and change your next payload accordingly.
- Confirm before claiming: a finding needs response evidence the injection/bypass actually landed,
  not just that a payload was accepted. If the evidence is weak, keep probing or stop "not_found".
- Stop as soon as you have confirmed the issue, or when you've genuinely run out of ideas.
- Output ONLY the JSON object, no prose around it."""


class IterativeAgent:
    def __init__(self, ollama, model: str, allowed_hosts: list[str], *, temperature: float = 0.2,
                 max_steps: int = 250):
        self.ollama = ollama
        self.model = model
        self.allowed_hosts = allowed_hosts or []
        self.temperature = temperature
        self.max_steps = max_steps
        self.gate = get_default_gate()

    def _host_allowed(self, url: str) -> bool:
        if not self.allowed_hosts:
            return True
        host = (urlsplit(url).hostname or "").lower()
        return any(host == h.lower() or host.endswith("." + h.lower()) for h in self.allowed_hosts)

    def _build_request(self, exchange: HttpExchange, action: dict, headers_state: dict) -> tuple:
        """Translate a constrained action into (method, url, headers, body),
        derived from the captured exchange. Returns (None, reason) if invalid."""
        method = exchange.method.upper()
        url = exchange.url
        body = exchange.request_body or ""
        headers = dict(headers_state)

        if action.get("action") == "set_header":
            name, value = action.get("name"), action.get("value")
            if not isinstance(name, str) or not isinstance(value, str):
                return None, "set_header requires string name/value"
            headers[name] = value
            return (method, url, headers, body), None

        # mutate
        loc, param, value = action.get("location"), action.get("param"), action.get("value")
        if loc not in ("query", "body") or not isinstance(param, str) or not isinstance(value, str):
            return None, "mutate requires location(query|body), param, value"
        if loc == "query":
            new_url = _mutate_query_param(url, param, value)
            if new_url is None:
                return None, f"query param {param!r} not present on the captured request"
            return (method, new_url, headers, body), None
        # body
        ct = _content_type_of(exchange)
        if _looks_like_json(body, ct):
            nb = _mutate_json_param(body, param, value)
        else:
            nb = _mutate_form_param(body, param, value)
        if nb is None:
            return None, f"body param {param!r} not present on the captured request"
        return (method, url, headers, nb), None

    def _mutable_params(self, exchange: HttpExchange) -> dict:
        ct = _content_type_of(exchange)
        body = exchange.request_body or ""
        body_params = (_json_top_level_params(body) if _looks_like_json(body, ct)
                       else _form_top_level_params(body))
        return {"query": _query_top_level_params(exchange.url), "body": body_params}

    async def _execute(self, method, url, headers, body) -> tuple:
        """Scope-check + safety-gate + throttle + send. Returns (status, text)
        or (None, reason-blocked)."""
        if not self._host_allowed(url):
            return None, f"blocked: {urlsplit(url).hostname} out of scope"
        if method != "GET":
            decision = self.gate.authorize(validator_name="iterative_agent", method=method, url=url, body=body)
            if not decision.allowed:
                return None, f"blocked by safety gate: {decision.reason}"
        try:
            await global_throttle.acquire()
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                resp = await client.request(method, url, headers=headers, content=body or None)
            return resp.status_code, (resp.text or "")[:_MAX_RESP_CHARS]
        except httpx.HTTPError as e:
            return None, f"request failed: {e.__class__.__name__}"

    async def run(self, exchange: HttpExchange, hypothesis: str, specialty: str,
                  step_budget: int = 250, effort_budget: "EffortBudget | None" = None) -> IterativeResult:
        budget = min(step_budget, self.max_steps)
        result = IterativeResult(agent=f"iterative:{specialty}")
        headers_state = {k: v for k, v in (exchange.request_headers or {}).items()
                         if k.lower() not in ("host", "content-length")}
        headers_state.setdefault("User-Agent", "harness-iterative-agent/1.0")

        system = _SYSTEM_PROMPT.format(specialty=specialty)
        history: list[str] = [
            f"HYPOTHESIS: {hypothesis}",
            f"ENDPOINT: {exchange.method} {exchange.url}",
            f"RESPONSE STATUS (captured baseline): {exchange.response_status}",
            f"MUTABLE PARAMETERS: {json.dumps(self._mutable_params(exchange))}",
        ]

        for step in range(1, budget + 1):
            if effort_budget is not None:
                allowed, reason = effort_budget.allow()
                if not allowed:
                    result.stop_reason = "budget"
                    result.handoff_note = f"Halted by effort budget at step {step}: {reason}"
                    break

            user = ("\n".join(history) +
                    "\n\nChoose your next action as a single JSON object.")
            try:
                if effort_budget is not None:
                    r = await self.ollama.chat_json_metered(
                        model=self.model, system_prompt=system, user_prompt=user, temperature=self.temperature)
                    from effort import CallKind
                    effort_budget.record(CallKind.ESCALATION, self.model, r.prompt_tokens, r.completion_tokens)
                    action = r.data
                else:
                    action = await self.ollama.chat_json(
                        model=self.model, system_prompt=system, user_prompt=user, temperature=self.temperature)
            except Exception as e:
                result.stop_reason = "error"
                result.handoff_note = f"LLM call failed at step {step}: {e}"
                break

            if not isinstance(action, dict):
                history.append(f"[step {step}] invalid action (not an object); try again.")
                continue

            kind = action.get("action")
            if kind == "stop":
                result.stop_reason = "found" if action.get("verdict") == "found" else "gave_up"
                fd = action.get("finding")
                if result.stop_reason == "found" and isinstance(fd, dict):
                    try:
                        result.findings.append(Finding(**{**fd, "confirmed": False}))
                    except Exception as e:
                        log.debug("iterative_agent: malformed finding on stop: %s", e)
                result.handoff_note = action.get("thought", "") or result.handoff_note
                result.steps_used = step - 1
                result.transcript.append(IterativeStep(step, action, "(stop)", None, ""))
                return result

            built, err = self._build_request(exchange, action, headers_state)
            if err:
                history.append(f"[step {step}] action rejected: {err}")
                result.transcript.append(IterativeStep(step, action, "(rejected)", None, err, blocked=err))
                continue
            method, url, headers, body = built
            if kind == "set_header":
                headers_state = headers  # persist

            status, text = await self._execute(method, url, headers, body)
            req_summary = f"{method} {url}" + (f" body={body[:80]}" if body else "")
            if status is None:
                history.append(f"[step {step}] {req_summary} -> {text}")
                result.transcript.append(IterativeStep(step, action, req_summary, None, text, blocked=text))
                continue
            resp_summary = f"HTTP {status}, {len(text)} bytes: {text[:400]}"
            history.append(f"[step {step}] {req_summary} -> {resp_summary}")
            result.transcript.append(IterativeStep(step, action, req_summary, status, text[:400]))

        result.steps_used = min(budget, len(result.transcript))
        if not result.stop_reason:
            result.stop_reason = "exhausted_steps"
            if not result.handoff_note:
                result.handoff_note = (f"Ran {result.steps_used} steps on {exchange.method} "
                                       f"{exchange.url} without confirming {specialty}; last responses in transcript.")
        return result
