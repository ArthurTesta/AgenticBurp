from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class AttemptStatus(str, Enum):
    CONFIRMED = "confirmed"
    SUPPORTED = "supported"       # partial signal, short of confirmed -- feeds the suspicion heuristic below
    NOT_CONFIRMED = "not_confirmed"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class Action(str, Enum):
    RETRY_DEFAULT = "retry_default"          # try again with a genuinely new payload, same model
    ESCALATE = "escalate"                    # switch to the stronger model, exactly once
    HANDOVER_MANUAL = "handover_manual"      # stop; surface to the operator
    STOP_INCONCLUSIVE = "stop_inconclusive"  # stop; no special operator alert
    STOP_CONFIRMED = "stop_confirmed"


@dataclass
class Attempt:
    status: AttemptStatus
    model: str
    escalated: bool
    payload: str | None = None
    confidence: float = 0.0
    note: str = ""


@dataclass
class RetryPolicy:
    """
    Bounds how many times a finding gets re-tested before this harness
    stops trusting repeated self-re-assertion and hands off -- to a
    stronger model once, then to the operator if warranted, otherwise to
    an honest "inconclusive."

    Why this exists: asking a model "are you sure?" against identical
    evidence tends to produce a re-assertion, not new information -- that
    is not verification (see HANDOVER.md's core principle: a check must
    touch something the original didn't). This policy does not, by
    itself, prevent that -- it only bounds HOW MANY chances a
    default-model attempt gets before something has to change. It is the
    caller's job (see orchestrator.py's wiring) to make every RETRY_DEFAULT
    actually use a different payload (from payload_library, or its LLM
    fallback once that's exhausted) rather than re-asking the same
    question -- decide() has no way to enforce that itself, since it only
    sees outcomes, not how each attempt's input was constructed.

    max_default_attempts: attempts on the default model, each required
        (by the caller) to use a different payload, before escalating.
    suspicion_confidence_threshold / suspicion_severities: what counts as
        "high suspicion" if neither the default model nor the escalated
        model can confirm. If met, HANDOVER_MANUAL instead of a silent
        STOP_INCONCLUSIVE -- an unconfirmed high-severity, high-prior-
        confidence finding, or one where at least one attempt reached
        SUPPORTED (a real partial signal, not nothing), is exactly the
        case where silently dropping it risks the analyst never seeing
        something real. A low-severity or low-confidence finding that
        never showed any partial signal does not get this treatment --
        surfacing every dead end to the operator would train them to
        ignore the flag, defeating its purpose.
    """
    max_default_attempts: int = 3
    suspicion_confidence_threshold: float = 0.55
    suspicion_severities: tuple[str, ...] = ("high", "critical")

    def decide(self, attempts: list[Attempt], original_confidence: float, original_severity: str) -> Action:
        if not attempts:
            return Action.RETRY_DEFAULT

        last = attempts[-1]
        if last.status == AttemptStatus.CONFIRMED:
            return Action.STOP_CONFIRMED

        default_attempts = [a for a in attempts if not a.escalated]
        escalated_attempts = [a for a in attempts if a.escalated]

        if escalated_attempts:
            # Already escalated once -- this is the final decision point,
            # not another retry loop. "Escalate once" is a hard contract:
            # decide() never returns ESCALATE a second time regardless of
            # how many escalated attempts exist, so a caller bug that
            # calls decide() again after escalating can't spiral into
            # repeated escalation.
            suspicious = self.is_suspicious(attempts, original_confidence, original_severity)
            return Action.HANDOVER_MANUAL if suspicious else Action.STOP_INCONCLUSIVE

        if len(default_attempts) < self.max_default_attempts:
            return Action.RETRY_DEFAULT

        return Action.ESCALATE

    def is_suspicious(self, attempts: list[Attempt], original_confidence: float, original_severity: str) -> bool:
        any_partial_signal = any(a.status == AttemptStatus.SUPPORTED for a in attempts)
        high_prior = (
            original_confidence >= self.suspicion_confidence_threshold
            and original_severity in self.suspicion_severities
        )
        return any_partial_signal or high_prior
