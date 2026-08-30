from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


class HttpExchange(BaseModel):
    """One captured request/response pair, as sent by the Burp extension."""
    url: str
    method: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_status: Optional[int] = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    # Free-text notes the analyst typed in Burp before sending, if any.
    analyst_note: str = ""


class ComponentCandidate(BaseModel):
    """
    A software component + version an agent noticed in an exchange --
    e.g. from a Server header, a JS library banner, or an exposed
    dependency manifest. This is a candidate for the orchestrator's
    deterministic known-vulnerability lookup, not a vulnerability claim
    on its own: agents extract candidates, they do not decide whether a
    version is vulnerable (see base_agent's common rules).
    """
    ecosystem: str  # e.g. "npm", "PyPI", "Maven", "RubyGems", "Go", "generic"
    name: str
    version: Optional[str] = None
    source: str = ""  # where it was seen, e.g. "Server header" or "package.json body"
    observed_in_exchange: bool = False  # independently verified against raw exchange text
    verification_note: str = ""


class Finding(BaseModel):
    """One structured claim made by a specialist agent."""
    vulnerability_class: str
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence: str
    suggested_test: str
    basis: str  # "derived" | "recalled" | "assumed" -- see agent prompts

    # Severity/taxonomy fields -- added after reviewing how comparable
    # tools (Strix, Xalgorix) report findings. Confidence answers "how
    # sure are we this is real"; severity answers "how much would it
    # matter if it is" -- two different axes a reader needs separately.
    severity: str = "info"  # "info" | "low" | "medium" | "high" | "critical"
    owasp_category: Optional[str] = None  # e.g. "A01:2021-Broken Access Control"

    # Populated by the orchestrator's critique pass (§6-style adversarial
    # review), not by the specialist agent itself. None until reviewed.
    original_confidence: Optional[float] = None
    review_verdict: Optional[str] = None  # "survived" | "downgraded" | "rejected"
    review_note: Optional[str] = None

    # True only when the harness has actually performed the suggested
    # confirming action (or another explicit verification path). LLM
    # reasoning alone never sets this.
    confirmed: bool = False
    validation_hints: list[str] = Field(default_factory=list)


class AgentReport(BaseModel):
    agent: str
    model: str
    findings: list[Finding] = Field(default_factory=list)
    components: list[ComponentCandidate] = Field(default_factory=list)
    raw_error: Optional[str] = None
    # Short hash of the exact system prompt used for this run (see
    # base_agent._prompt_version) -- lets a stored finding be traced back
    # to precisely which prompt version produced it, without hand-
    # maintained version numbers going stale the moment a prompt changes.
    prompt_version: str = ""


class AnalysisRequest(BaseModel):
    exchange: HttpExchange
    # If empty, the coordinator picks agents itself. If set, caller forces
    # a specific subset (e.g. user right-clicked "Test for SQLi only").
    force_agents: list[str] = Field(default_factory=list)
    # Default is False: when a component matches a known, disclosed
    # vulnerability, the harness stops there rather than spending an
    # additional model call trying to independently re-derive something
    # already established (see the top-level "known vs rediscover"
    # design). Set True to explicitly ask the harness to attempt
    # independent analysis anyway -- e.g. to look for exchange-specific
    # exploitability evidence beyond the generic advisory text. This is
    # the analyst's call to make, not a default the harness assumes.
    attempt_rediscovery: bool = False


class TestPlan(BaseModel):
    """A declarative request for independent verification.

    Plans contain capabilities and constrained mutation instructions, never
    shell commands or model-generated destination URLs. The Burp extension
    is the preferred execution plane for stateful/identity-aware plans.
    """
    id: str
    capability: str
    finding_class: str
    # Canonicalized category (see categories.py), distinct from
    # finding_class: finding_class is the LLM's original free-text label
    # (kept for display/traceability), category is the normalized key
    # everything downstream -- the coverage ledger, capability planning --
    # should actually join/group on. None when the free text didn't match
    # any known category (surfaced as such, not silently dropped).
    category: Optional[str] = None
    source_exchange_url: str
    mutation: dict[str, str] = Field(default_factory=dict)
    success_signals: list[str] = Field(default_factory=list)
    requires_approval: bool = True
    execution_plane: str = "burp"  # burp | local_tool
    rationale: str = ""
    source_exchange_hash: str = ""
    schema_version: str = "1"


class ValidationSubmission(BaseModel):
    plan_id: str
    status: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    confirmed: bool = False
    summary: str = ""
    evidence: str = ""
    executor: str = ""
    source_exchange_hash: str = ""


class ValidationReport(BaseModel):
    validator: str
    status: str
    finding_class: str
    confidence: float = 0.0
    confirmed: bool = False
    summary: str = ""
    evidence: str = ""


class AnalysisResponse(BaseModel):
    coordinator_model: str
    dispatched_agents: list[str]
    agent_reports: list[AgentReport]
    summary: str
    highest_confidence_finding: Optional[Finding] = None
    # How many findings were sent through the adversarial critique pass,
    # and how many survived/were downgraded/rejected -- a reader-visible
    # signal that review happened, distinct from just claiming it did.
    findings_reviewed: int = 0
    findings_rejected: int = 0
    validation_reports: list[ValidationReport] = Field(default_factory=list)
    test_plans: list[TestPlan] = Field(default_factory=list)
    # Real cumulative token spend for this assessment (across all
    # exchanges analyzed so far in this orchestrator's lifetime, not just
    # this one call) -- see effort.EffortBudget. budget_remaining is None
    # when no cap is configured (tracked but never blocking).
    effort_spent_tokens: int = 0
    effort_budget_remaining: Optional[int] = None
    effort_budget_warning: str = ""


class UrlEstimateItem(BaseModel):
    url: str
    # 0.0-1.0 triage/risk score if already scored (e.g. Burp's PathScorer
    # tier normalized, or a prior agent's confidence). None if the URL is
    # only known from spidering, not yet walked through.
    risk_score: Optional[float] = None
    category: Optional[str] = None


class EstimateRequest(BaseModel):
    urls: list[UrlEstimateItem]


class EffortStatus(BaseModel):
    mode: str
    total_tokens: Optional[int] = None
    spent_tokens: int = 0
    remaining_tokens: Optional[int] = None
    exhausted: bool = False
    breakdown: dict[str, int] = Field(default_factory=dict)


class IdentityCreateRequest(BaseModel):
    name: str
    role: str = "user"  # anonymous | user | admin | service
    notes: str = ""


class SessionCreateRequest(BaseModel):
    identity_id: str
    host: str
    exchange_hash: str
    label: str = ""


class SuppressFindingRequest(BaseModel):
    fingerprint: str
    reason: str = ""
