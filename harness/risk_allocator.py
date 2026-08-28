from __future__ import annotations
from dataclasses import dataclass, field


_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1,
}


@dataclass
class RiskScore:
    """
    expected_risk = P(vulnerable) x impact-if-real. `probability` can come
    from either side of the pipeline depending on when this is computed:
    a pre-dispatch triage prior (e.g. Burp's PathScorer tier, normalized
    to 0-1) before any agent has looked at the URL, or an agent's own
    post-dispatch confidence once a finding exists. Both are legitimate
    inputs to the same formula -- this class doesn't care which produced
    the number, only that the caller is honest about which one it is via
    the `source` field, since a pre-dispatch prior and a post-dispatch
    confidence carry different amounts of actual evidence and shouldn't
    be silently treated as interchangeable by a reader of a report.

    `cost` is a relative cost estimate (e.g. tokens from
    effort.EffortLedger.average_tokens for this finding's category) --
    defaults to 1.0, which makes ranking identical to a cost-blind
    expected_risk ranking when costs aren't supplied or are all equal.
    Ranking by value_density (expected_risk / cost) rather than raw risk
    means two findings with identical risk but very different retry cost
    (a one-shot sqlmap confirmation vs. an XSS finding needing several
    payload rounds) are no longer treated as equal priority.
    """
    category: str
    url: str
    probability: float
    severity: str
    source: str = "unspecified"  # "triage_prior" | "agent_confidence" | "unspecified"
    cost: float = 1.0
    expected_risk: float = field(init=False)
    value_density: float = field(init=False)

    def __post_init__(self) -> None:
        p = max(0.0, min(1.0, self.probability))
        self.expected_risk = p * _SEVERITY_WEIGHT.get(self.severity, _SEVERITY_WEIGHT["info"])
        self.value_density = self.expected_risk / max(self.cost, 1e-9)


def rank(scores: list[RiskScore]) -> list[RiskScore]:
    return sorted(scores, key=lambda s: s.value_density, reverse=True)


def allocate_retry_budget(
    scores: list[RiskScore],
    *,
    max_rounds_top: int = 3,
    max_rounds_rest: int = 1,
    top_fraction: float = 0.3,
) -> dict[tuple[str, str], int]:
    """
    Maps (category, url) -> retry rounds RetryPolicy.max_default_attempts
    should be set to for that finding, ranked by expected_risk and spent
    top-down: the top `top_fraction` of findings by expected_risk get
    `max_rounds_top`; everything else gets `max_rounds_rest`.

    Deliberately a simple greedy split, not a knapsack against the actual
    token budget -- effort.estimate_for_urls / EffortBudget is where
    total spend actually gets bounded. This only decides WHERE effort
    goes within whatever budget exists, not how much total effort there
    is; conflating the two would make a change to the token budget
    silently change which findings get investigated, which is a much
    harder thing for an operator to reason about than two independent,
    separately-inspectable numbers.
    """
    ranked = rank(scores)
    if not ranked:
        return {}
    n_top = max(1, round(len(ranked) * top_fraction))
    return {
        (s.category, s.url): (max_rounds_top if i < n_top else max_rounds_rest)
        for i, s in enumerate(ranked)
    }
