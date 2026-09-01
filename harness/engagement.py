"""
Engagement state -- the shared spine the discrete capabilities hang off.

Every other module here is a leaf: it takes an input and returns a result and
forgets. That makes a good toolbox and a bad agent -- nothing lets a crawl, an
access matrix, an LLM rating, and a finding inform ONE picture of the target so
the next action can be chosen from all of them at once. This module is that
picture.

An `EngagementState` is a per-host graph of:
  - SURFACE: every known endpoint, carrying whatever signals we've gathered
    about it -- a static path tier (PathScorer, from Burp), an LLM structure
    rating (surface_prioritizer), the per-role access matrix (role_crawl), and
    any findings the agents/validators produced for it.
  - IDENTITIES: the roles/credentials in play and HOW each was obtained (seeded
    by the tester vs. derived from a finding) -- the substrate the closed loop
    (slice 2) will re-crawl from.

Its one job today is FUSION: collapse those separate, currently-disjoint signals
into a single, auditable "test-next" ranking, so the worklist reflects
everything known -- "reachable by anonymous but shaped like admin" outranks "a
static high tier with nothing else behind it," and an endpoint already validated
drops down the list. The score is a transparent weighted sum with per-endpoint
reasons (same discipline as resource_governor), never an opaque number.

Pure and deterministic: ingest_* mutate the state, fusion is arithmetic, no LLM
call and no network. Persistence is a JSON snapshot per host (see store).
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_SEV_W = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1}
_TIER_W = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1, "unscored": 0.1}

# Path shapes that read as privileged/sensitive -- used to flag the high-value
# anomaly "a low-trust role can reach something that looks admin-only".
_PRIVILEGED = re.compile(
    r"/(admin|administrator|manage|management|config|configuration|settings|internal|debug|"
    r"actuator|console|dashboard|billing|payment|invoice|account|users?|profile|report|export|"
    r"backup|token|secret|key|password|role|permission|privilege)(s)?(/|$)",
    re.IGNORECASE,
)

_NUM_SEG = re.compile(r"/\d+(?=/|$)")
_HEXISH = re.compile(r"/[0-9a-fA-F]{12,}(?=/|$)")


def normalize_path(url_or_path: str) -> str:
    """A stable key that aligns a crawl's normalized path with a finding's
    concrete URL: strip scheme/host/query, collapse numeric and long-hex
    segments to {id} (so /orders/42 and /orders/{id} map together)."""
    s = url_or_path or ""
    if "://" in s:
        parts = urlsplit(s)
        s = parts.path or "/"
    else:
        s = s.split("?", 1)[0].split("#", 1)[0]
    s = _HEXISH.sub("/{id}", s)
    s = _NUM_SEG.sub("/{id}", s)
    if len(s) > 1 and s.endswith("/"):
        s = s[:-1]
    return s or "/"


def _looks_privileged(path: str) -> bool:
    return bool(_PRIVILEGED.search(path or ""))


@dataclass
class SurfaceEndpoint:
    method: str
    path: str                         # normalized key path
    path_tier: str | None = None      # PathScorer tier (from Burp)
    llm_priority: str | None = None   # surface_prioritizer ai_priority
    llm_score: float | None = None    # surface_prioritizer ai_score 0..1
    access: dict = field(default_factory=dict)          # role -> status
    reachable_roles: list = field(default_factory=list)  # substantive 2xx
    object_scoped: bool = False
    findings: list = field(default_factory=list)         # [{class, severity, confidence, confirmed}]
    status: str = "discovered"        # discovered | analyzed | validated

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"

    def best_finding(self) -> dict | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: (
            1 if f.get("confirmed") else 0, _SEV_W.get((f.get("severity") or "info").lower(), 0.1),
            f.get("confidence", 0.0)))

    def add_finding(self, f: dict) -> None:
        """Attach a finding, de-duped by vulnerability_class: a later
        confirmation or higher-confidence read supersedes an earlier hypothesis
        rather than piling up duplicates."""
        slim = {
            "vulnerability_class": f.get("vulnerability_class", ""),
            "severity": f.get("severity", "info"),
            "confidence": f.get("confidence", 0.0),
            "confirmed": bool(f.get("confirmed", False)),
        }
        for existing in self.findings:
            if existing["vulnerability_class"] == slim["vulnerability_class"]:
                if slim["confirmed"] or slim["confidence"] >= existing["confidence"]:
                    existing.update(slim)
                return
        self.findings.append(slim)

    def fused_score(self) -> tuple[float, list[str]]:
        """Collapse every signal into one 'worth testing next' value with the
        reasons that drove it. Higher = attack value still on the table."""
        score = 0.0
        reasons: list[str] = []

        bf = self.best_finding()
        if bf:
            sev = _SEV_W.get((bf.get("severity") or "info").lower(), 0.1)
            if bf.get("confirmed"):
                score += 1.0 * sev
                reasons.append(f"confirmed {bf.get('vulnerability_class', 'finding')} (sev {bf.get('severity')})")
            else:
                score += 0.6 * sev * float(bf.get("confidence", 0.0) or 0.0)
                reasons.append(f"unconfirmed {bf.get('vulnerability_class', 'finding')} @ {bf.get('confidence', 0):.2f}")

        if self.llm_score is not None:
            score += 0.4 * float(self.llm_score)
            reasons.append(f"LLM rating {self.llm_priority or ''} {self.llm_score:.2f}".strip())

        if self.path_tier:
            score += 0.3 * _TIER_W.get(self.path_tier.lower(), 0.1)
            reasons.append(f"path tier {self.path_tier}")

        # Access-matrix anomalies -- the highest-signal cross-source insight.
        low_trust_reaches = any(r.lower() in ("anonymous", "user") for r in self.reachable_roles)
        if low_trust_reaches and _looks_privileged(self.path):
            score += 0.7
            reasons.append("low-trust role reaches a privileged-looking path (authz gap)")
        if self.object_scoped and any(r.lower() not in ("anonymous",) for r in self.reachable_roles):
            score += 0.3
            reasons.append("object-scoped endpoint reachable by an identity (IDOR candidate)")
        if _looks_privileged(self.path) and not self.findings and not self.reachable_roles:
            score += 0.15
            reasons.append("privileged-looking path, not yet tested")

        # Already validated -> mostly done; keep a little so it stays visible.
        if self.status == "validated":
            score *= 0.3
            reasons.append("already validated (deprioritized)")

        return round(score, 4), reasons

    def to_dict(self) -> dict:
        s, reasons = self.fused_score()
        return {
            "method": self.method, "path": self.path, "status": self.status,
            "path_tier": self.path_tier, "llm_priority": self.llm_priority, "llm_score": self.llm_score,
            "access": self.access, "reachable_roles": self.reachable_roles,
            "object_scoped": self.object_scoped, "findings": self.findings,
            "score": s, "reasons": reasons,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SurfaceEndpoint":
        return cls(
            method=d.get("method", "GET"), path=d.get("path", "/"),
            path_tier=d.get("path_tier"), llm_priority=d.get("llm_priority"), llm_score=d.get("llm_score"),
            access=d.get("access", {}) or {}, reachable_roles=d.get("reachable_roles", []) or [],
            object_scoped=bool(d.get("object_scoped", False)), findings=d.get("findings", []) or [],
            status=d.get("status", "discovered"),
        )


@dataclass
class EngagementState:
    host: str
    endpoints: dict = field(default_factory=dict)   # key "METHOD path" -> SurfaceEndpoint
    identities: list = field(default_factory=list)  # [{name, role, source, obtained_from}]

    # --- ingest: every source writes into the SAME model ---

    def _ep(self, method: str, path: str) -> SurfaceEndpoint:
        key = f"{method.upper()} {path}"
        ep = self.endpoints.get(key)
        if ep is None:
            ep = SurfaceEndpoint(method=method.upper(), path=path)
            self.endpoints[key] = ep
        return ep

    def ingest_endpoints(self, paths, method: str = "GET") -> int:
        """From a plain /crawl: add discovered paths as GET endpoints."""
        n = 0
        for p in paths or []:
            self._ep(method, normalize_path(p))
            n += 1
        return n

    def ingest_role_crawl(self, result: dict) -> int:
        """From /crawl-roles: the access matrix + object-scoping per endpoint,
        plus the derived IDOR findings."""
        n = 0
        for e in result.get("endpoints", []) or []:
            ep = self._ep(e.get("method", "GET"), normalize_path(e.get("path", "/")))
            ep.access = e.get("by_role", {}) or {}
            ep.reachable_roles = e.get("reachable_roles", []) or []
            ep.object_scoped = bool(e.get("object_scoped", False))
            n += 1
        for f in result.get("idor_findings", []) or []:
            # idor_findings carry a validation_hint "cross_identity_compare:<path>"
            for hint in f.get("validation_hints", []) or []:
                if hint.startswith("cross_identity_compare:"):
                    path = normalize_path(hint.split(":", 1)[1])
                    self._ep("GET", path).add_finding(f)
        return n

    def ingest_prioritization(self, items) -> int:
        """From /prioritize (surface_prioritizer LLM ratings)."""
        n = 0
        for it in items or []:
            method = it.get("method", "GET")
            path = normalize_path(it.get("url", "/"))
            ep = self._ep(method, path)
            ep.llm_priority = it.get("ai_priority")
            try:
                ep.llm_score = float(it.get("ai_score")) if it.get("ai_score") is not None else None
            except (TypeError, ValueError):
                ep.llm_score = None
            n += 1
        return n

    def ingest_findings(self, url: str, method: str, findings) -> int:
        """From /analyze (agents + validators): attach findings to the endpoint,
        promoting its status."""
        ep = self._ep(method, normalize_path(url))
        n = 0
        for f in findings or []:
            ep.add_finding(f if isinstance(f, dict) else _finding_to_dict(f))
            n += 1
        if any(fd.get("confirmed") for fd in ep.findings):
            ep.status = "validated"
        elif ep.findings:
            ep.status = "analyzed"
        return n

    def ingest_identity(self, name: str, role: str, source: str = "seed", obtained_from: str = "") -> None:
        if any(i["name"] == name for i in self.identities):
            return
        self.identities.append({"name": name, "role": role, "source": source, "obtained_from": obtained_from})

    # --- the fused output ---

    def worklist(self, limit: int = 25) -> list:
        ranked = sorted(self.endpoints.values(), key=lambda e: e.fused_score()[0], reverse=True)
        return [e.to_dict() for e in ranked[:limit]]

    def summary(self) -> dict:
        by_status: dict[str, int] = {}
        for e in self.endpoints.values():
            by_status[e.status] = by_status.get(e.status, 0) + 1
        return {"host": self.host, "endpoint_count": len(self.endpoints),
                "by_status": by_status, "identities": self.identities}

    def to_dict(self) -> dict:
        return {"host": self.host,
                "endpoints": {k: v.to_dict() for k, v in self.endpoints.items()},
                "identities": self.identities}

    @classmethod
    def from_dict(cls, d: dict) -> "EngagementState":
        st = cls(host=d.get("host", ""))
        for k, v in (d.get("endpoints", {}) or {}).items():
            st.endpoints[k] = SurfaceEndpoint.from_dict(v)
        st.identities = d.get("identities", []) or []
        return st


def _finding_to_dict(f) -> dict:
    return {
        "vulnerability_class": getattr(f, "vulnerability_class", ""),
        "severity": getattr(f, "severity", "info"),
        "confidence": getattr(f, "confidence", 0.0),
        "confirmed": getattr(f, "confirmed", False),
    }
