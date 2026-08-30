from __future__ import annotations
import os
import logging
import asyncio
from dataclasses import dataclass, field

import httpx

from models import ComponentCandidate

log = logging.getLogger("harness.github_advisories")

_API_BASE = "https://api.github.com"

# GitHub's advisory ecosystem values differ slightly from common package-
# manager names -- this is the mapping actually documented by GitHub's
# REST API for GET /advisories?ecosystem=. Anything not in here is passed
# through as-is (lets an agent's "generic" guess still attempt a lookup;
# it'll just return nothing if the value isn't one GitHub recognizes).
_ECOSYSTEM_MAP = {
    "npm": "npm", "node": "npm", "javascript": "npm",
    "pypi": "pip", "python": "pip",
    "maven": "maven", "java": "maven",
    "rubygems": "rubygems", "ruby": "rubygems",
    "go": "go", "golang": "go",
    "nuget": "nuget", ".net": "nuget", "dotnet": "nuget",
    "composer": "composer", "php": "composer",
    "rust": "rust", "cargo": "rust",
    "swift": "swift",
    "actions": "actions", "github-actions": "actions",
}


@dataclass
class AdvisoryMatch:
    ghsa_id: str
    cve_id: str | None
    summary: str
    severity: str  # "low"|"moderate"|"high"|"critical" per GitHub's scale
    vulnerable_range: str
    url: str
    version_string_appears_in_range: bool  # cheap, approximate signal only


@dataclass
class LookupResult:
    component: ComponentCandidate
    status: str  # "matched" | "no_known_advisory" | "error" | "skipped_no_name"
    matches: list[AdvisoryMatch] = field(default_factory=list)
    detail: str = ""


class GitHubAdvisoryClient:
    """
    Thin client for GitHub's public Security Advisory REST API
    (GET /advisories). This is the "known" half of the known-vs-rediscover
    split: a deterministic lookup against an authoritative external
    database, run instead of asking an LLM to recall whether a version is
    vulnerable. It answers "does a disclosed advisory exist for this
    package" -- it does NOT attempt precise semver-range containment
    (see note in lookup()), because getting that subtly wrong and
    reporting it with false confidence would be worse than not
    attempting it and saying so.

    Rate limits, confirmed live against this API while building this:
    unauthenticated requests are capped at 60/hour and that ceiling is
    trivial to hit -- a token via GITHUB_TOKEN (env) or config raises it
    to 5000/hour. Without a token this feature will mostly report
    "error: rate_limited" rather than useful results; that's surfaced
    explicitly rather than silently treated as "no known advisory".
    """

    def __init__(self, token: str | None = None, timeout_seconds: float = 15.0):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.timeout_seconds = timeout_seconds

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def lookup(self, component: ComponentCandidate) -> LookupResult:
        if not component.name:
            return LookupResult(component=component, status="skipped_no_name")

        ecosystem = _ECOSYSTEM_MAP.get(component.ecosystem.lower().strip(), component.ecosystem)
        params = {"ecosystem": ecosystem, "affects": component.name, "per_page": "10"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = None
                for attempt in range(3):
                    try:
                        resp = await client.get(f"{_API_BASE}/advisories", params=params, headers=self._headers())
                    except httpx.RequestError as e:
                        if attempt == 2:
                            return LookupResult(component=component, status="error",
                                                detail=f"network error reaching GitHub Advisory API: {e}")
                        await asyncio.sleep(0.25 * (2 ** attempt))
                        continue
                    if resp.status_code not in (429, 500, 502, 503, 504) or attempt == 2:
                        break
                    await asyncio.sleep(0.25 * (2 ** attempt))
        except Exception as e:
            return LookupResult(component=component, status="error", detail=f"GitHub lookup failed: {e}")

        if resp is None:
            return LookupResult(component=component, status="error", detail="GitHub lookup failed without a response")
        if resp.status_code == 403 or (resp.status_code == 429):
            return LookupResult(component=component, status="error",
                                 detail="GitHub API rate-limited this lookup. Set GITHUB_TOKEN "
                                        "(env var) or github_advisories.token in config.yaml -- "
                                        "unauthenticated requests are capped at 60/hour and that "
                                        "ceiling is easy to exhaust.")
        if resp.status_code != 200:
            return LookupResult(component=component, status="error",
                                 detail=f"GitHub API returned HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            data = resp.json()
        except Exception as e:
            return LookupResult(component=component, status="error",
                                 detail=f"could not parse GitHub API response: {e}")

        matches: list[AdvisoryMatch] = []
        for advisory in data:
            for vuln in advisory.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                if pkg.get("name", "").lower() != component.name.lower():
                    continue
                vrange = vuln.get("vulnerable_version_range", "") or ""
                appears = bool(component.version) and component.version in vrange
                matches.append(AdvisoryMatch(
                    ghsa_id=advisory.get("ghsa_id", "unknown"),
                    cve_id=advisory.get("cve_id"),
                    summary=advisory.get("summary", ""),
                    severity=advisory.get("severity", "unknown"),
                    vulnerable_range=vrange,
                    url=advisory.get("html_url", ""),
                    version_string_appears_in_range=appears,
                ))

        if matches:
            return LookupResult(component=component, status="matched", matches=matches)
        return LookupResult(component=component, status="no_known_advisory")
