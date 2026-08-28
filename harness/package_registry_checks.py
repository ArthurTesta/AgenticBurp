from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import quote
from datetime import datetime, timezone

import httpx

from models import ComponentCandidate

log = logging.getLogger("harness.package_registry_checks")

# This module integrates the *concept* behind Aikido's Safe Chain
# (github.com/AikidoSec/safe-chain), not its actual data feed: Safe
# Chain's malware intelligence (malware_predictions.json /
# malware_pypi.json, served from malware-list.aikido.dev) is not
# publicly documented at the schema level and isn't reachable from this
# environment, so it is not something this module can honestly claim to
# query. What IS reachable, public, and directly checkable is the same
# "minimum package age" signal Safe Chain applies by default (48 hours):
# a component published to its registry only hours or days ago is
# exactly the shape of a supply-chain-attack package (a malicious or
# typosquatted release that gets pulled once caught, so age itself is
# weak-but-real evidence). This queries the real npm/PyPI registries
# directly -- confirmed live against both while building this.
#
# This is explicitly a WEAKER, LOWER-CONFIDENCE signal than the
# known-vulnerability lookup in github_advisories.py: "published
# recently" is not "malicious", it's a prior worth raising, not a
# verdict. It ships as its own finding rather than folded into the
# known-vulnerability finding so the two kinds of evidence stay visibly
# distinct.

_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_REGISTRY = "https://pypi.org/pypi"

_NPM_LIKE_ECOSYSTEMS = {"npm", "javascript", "node"}
_PYPI_LIKE_ECOSYSTEMS = {"pypi", "python", "pip"}


@dataclass
class RegistryAgeResult:
    component: ComponentCandidate
    status: str  # "checked" | "not_found" | "unsupported_ecosystem" | "error"
    published_at: datetime | None = None
    age_days: float | None = None
    detail: str = ""


class PackageRegistryClient:
    def __init__(self, timeout_seconds: float = 15.0, minimum_age_days: float = 2.0):
        self.timeout_seconds = timeout_seconds
        # Safe Chain's default is 48 hours; matched here as the default,
        # configurable the same way github_advisories' behavior is.
        self.minimum_age_days = minimum_age_days

    async def check(self, component: ComponentCandidate) -> RegistryAgeResult:
        eco = component.ecosystem.lower().strip()
        if not component.name:
            return RegistryAgeResult(component=component, status="error", detail="no package name")

        if eco in _NPM_LIKE_ECOSYSTEMS:
            return await self._check_npm(component)
        if eco in _PYPI_LIKE_ECOSYSTEMS:
            return await self._check_pypi(component)
        return RegistryAgeResult(component=component, status="unsupported_ecosystem",
                                   detail=f"registry-age check only covers npm/PyPI, got '{component.ecosystem}'")

    async def _check_npm(self, component: ComponentCandidate) -> RegistryAgeResult:
        url = f"{_NPM_REGISTRY}/{quote(component.name, safe='')}"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = None
            for attempt in range(3):
                try:
                    resp = await client.get(url)
                except httpx.RequestError as e:
                    if attempt == 2:
                        return RegistryAgeResult(component=component, status="error", detail=f"network error: {e}")
                    await asyncio.sleep(0.25 * (2 ** attempt))
                    continue
                if resp.status_code not in (429, 500, 502, 503, 504) or attempt == 2:
                    break
                await asyncio.sleep(0.25 * (2 ** attempt))
        if resp is None:
            return RegistryAgeResult(component=component, status="error", detail="registry request failed")

        if resp.status_code == 404:
            return RegistryAgeResult(component=component, status="not_found",
                                       detail="package not found on npm registry")
        if resp.status_code != 200:
            return RegistryAgeResult(component=component, status="error",
                                       detail=f"npm registry returned HTTP {resp.status_code}")

        data = resp.json()
        version = component.version or data.get("dist-tags", {}).get("latest")
        time_str = data.get("time", {}).get(version) if version else None
        if not time_str:
            return RegistryAgeResult(component=component, status="not_found",
                                       detail=f"version {version!r} not found in npm registry's time data")

        published = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - published).total_seconds() / 86400
        return RegistryAgeResult(component=component, status="checked",
                                   published_at=published, age_days=age_days)

    async def _check_pypi(self, component: ComponentCandidate) -> RegistryAgeResult:
        url = f"{_PYPI_REGISTRY}/{quote(component.name, safe='')}/json"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = None
            for attempt in range(3):
                try:
                    resp = await client.get(url)
                except httpx.RequestError as e:
                    if attempt == 2:
                        return RegistryAgeResult(component=component, status="error", detail=f"network error: {e}")
                    await asyncio.sleep(0.25 * (2 ** attempt))
                    continue
                if resp.status_code not in (429, 500, 502, 503, 504) or attempt == 2:
                    break
                await asyncio.sleep(0.25 * (2 ** attempt))
        if resp is None:
            return RegistryAgeResult(component=component, status="error", detail="registry request failed")

        if resp.status_code == 404:
            return RegistryAgeResult(component=component, status="not_found",
                                       detail="package not found on PyPI")
        if resp.status_code != 200:
            return RegistryAgeResult(component=component, status="error",
                                       detail=f"PyPI returned HTTP {resp.status_code}")

        data = resp.json()
        version = component.version or data.get("info", {}).get("version")
        files = data.get("releases", {}).get(version, []) if version else []
        if not files:
            return RegistryAgeResult(component=component, status="not_found",
                                       detail=f"version {version!r} not found in PyPI release data")

        upload_time = files[0].get("upload_time_iso_8601")
        if not upload_time:
            return RegistryAgeResult(component=component, status="error", detail="no upload timestamp in PyPI response")

        published = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - published).total_seconds() / 86400
        return RegistryAgeResult(component=component, status="checked",
                                   published_at=published, age_days=age_days)
