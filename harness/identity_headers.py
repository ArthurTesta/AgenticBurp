"""
In-memory, NEVER-persisted transient credential store for tester-fed
cross-identity (Autorize-style) authorization testing.

The harness deliberately never writes session tokens to disk (see identity.py /
store.Session: a Session records a fingerprint, "not the credential itself…
without ever holding the token value"). The cross-identity validator, however,
needs another identity's real session headers at run time to replay a request as
that identity and see whether an access control actually holds.

This module holds those headers ONLY in process memory, for the lifetime of the
run -- exactly like Autorize's configured low-privilege cookie -- and provides no
persistence path whatsoever. It is cleared on restart. The tester populates it
(e.g. via POST /identities/session-headers); nothing here is ever logged, cached,
or written to a DB.
"""
from __future__ import annotations
import threading

# host -> {identity_name: {"role": str, "headers": dict}}
_STORE: dict[str, dict[str, dict]] = {}
_LOCK = threading.Lock()


def set_identity(host: str, name: str, headers: dict, role: str = "user") -> None:
    """Register (or replace) an identity's transient session headers for a host."""
    with _LOCK:
        _STORE.setdefault(host, {})[name] = {"role": role, "headers": dict(headers or {})}


def identities_for_host(host: str) -> list[dict]:
    """All identities configured for a host, each as {name, role, headers}."""
    with _LOCK:
        return [{"name": n, "role": v["role"], "headers": dict(v["headers"])}
                for n, v in _STORE.get(host, {}).items()]


def has_identities(host: str) -> bool:
    with _LOCK:
        return bool(_STORE.get(host))


def clear(host: str | None = None) -> None:
    """Forget transient credentials -- for one host, or all of them."""
    with _LOCK:
        if host is None:
            _STORE.clear()
        else:
            _STORE.pop(host, None)
