from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import time
import uuid


class IdentityRole(str, Enum):
    ANONYMOUS = "anonymous"
    USER = "user"
    ADMIN = "admin"
    SERVICE = "service"


@dataclass
class Identity:
    """
    A named test identity (e.g. "Alice", "admin"), independent of any one
    captured exchange. Replaces the previous ad hoc pattern of tracking
    "Alice vs Bob vs admin" purely via which Burp exchange happened to be
    selected in a JOptionPane at cross-identity-compare time -- that
    still works for a single comparison, but has no persistent notion of
    "this identity" across the rest of an assessment.

    Deliberately does NOT store credential values -- see Session below
    and base_agent._redact_headers: this project already keeps secrets
    out of LLM prompts, and an Identity object storing raw passwords
    would undermine that. `session_ids` is a list of opaque Session ids
    a human (or the Burp extension, once wired) associates with this
    identity; the actual header/cookie evidence stays wherever it was
    captured (Burp's own history), this is only the label + relationship.
    """
    name: str
    role: IdentityRole = IdentityRole.USER
    notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)


@dataclass
class Session:
    """
    Links an Identity to a specific host and a specific captured
    exchange's fingerprint -- not the credential itself. `exchange_hash`
    is the same SHA-256 fingerprint planner.py/ValidationExecutor already
    compute for a captured request, so a Session is verifiably "this
    identity's session is the one captured in exchange X" without ever
    holding the token value.
    """
    identity_id: str
    host: str
    exchange_hash: str
    label: str = ""  # e.g. "logged in as Alice via /login"
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)
