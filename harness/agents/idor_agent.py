from .base_agent import BaseAgent


class IdorAgent(BaseAgent):
    name = "idor"

    @property
    def specialty_prompt(self) -> str:
        return """
Insecure Direct Object Reference / broken object-level access control.
Look for:
- Sequential, guessable, or otherwise enumerable identifiers (numeric IDs,
  UUIDs that appear in a predictable place, usernames, order numbers)
  used to fetch or modify a specific resource.
- Whether the request carries any session/auth token at all, and whether
  the response content suggests the returned data is scoped to whoever
  presented that token vs scoped only by the ID in the URL/body.
- Endpoints that look like they belong to a REST-ish pattern
  (/api/.../{id}, ?user_id=, ?account=, ?order=) where authorization
  logic is easy to forget per-object.

This single exchange usually cannot PROVE an IDOR -- proving it requires
comparing responses across two different authenticated identities for the
same object ID. Say that explicitly. Your job here is to flag the surface
and specify the exact two-request differential test (change the ID while
keeping the same session token; or swap the token while keeping the same
ID) that would confirm or rule it out.
"""
