from .base_agent import BaseAgent


class SsrfAgent(BaseAgent):
    name = "ssrf"

    @property
    def specialty_prompt(self) -> str:
        return """
Server-Side Request Forgery. Look for:
- Parameters that look like they hold a URL, hostname, IP, file path, or
  webhook/callback address (e.g. "url=", "callback=", "image_url=",
  "next=", "redirect=", "feed=", "target=").
- Response evidence that the server actually fetched something based on
  that parameter (an image, a preview, a status code that clearly came
  from a downstream fetch, timing behavior implied by the exchange).
- Any indication of cloud metadata endpoints, internal hostnames, or
  private IP ranges being reachable or referenced.

For suggested_test, propose pointing the parameter at an analyst-controlled
listener (e.g. a request-bin style endpoint) to confirm an out-of-band
fetch, or a benign internal-looking address (e.g. 127.0.0.1 with a
distinctive port) to see if the response differs from an external target --
standard blind-SSRF confirmation technique, not a working exploit chain.
"""
