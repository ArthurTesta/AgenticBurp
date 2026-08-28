from __future__ import annotations
import json
import httpx
from dataclasses import dataclass


class OllamaError(RuntimeError):
    pass


@dataclass
class OllamaResult:
    """Parsed response body plus real token usage from the same call --
    verified against Ollama's actual /api/chat response shape (top-level
    prompt_eval_count / eval_count fields alongside "message" and "done"),
    not assumed. See effort.EffortLedger, which is what these numbers are
    for."""
    data: dict
    prompt_tokens: int
    completion_tokens: int


class OllamaClient:
    """
    Minimal wrapper around Ollama's /api/chat endpoint.
    Docs: https://github.com/ollama/ollama/blob/main/docs/api.md
    """

    def __init__(self, base_url: str, timeout_seconds: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def _chat(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> tuple[dict, dict]:
        """Shared implementation. Returns (parsed_json_body, raw_response_dict)
        so callers needing usage fields don't have to make a second call."""
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "format": "json",
            "stream": False,
            "options": {"temperature": temperature},
        }
        url = f"{self.base_url}/api/chat"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.post(url, json=payload)
        except httpx.ConnectError as e:
            raise OllamaError(
                f"Could not reach Ollama at {self.base_url}. "
                f"Is `ollama serve` running? ({e})"
            ) from e
        except httpx.TimeoutException as e:
            raise OllamaError(f"Ollama request timed out after {self.timeout_seconds}s") from e

        if resp.status_code != 200:
            raise OllamaError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:500]}")

        data = resp.json()
        content = data.get("message", {}).get("content", "")
        if not content:
            raise OllamaError(f"Ollama returned an empty message body: {data}")

        try:
            return json.loads(content), data
        except json.JSONDecodeError as e:
            raise OllamaError(
                f"Model '{model}' did not return valid JSON. "
                f"Raw content (truncated): {content[:500]}"
            ) from e

    async def chat_json(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> dict:
        """
        Calls the model and requires a JSON object back (Ollama's `format: json`
        mode). Returns the parsed dict. Raises OllamaError on failure --
        callers are responsible for turning that into a labeled, degraded
        result rather than pretending the call succeeded.
        """
        parsed, _raw = await self._chat(model, system_prompt, user_prompt, temperature)
        return parsed

    async def chat_json_metered(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> OllamaResult:
        """
        Same as chat_json, but also returns real token usage
        (prompt_eval_count / eval_count from Ollama's own response) so the
        caller can feed effort.EffortLedger with actual numbers instead of
        the unmeasured priors in effort._DEFAULT_TOKEN_ESTIMATE. Falls back
        to 0/0 if Ollama's response is missing these fields (older server
        versions, or a proxy that strips them) rather than raising --
        losing calibration data isn't worth failing an otherwise-successful
        call over.
        """
        parsed, raw = await self._chat(model, system_prompt, user_prompt, temperature)
        prompt_tokens = raw.get("prompt_eval_count", 0) or 0
        completion_tokens = raw.get("eval_count", 0) or 0
        return OllamaResult(data=parsed, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)

