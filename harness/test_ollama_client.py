import json
import unittest
import httpx

from ollama_client import OllamaClient, OllamaError


_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _make_client(handler) -> OllamaClient:
    client = OllamaClient(base_url="http://fake-ollama:11434")

    class PatchedAsyncClient(_REAL_ASYNC_CLIENT):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            super().__init__(*args, **kwargs)

    import ollama_client as mod
    mod.httpx.AsyncClient = PatchedAsyncClient
    return client


class ChatJsonMeteredTests(unittest.IsolatedAsyncioTestCase):
    async def test_extracts_real_prompt_eval_count_and_eval_count(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "message": {"content": json.dumps({"findings": []})},
                "done": True,
                "prompt_eval_count": 742,
                "eval_count": 88,
            })
        client = _make_client(handler)
        result = await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")
        self.assertEqual(result.data, {"findings": []})
        self.assertEqual(result.prompt_tokens, 742)
        self.assertEqual(result.completion_tokens, 88)

    async def test_missing_usage_fields_falls_back_to_zero_not_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "message": {"content": json.dumps({"ok": True})},
                "done": True,
                # no prompt_eval_count / eval_count -- older server or stripping proxy
            })
        client = _make_client(handler)
        result = await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")
        self.assertEqual(result.prompt_tokens, 0)
        self.assertEqual(result.completion_tokens, 0)
        self.assertEqual(result.data, {"ok": True})

    async def test_chat_json_unmetered_still_returns_plain_dict(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "message": {"content": json.dumps({"dispatch": ["sqli"]})},
                "done": True,
                "prompt_eval_count": 500,
                "eval_count": 40,
            })
        client = _make_client(handler)
        result = await client.chat_json(model="m", system_prompt="s", user_prompt="u")
        self.assertEqual(result, {"dispatch": ["sqli"]})
        self.assertNotIsInstance(result, tuple)

    async def test_invalid_json_content_raises_ollama_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": {"content": "not json"}, "done": True})
        client = _make_client(handler)
        with self.assertRaises(OllamaError):
            await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")

    async def test_non_200_status_raises_ollama_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal error")
        client = _make_client(handler)
        with self.assertRaises(OllamaError):
            await client.chat_json_metered(model="m", system_prompt="s", user_prompt="u")


if __name__ == "__main__":
    unittest.main()
