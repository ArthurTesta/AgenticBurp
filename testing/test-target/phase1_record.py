"""
Phase 1: run the REAL orchestrator.py against the captured exchanges,
with the OllamaClient's network-calling methods replaced by a recorder
that logs every (caller, exchange, system_prompt, user_prompt) it would
have sent to a real model, and returns an empty/neutral placeholder so
the pipeline completes without erroring.

This produces the real fast-path/coordinator dispatch decisions (those
are deterministic, unaffected by the fake client) and a full transcript
of exactly what every specialist agent, the coordinator (if reached),
and the critique pass (if reached) would actually see -- so the next
phase's answers are grounded in the harness's real prompt construction,
not reconstructed from memory of the code.
"""
import asyncio
import json
import sys
import yaml
from pathlib import Path

# test-target/ lives at testing/test-target/ -- two levels up is the
# project root, where harness/ lives.
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS_DIR = PROJECT_ROOT / "harness"
sys.path.insert(0, str(HARNESS_DIR))

import store
store._DB_PATH = "/tmp/pixelmart_test_state.db"  # don't touch the real harness DB
import cache
cache.init_cache(db_path="/tmp/pixelmart_test_cache.db")  # ditto for the exchange cache

import orchestrator as orch_mod
from models import HttpExchange

with open(HARNESS_DIR / "config.yaml") as f:
    config = yaml.safe_load(f)

orch = orch_mod.Orchestrator(config)

# Build a lookup of agent name -> specialty_prompt text, for identifying
# which agent a given system prompt belongs to (system prompt = shared
# _COMMON_RULES + "Your specialty:\n" + specialty_prompt).
agent_specialty = {name: agent.specialty_prompt for name, agent in orch.agent_manager.agents.items()}

transcript = []


CURRENT_EXCHANGE_INDEX = {"value": None}


async def fake_chat_json(model, system_prompt, user_prompt, temperature=0.1):
    caller = "unknown"
    if "adversarial reviewer" in system_prompt:
        caller = "critique"
    elif "coordinator in a security-testing harness" in system_prompt:
        caller = "coordinator"
    else:
        for name, specialty in agent_specialty.items():
            if specialty.strip() and specialty.strip() in system_prompt:
                caller = f"agent:{name}"
                break
    transcript.append({
        "exchange_index": CURRENT_EXCHANGE_INDEX["value"],
        "caller": caller,
        "model": model,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
    })
    if caller == "coordinator":
        return {"dispatch": [], "reason": "recording phase placeholder"}
    if caller == "critique":
        return {"reviews": []}
    return {"findings": [], "components": []}


async def fake_chat_json_metered(model, system_prompt, user_prompt, temperature=0.1):
    data = await fake_chat_json(model, system_prompt, user_prompt, temperature)
    return orch_mod.OllamaClient.__module__  # placeholder, replaced below


# chat_json_metered must return an OllamaResult, not a dict -- fix properly:
from ollama_client import OllamaResult


async def fake_chat_json_metered(model, system_prompt, user_prompt, temperature=0.1):
    data = await fake_chat_json(model, system_prompt, user_prompt, temperature)
    return OllamaResult(data=data, prompt_tokens=0, completion_tokens=0)


orch.ollama.chat_json = fake_chat_json
orch.ollama.chat_json_metered = fake_chat_json_metered


async def main():
    with open("/tmp/pixelmart_exchanges.json") as f:
        exchanges_raw = json.load(f)

    dispatch_summary = []
    for idx, e in enumerate(exchanges_raw):
        CURRENT_EXCHANGE_INDEX["value"] = idx
        exchange = HttpExchange(
            url=e["url"],
            method=e["method"],
            request_headers=e["request_headers"],
            request_body=e["request_body"],
            response_status=e["response_status"],
            response_headers=e["response_headers"],
            response_body=e["response_body"],
        )
        result = await orch.analyze(exchange)
        dispatch_summary.append({
            "exchange_index": idx,
            "label": e["label"],
            "url": e["url"],
            "dispatched_agents": result.dispatched_agents,
        })

    with open("/tmp/pixelmart_transcript.json", "w") as f:
        json.dump(transcript, f, indent=2)
    with open("/tmp/pixelmart_dispatch.json", "w") as f:
        json.dump(dispatch_summary, f, indent=2)

    print(f"Recorded {len(transcript)} would-be LLM calls -> /tmp/pixelmart_transcript.json")
    print(f"Dispatch summary -> /tmp/pixelmart_dispatch.json\n")
    for d in dispatch_summary:
        print(f"  {d['label']}")
        print(f"    -> dispatched: {d['dispatched_agents']}")


asyncio.run(main())
