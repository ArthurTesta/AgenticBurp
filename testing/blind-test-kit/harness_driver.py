"""
harness_driver.py -- run the REAL Burp LLM Harness orchestrator against
a captured set of HTTP exchanges, with yourself substituting for the LLM
at every call site (agents, coordinator, critique). Ollama doesn't need
to be reachable for this.

This is target-agnostic: it knows nothing about what's on the other end
of the exchanges you feed it. All the target-specific work (exploring
the app, deciding what requests to send, reading the real prompts and
writing genuine answers) happens in your own capture script and answers
file, not in this one.

THREE-PHASE WORKFLOW
=====================

Phase 1 -- RECORD: run your captured exchanges through the real
orchestrator with a fake LLM client that just records every prompt it
would have sent and returns an empty placeholder, so the pipeline
completes without erroring. This gives you the real dispatch decisions
(fast_path is deterministic, unaffected by the fake client) and the
exact, real prompt text every agent/coordinator/critique call would see.

    python harness_driver.py record \\
        --exchanges my_exchanges.json \\
        --out-transcript /tmp/transcript.json \\
        --out-dispatch /tmp/dispatch.json

Phase 2 -- ANSWER: read /tmp/transcript.json yourself. For each entry,
you (the person or agent running this) act as that specialist agent:
read ONLY the evidence shown in that entry's user_prompt (don't use
outside knowledge of the target), and decide what a disciplined
specialist would report. Write your answers into a Python file that
defines a function `get_answer(exchange_index: int, agent_name: str) -> dict`
returning `{"findings": [...], "components": [...]}` in the harness's
real Finding/ComponentCandidate schema (see models.py). See
answers_template.py in this kit for the exact shape and a worked empty
example.

Phase 3 -- RUN: run the same exchanges through the real orchestrator
again, this time with your answers wired in. This exercises the REAL
critique pass, known-vulnerability lookup, cross-exchange chaining, and
caching on top of your answers -- none of that is simulated.

    python harness_driver.py run \\
        --exchanges my_exchanges.json \\
        --answers my_answers.py \\
        --out-results /tmp/results.json

EXCHANGE FILE FORMAT
=====================
A JSON list of objects, each with: label, method, url, request_headers
(dict), request_body (string), response_status (int), response_headers
(dict), response_body (string). See exchange_template.json in this kit.

WHY THIS EXISTS
================
Testing this harness against a target whose vulnerabilities are already
publicly documented (write-ups, blog posts, previous training data) makes
it impossible to tell whether a "confirmed" finding came from genuine
reasoning over the evidence or from recognizing a familiar target. This
tool lets you drive the REAL harness code (dispatch, critique, chaining,
caching, known-vuln lookup) against any target while substituting your
own reasoning for the LLM calls, so you get a real signal on the
architecture even without a live model.
"""
from __future__ import annotations
import argparse
import asyncio
import importlib.util
import json
import re
import sys
from pathlib import Path

HARNESS_DIR = Path(__file__).parent / "harness"
sys.path.insert(0, str(HARNESS_DIR))


def load_config():
    import yaml
    with open(HARNESS_DIR / "config.yaml") as f:
        return yaml.safe_load(f)


def build_orchestrator(state_db: str, cache_db: str):
    import store
    store._DB_PATH = state_db
    import cache
    cache.init_cache(db_path=cache_db)
    import orchestrator as orch_mod
    orch = orch_mod.Orchestrator(load_config())
    return orch


def make_exchange(e: dict):
    from models import HttpExchange
    return HttpExchange(
        url=e["url"], method=e["method"],
        request_headers=e.get("request_headers", {}), request_body=e.get("request_body", ""),
        response_status=e.get("response_status"), response_headers=e.get("response_headers", {}),
        response_body=e.get("response_body", ""),
    )


def build_agent_specialty_map(orch):
    return {name: agent.specialty_prompt for name, agent in orch.agent_manager.agents.items()}


# ---------------------------------------------------------------------------
# Phase 1: record
# ---------------------------------------------------------------------------

async def cmd_record(args):
    from ollama_client import OllamaResult

    orch = build_orchestrator(args.state_db, args.cache_db)
    agent_specialty = build_agent_specialty_map(orch)

    transcript = []
    current_index = {"value": None}

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
            "exchange_index": current_index["value"],
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
        return OllamaResult(data=data, prompt_tokens=0, completion_tokens=0)

    orch.ollama.chat_json = fake_chat_json
    orch.ollama.chat_json_metered = fake_chat_json_metered

    with open(args.exchanges) as f:
        exchanges_raw = json.load(f)

    dispatch_summary = []
    for idx, e in enumerate(exchanges_raw):
        current_index["value"] = idx
        exchange = make_exchange(e)
        result = await orch.analyze(exchange)
        dispatch_summary.append({
            "exchange_index": idx,
            "label": e.get("label", ""),
            "url": e["url"],
            "dispatched_agents": result.dispatched_agents,
        })

    with open(args.out_transcript, "w") as f:
        json.dump(transcript, f, indent=2)
    with open(args.out_dispatch, "w") as f:
        json.dump(dispatch_summary, f, indent=2)

    print(f"Recorded {len(transcript)} would-be LLM calls -> {args.out_transcript}")
    print(f"Dispatch summary -> {args.out_dispatch}\n")
    for d in dispatch_summary:
        print(f"  [{d['exchange_index']}] {d['label'] or d['url']}")
        print(f"      -> dispatched: {d['dispatched_agents']}")
    if any(d["dispatched_agents"] == [] for d in dispatch_summary):
        print("\nNote: exchanges with an empty dispatch list produced no findings")
        print("opportunity at all -- fast_path found nothing and the coordinator")
        print("(if reached) also returned nothing usable, or force_agents wasn't set.")


# ---------------------------------------------------------------------------
# Phase 3: run with real answers
# ---------------------------------------------------------------------------

def load_answers_module(path: str):
    spec = importlib.util.spec_from_file_location("answers_module", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "get_answer"):
        raise ValueError(f"{path} must define get_answer(exchange_index, agent_name) -> dict")
    return module


async def cmd_run(args):
    from ollama_client import OllamaResult

    orch = build_orchestrator(args.state_db, args.cache_db)
    agent_specialty = build_agent_specialty_map(orch)
    answers = load_answers_module(args.answers)

    current_index = {"value": None}
    critique_calls = []

    async def fake_chat_json(model, system_prompt, user_prompt, temperature=0.1):
        if "adversarial reviewer" in system_prompt:
            critique_calls.append(user_prompt)
            indices = [int(m) for m in re.findall(r'^(\d+)\.\s*\[', user_prompt, re.MULTILINE)]
            reviews = [
                {"index": i, "verdict": "survived",
                 "note": "Independent read matches the stated finding."}
                for i in indices
            ]
            return {"reviews": reviews}
        if "coordinator in a security-testing harness" in system_prompt:
            print("WARNING: coordinator was reached but this driver doesn't answer "
                  "it interactively. Add coordinator handling to your answers module "
                  "if you see this, or check whether fast_path should have been "
                  "confident here.")
            return {"dispatch": [], "reason": "unhandled by driver"}
        for name, specialty in agent_specialty.items():
            if specialty.strip() and specialty.strip() in system_prompt:
                return answers.get_answer(current_index["value"], name)
        return {"findings": [], "components": []}

    async def fake_chat_json_metered(model, system_prompt, user_prompt, temperature=0.1):
        data = await fake_chat_json(model, system_prompt, user_prompt, temperature)
        return OllamaResult(data=data, prompt_tokens=0, completion_tokens=0)

    orch.ollama.chat_json = fake_chat_json
    orch.ollama.chat_json_metered = fake_chat_json_metered

    with open(args.exchanges) as f:
        exchanges_raw = json.load(f)

    results = []
    for idx, e in enumerate(exchanges_raw):
        current_index["value"] = idx
        exchange = make_exchange(e)
        result = await orch.analyze(exchange)
        results.append({
            "exchange_index": idx,
            "label": e.get("label", ""),
            "url": e["url"],
            "dispatched_agents": result.dispatched_agents,
            "findings": [f.model_dump() for r in result.agent_reports for f in r.findings],
            "components": [c.model_dump() for r in result.agent_reports for c in r.components],
            "summary": result.summary,
        })

    with open(args.out_results, "w") as f:
        json.dump({"results": results, "critique_calls": len(critique_calls)}, f, indent=2)

    print(f"Ran {len(results)} exchanges through the real orchestrator.")
    print(f"Critique was invoked {len(critique_calls)} time(s).\n")
    for r in results:
        if r["findings"]:
            print(f"[{r['exchange_index']}] {r['label'] or r['url']}")
            for f in r["findings"]:
                print(f"    -> {f['vulnerability_class']} (conf={f['confidence']}, "
                      f"sev={f['severity']}, basis={f['basis']})")
    print(f"\nFull results -> {args.out_results}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_record = sub.add_parser("record", help="Phase 1: record real dispatch + prompts")
    p_record.add_argument("--exchanges", required=True)
    p_record.add_argument("--state-db", default="/tmp/harness_driver_state.db")
    p_record.add_argument("--cache-db", default="/tmp/harness_driver_cache.db")
    p_record.add_argument("--out-transcript", default="/tmp/harness_driver_transcript.json")
    p_record.add_argument("--out-dispatch", default="/tmp/harness_driver_dispatch.json")

    p_run = sub.add_parser("run", help="Phase 3: run with your real answers")
    p_run.add_argument("--exchanges", required=True)
    p_run.add_argument("--answers", required=True)
    p_run.add_argument("--state-db", default="/tmp/harness_driver_state.db")
    p_run.add_argument("--cache-db", default="/tmp/harness_driver_cache.db")
    p_run.add_argument("--out-results", default="/tmp/harness_driver_results.json")

    args = parser.parse_args()
    if args.command == "record":
        asyncio.run(cmd_record(args))
    elif args.command == "run":
        asyncio.run(cmd_run(args))


if __name__ == "__main__":
    main()
