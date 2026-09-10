"""Offline diagnostics for astra-t05-t08: synthetic data, no target traffic."""
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, r"C:\Users\arthu\Documents\AgenticVibe\.worktrees\astra-t05-t08\harness")
sys.path.append(r"C:\Users\arthu\Documents\AgenticVibe\.review-deps")
import coverage_model as cm
import coverage_tracker as ct
import issues
import store
from models import Finding, HttpExchange


async def main():
    result = {}
    matrix = cm.CoverageMatrix()
    a, b = cm.CaseKey("query", "a"), cm.CaseKey("query", "b")
    cell = ("alice", "GET /search", "WSTG-INPV-05")
    matrix.expand_cases(*cell, [a, b])
    matrix.record_case(*cell, a, status=cm.CellStatus.CONTROLLED_NEGATIVE)
    matrix.record_case(*cell, b, status=cm.CellStatus.ERROR)
    parent = matrix.get(*cell)
    result["mixed_negative_error_parent"] = parent.to_dict()
    result["occurrence_proof_name_collision"] = (
        cm.CaseKey("query", "id", 1).case_parameter_name()
        == cm.CaseKey("query", "id[1]", 0).case_parameter_name())

    tracker = ct.CoverageTracker()
    tracker.matrix.expand_cases(*cell, [a, b, cm.CaseKey("query", "c")])
    calls = []

    async def failed(*args):
        calls.append(args[-1].parameter_name)
        raise RuntimeError("synthetic operational failure")

    driven = await tracker.drive_coverage_cases(failed, budget=1)
    result["exception_budget"] = {"budget": 1, "calls": len(calls), "driven": driven,
                                  "errors_recorded": tracker.matrix.case_summary()["error"]}

    def finding(url, **extra):
        return {"url": url, "method": "GET", "vulnerability_class": "idor",
                "summary": "synthetic observation", **extra}

    left = finding("https://a.invalid/items/1")
    right = finding("https://b.invalid/items/1")
    result["different_targets_same_issue_id"] = issues.issue_id_for(issues.issue_key(left)) == issues.issue_id_for(issues.issue_key(right))
    result["unknown_input_findings_group_count"] = len(issues.group_findings_into_issues([
        finding("https://a.invalid/items/1", finding_id="A", summary="different A"),
        finding("https://a.invalid/items/1", finding_id="B", summary="different B")]))
    group = issues.group_findings_into_issues([finding(
        "https://a.invalid/items/1?token=SYNTHETIC_URL_MARKER",
        evidence='{"password":"SYNTHETIC_JSON_MARKER"}')])[0]
    exported = json.dumps(issues.export_issue(group))
    replay = json.dumps(issues.replay_view(group))
    result["export_retains_url_secret_marker"] = "SYNTHETIC_URL_MARKER" in exported
    result["export_retains_json_secret_marker"] = "SYNTHETIC_JSON_MARKER" in exported
    result["replay_retains_url_secret_marker"] = "SYNTHETIC_URL_MARKER" in replay

    group = issues.group_findings_into_issues([finding(
        "https://a.invalid/items/1", case_id="case-A", proof_id="proof-old")])[0]
    result["proof_reference_verdict_mismatch"] = issues.export_issue(group, proofs_by_case={
        "case-A": {"proof_id": "proof-new", "verdict": "confirmed"}
    })["proof_references"]

    ex = HttpExchange(url="https://history.invalid/items/1", method="GET")
    for run, confirmed in (("first", True), ("retest", False)):
        f = Finding(vulnerability_class="idor", confidence=0.5,
                    summary="same case summary", evidence=run, suggested_test="synthetic",
                    basis="derived", confirmed=confirmed, case_id=run, proof_id=run)
        store.persist_findings(ex, "offline", [f])
    rows = store.all_host_findings(ex.url)
    result["persisted_retest_cases"] = [r["case_id"] for r in rows]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    previous = store._DB_PATH
    try:
        with tempfile.TemporaryDirectory(prefix="astra-t05-review-") as tmp:
            store._DB_PATH = Path(tmp) / "state.db"
            asyncio.run(main())
    finally:
        store._DB_PATH = previous
