"""Offline review diagnostics: no target requests, no application code changes."""
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, r"C:\Users\arthu\Documents\AgenticVibe-impl\harness")
sys.path.append(r"C:\Users\arthu\Documents\AgenticVibe\.review-deps")

import evidence
import store
from models import AgentReport, Finding, HttpExchange
from orchestrator import Orchestrator
from validators.base import ValidationResult


class FakeValidator:
    name = "offline-review-stub"

    def plan(self, finding, exchange):
        return None

    async def validate(self, finding, exchange):
        yes = finding.summary == "case A"
        return ValidationResult(
            validator=self.name, status="confirmed" if yes else "skipped",
            finding_class=finding.vulnerability_class, confirmed=yes,
            confidence=0.9 if yes else 0.1, summary="synthetic result")


class FakeRegistry:
    def for_finding(self, finding, exchange):
        return [FakeValidator()]


async def main():
    orch = Orchestrator.__new__(Orchestrator)
    orch.validator_registry = FakeRegistry()
    findings = [Finding(vulnerability_class="idor", confidence=0.5,
                        summary=label, evidence="synthetic", suggested_test=label,
                        basis="derived") for label in ("case A", "case B")]
    reports = [AgentReport(agent="offline", model="stub", findings=findings)]
    exchange = HttpExchange(url="http://review.invalid/items/1", method="GET")
    _, proofs = await orch._validate_findings(exchange, reports)
    first_id = orch._run_id()
    second_id = orch._run_id()
    ident = SimpleNamespace(id="review-alice", name="Alice", role="user", notes="", created_at=1.0)
    store.save_identity(ident)
    store.set_identity_principal_meta(ident.id, tenant="tenant-A", permissions=["read:object-1"], trust=3)
    before = store.get_identity_principal_meta(ident.id)
    store.save_identity(ident)
    after = store.get_identity_principal_meta(ident.id)
    print(json.dumps({
        "same_class_case_ids_equal": proofs[0]["case"]["case_id"] == proofs[1]["case"]["case_id"],
        "skipped_finding_marked_confirmed": findings[1].confirmed,
        "new_confirmed_proof_has_no_artifacts": not any((proofs[0]["baseline_artifact_id"], proofs[0]["attack_artifact_id"], proofs[0]["control_artifact_ids"])),
        "new_confirmed_proof_legacy_flag": proofs[0]["legacy"],
        "not_confirmed_maps_to": evidence.Verdict.from_validation("not_confirmed", False).value,
        "orchestrator_reuses_run_id": first_id == second_id,
        "principal_metadata_before_resave": before,
        "principal_metadata_after_resave": after,
    }, indent=2))


if __name__ == "__main__":
    original = store._DB_PATH
    try:
        with tempfile.TemporaryDirectory(prefix="astra-offline-review-") as tmp:
            store._DB_PATH = Path(tmp) / "review.db"
            asyncio.run(main())
    finally:
        store._DB_PATH = original
