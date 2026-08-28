"""
Orchestrator - Main analysis coordinator.

This is the central module that coordinates all security testing activities.
It delegates to specialized modules for:
- Agent management (agent_manager.py)
- Agent coordination (coordinator.py)
- Analysis pipeline (analysis_pipeline.py)
- Caching (cache.py)
- Fast-path selection (fast_path.py)

The orchestrator is responsible for:
1. Receiving HTTP exchanges from the server
2. Determining which agents to dispatch (via coordinator or fast-path)
3. Running the analysis pipeline
4. Collecting and processing results
5. Returning comprehensive analysis responses
"""
from __future__ import annotations
import asyncio
import logging
from urllib.parse import urlparse
from typing import Optional

from models import (
    HttpExchange,
    AnalysisResponse,
    AgentReport,
    Finding,
    UrlEstimateItem,
    EffortStatus,
    ValidationReport,
    ValidationSubmission,
)
import store
import chaining
import planner
import effort
from effort import BudgetMode, CallKind, EffortBudget
import security
import cache
import fast_path
from agent_manager import AgentManager
from coordinator import Coordinator
from analysis_pipeline import AnalysisPipeline
from github_advisories import GitHubAdvisoryClient
from package_registry_checks import PackageRegistryClient
from kev_check import KevClient
from validators import ValidatorRegistry
from models import ValidationReport, ValidationSubmission

log = logging.getLogger("harness.orchestrator")


class Orchestrator:
    """
    Main orchestrator for security testing.
    
    This class coordinates all aspects of analyzing HTTP exchanges,
    including agent dispatching, finding collection, validation, and
    result delivery.
    """

    def __init__(self, config: dict):
        """
        Initialize the orchestrator.
        
        Args:
            config: Full application configuration
        """
        self.config = config
        
        # Initialize Ollama client with integrated components
        from ollama_client import OllamaClient
        self.ollama = OllamaClient(
            base_url=config["ollama"]["base_url"],
            timeout_seconds=config["ollama"].get("timeout_seconds", 120),
        )
        
        # Initialize coordinator
        self.coordinator = Coordinator(self.ollama, config["coordinator"])
        
        # Initialize agent manager
        self.agent_manager = AgentManager(config, self.ollama)
        
        # Initialize analysis pipeline
        self.analysis_pipeline = AnalysisPipeline(
            self.agent_manager,
            self._init_effort_budget(config),
            store,
            config,
        )
        
        # Initialize fast-path selector
        self.fast_path_selector = fast_path.FastPathSelector(
            set(self.agent_manager.get_enabled_agents())
        )
        
        # Configuration
        self.max_body_chars = config["server"].get("max_body_chars", 6000)
        self.allowed_hosts = config["server"].get("allowed_hosts", [])
        self.critique_cfg = config.get("critique", {})
        
        # Initialize validator registry
        self.validator_registry = ValidatorRegistry(config)
        
        log.info(f"Orchestrator initialized with {len(self.agent_manager.get_enabled_agents())} agents")
    
    def _init_effort_budget(self, config: dict) -> EffortBudget:
        """Initialize the effort budget."""
        effort_cfg = config.get("effort_budget", {})
        mode_str = str(effort_cfg.get("mode", "soft")).lower()
        try:
            budget_mode = BudgetMode(mode_str)
        except ValueError:
            log.warning("Unknown effort_budget.mode %r; defaulting to soft.", mode_str)
            budget_mode = BudgetMode.SOFT
        return EffortBudget(mode=budget_mode, total_tokens=effort_cfg.get("total_tokens"))
    
    async def _choose_agents(self, exchange: HttpExchange) -> tuple[list[str], str]:
        """
        Choose which agents to dispatch.
        
        This method first tries fast-path selection, then falls back to
        the coordinator LLM if no strong signals are detected.
        
        Args:
            exchange: HTTP exchange to analyze
            
        Returns:
            Tuple of (dispatch_list, reason)
        """
        available = self.agent_manager.get_enabled_agents()
        
        # Try fast-path selection first
        fast_agents, fast_reason = self.fast_path_selector.select_agents(exchange)
        if fast_agents is not None:
            log.debug("Fast-path selected agents: %s", fast_agents)
            return fast_agents, fast_reason
        
        # Fall back to coordinator
        return await self.coordinator.choose_agents(exchange, available)
    
    async def _validate_findings(
        self,
        exchange: HttpExchange,
        reports: list[AgentReport],
    ) -> list[ValidationReport]:
        """
        Validate findings using external validators.
        
        Args:
            exchange: HTTP exchange being analyzed
            reports: List of agent reports
            
        Returns:
            List of validation reports
        """
        jobs = []
        plans: list = []
        
        for report in reports:
            for finding in report.findings:
                for validator in self.validator_registry.for_finding(finding, exchange):
                    jobs.append(validator.validate(finding, exchange))
                    plans.append(validator.plan(finding, exchange))
        
        if not jobs:
            return []
        
        results = await asyncio.gather(*jobs, return_exceptions=True)
        output: list[ValidationReport] = []
        
        for result, plan in zip(results, plans):
            if isinstance(result, Exception):
                log.warning("validator failed: %s", result)
                continue
            output.append(ValidationReport(
                validator=result.validator,
                status=result.status,
                finding_class=result.finding_class,
                confidence=result.confidence,
                confirmed=result.confirmed,
                summary=result.summary,
                evidence=result.evidence,
            ))
            if plan is not None:
                await asyncio.to_thread(store.persist_test_plans, exchange, [plan])
                submission = ValidationSubmission(
                    plan_id=plan.id,
                    status=result.status,
                    confidence=result.confidence,
                    confirmed=result.confirmed,
                    summary=result.summary,
                    evidence=result.evidence or result.raw_output,
                    executor=f"{plan.execution_plane}:{plan.capability}",
                    source_exchange_hash=plan.source_exchange_hash,
                )
                ok, reason = await asyncio.to_thread(
                    store.persist_validation_submission, submission
                )
                if not ok:
                    log.warning(
                        "failed to persist local-tool validation result for plan %s: %s",
                        plan.id, reason
                    )
        
        # Update findings with validation results
        by_class = {r.finding_class: r for r in output if r.confirmed}
        for report in reports:
            for finding in report.findings:
                vr = by_class.get(finding.vulnerability_class)
                if vr and vr.confirmed:
                    finding.confirmed = True
                    finding.confidence = max(finding.confidence, vr.confidence)
                    finding.review_verdict = finding.review_verdict or "validator-confirmed"
                    finding.review_note = (finding.review_note or "") + (
                        " " if finding.review_note else ""
                    ) + vr.summary
        
        return output
    
    async def _check_registry_ages(
        self,
        exchange: HttpExchange,
        reports: list[AgentReport],
    ) -> Optional[AgentReport]:
        """Check registry ages for recently published packages."""
        if not self.analysis_pipeline.registry_checks_enabled:
            return None
        
        all_components = []
        for report in reports:
            for comp in getattr(report, 'components', []):
                all_components.append(comp)
        
        if not all_components:
            return None

        from models import Finding
        findings: list[Finding] = []
        errors: list[str] = []
        
        verified = [
            comp for comp in all_components
            if self.analysis_pipeline._verify_component_observation(comp, exchange)
        ]
        
        if len(verified) < len(all_components):
            errors.append(
                f"{len(all_components) - len(verified)} component candidate(s) "
                "rejected from registry-age lookup because not independently observed"
            )
        
        for comp in verified[:self.analysis_pipeline.gha_max_lookups]:
            result = await self.analysis_pipeline.registry_client.check(comp)
            if result.status == "checked" and result.age_days is not None:
                if result.age_days < self.analysis_pipeline.registry_client.minimum_age_days:
                    findings.append(Finding(
                        vulnerability_class=f"recently-published-dependency:{comp.name}",
                        confidence=0.3,
                        severity="low",
                        owasp_category="A08:2021-Software and Data Integrity Failures",
                        summary=f"{comp.name} ({comp.ecosystem}) was published only "
                                f"{result.age_days:.1f} days ago",
                        evidence=f"Registry publish time: {result.published_at}. "
                                 f"Seen via {comp.source or 'unspecified'}. This alone is not "
                                 f"evidence of malicious intent -- most recently-published "
                                 f"packages are legitimate -- but it is the same weak-but-real "
                                 f"signal Aikido Safe Chain's minimum-package-age check uses.",
                        suggested_test="If this dependency wasn't intentionally just updated, "
                                        "verify it against your lockfile history and check whether "
                                        "the publisher account/maintainer changed recently.",
                        basis="derived",
                    ))
            elif result.status == "error":
                errors.append(f"{comp.name}: {result.detail}")

        if not findings and not errors:
            return None
        
        from models import AgentReport
        return AgentReport(
            agent="registry_age_check",
            model="npm-pypi-registry",
            findings=findings,
            raw_error="; ".join(errors) if errors else None,
        )
    
    async def analyze(
        self,
        exchange: HttpExchange,
        force_agents: list[str] = None,
        attempt_rediscovery: bool = False,
        bypass_cache: bool = False,
    ) -> AnalysisResponse:
        """
        Analyze an HTTP exchange.
        
        This is the main entry point for analyzing HTTP exchanges.
        It coordinates all aspects of the analysis workflow.
        
        Args:
            exchange: HTTP exchange to analyze
            force_agents: Optional list of agents to force dispatch
            attempt_rediscovery: Whether to attempt rediscovery of known vulnerabilities
            bypass_cache: Whether to bypass the cache
            
        Returns:
            AnalysisResponse with all findings and metadata
        """
        # Check cache first
        cache_hit = False
        if not bypass_cache and not force_agents:
            current_prompt_versions = {
                agent.name: agent._prompt_version()
                for agent in self.agent_manager.agents.values()
            }
            cached_result = cache.get_cache().get(
                exchange, self.coordinator.model, current_prompt_versions
            )
            if cached_result is not None:
                log.info(
                    "Cache hit for exchange %s",
                    cache.compute_exchange_hash(exchange)[:16]
                )
                cache_hit = True
                return AnalysisResponse(
                    **cached_result.model_dump(
                        exclude={"effort_spent_tokens", "effort_budget_remaining", "effort_budget_warning"}
                    ),
                    summary=f"{cached_result.summary} (cached)",
                    effort_spent_tokens=self.analysis_pipeline.effort_budget.spent,
                    effort_budget_remaining=self.analysis_pipeline.effort_budget.remaining,
                    effort_budget_warning="",
                )

        # Check allowed hosts
        if self.allowed_hosts:
            hostname = (urlparse(exchange.url).hostname or "").lower()
            allowed = {h.lower().lstrip("*.") for h in self.allowed_hosts}
            if not hostname or not any(
                hostname == h or hostname.endswith("." + h) for h in allowed
            ):
                raise ValueError(
                    f"target host {hostname!r} is outside configured server.allowed_hosts scope"
                )

        # Check effort budget
        budget_allowed, budget_reason = self.analysis_pipeline.effort_budget.allow()
        if not budget_allowed:
            log.warning("Effort budget blocked this analysis: %s", budget_reason)
            return AnalysisResponse(
                coordinator_model=self.coordinator.model,
                dispatched_agents=[],
                agent_reports=[],
                summary=f"Not analyzed: {budget_reason}",
                effort_spent_tokens=self.analysis_pipeline.effort_budget.spent,
                effort_budget_remaining=self.analysis_pipeline.effort_budget.remaining,
                effort_budget_warning=budget_reason,
            )

        # Choose agents
        if force_agents:
            dispatch = [a for a in force_agents if a in self.agent_manager.agents]
            reason = "explicit override from caller"
        else:
            dispatch, reason = await self._choose_agents(exchange)

        # Get prior context
        prior_context = await asyncio.to_thread(
            store.prior_findings_summary, exchange.url, exclude_url=exchange.url
        )

        # Run analysis pipeline with early termination
        if len(dispatch) > 1:
            # Run first batch
            first_batch_size = min(3, len(dispatch))
            first_batch = dispatch[:first_batch_size]
            remaining = dispatch[first_batch_size:]
            
            # Run first batch
            reports, n_reviewed, n_rejected = await self.analysis_pipeline.run_full_analysis(
                exchange, first_batch, prior_context, self.max_body_chars
            )
            
            # Check for early termination
            if remaining:
                should_stop, stop_reason = self.fast_path_selector.check_early_termination(
                    reports, remaining
                )
                
                if should_stop:
                    log.info("Early termination: %s", stop_reason)
                else:
                    # Run remaining agents
                    remaining_reports, rem_reviewed, rem_rejected = await self.analysis_pipeline.run_full_analysis(
                        exchange, remaining, prior_context, self.max_body_chars
                    )
                    reports.extend(remaining_reports)
                    n_reviewed += rem_reviewed
                    n_rejected += rem_rejected
        else:
            reports, n_reviewed, n_rejected = await self.analysis_pipeline.run_full_analysis(
                exchange, dispatch, prior_context, self.max_body_chars
            )

        # Validate findings
        validation_reports = await self._validate_findings(exchange, reports)

        # Check registry ages
        registry_age_report = await self._check_registry_ages(exchange, reports)
        if registry_age_report is not None:
            reports.append(registry_age_report)

        # Persist findings
        for report in reports:
            await asyncio.to_thread(
                store.persist_findings,
                exchange,
                report.agent,
                report.findings,
                report.model,
                report.prompt_version,
            )

        # Detect chains
        host_findings = await asyncio.to_thread(store.all_host_findings, exchange.url)
        host_findings = [
            f for f in host_findings
            if not f["vulnerability_class"].startswith("potential-attack-chain:")
        ]
        chain_findings = [
            f for f in chaining.detect(host_findings)
            if not await asyncio.to_thread(
                store.is_chain_already_detected,
                exchange.url,
                f.vulnerability_class.split(":", 1)[-1],
            )
        ]
        
        if chain_findings:
            for f in chain_findings:
                await asyncio.to_thread(
                    store.mark_chain_detected,
                    exchange.url,
                    f.vulnerability_class.split(":", 1)[-1],
                )
            chain_report = AgentReport(
                agent="chain_detector",
                model="rule-based",
                findings=chain_findings,
            )
            reports.append(chain_report)
            await asyncio.to_thread(
                store.persist_findings,
                exchange,
                "chain_detector",
                chain_findings,
            )

        # Generate test plans
        all_findings: list[Finding] = [f for r in reports for f in r.findings]
        test_plans = planner.plans_for_findings(exchange, all_findings)
        await asyncio.to_thread(store.persist_test_plans, exchange, test_plans)
        
        top = max(all_findings, key=lambda f: f.confidence, default=None)

        # Build summary
        errors = [f"{r.agent}: {r.raw_error}" for r in reports if r.raw_error]
        summary_parts = [f"Dispatched: {', '.join(dispatch) or 'none'} ({reason})."]
        summary_parts.append(f"{len(all_findings)} finding(s) across {len(reports)} agent(s).")
        
        if n_reviewed:
            summary_parts.append(f"Critique pass reviewed {n_reviewed}; rejected {n_rejected}.")
        if errors:
            summary_parts.append(f"{len(errors)} agent(s) failed: {'; '.join(errors)}")

        _, current_budget_reason = self.analysis_pipeline.effort_budget.allow()
        
        # Build response
        response = AnalysisResponse(
            coordinator_model=self.coordinator.model,
            dispatched_agents=dispatch,
            agent_reports=reports,
            summary=" ".join(summary_parts),
            highest_confidence_finding=top,
            findings_reviewed=n_reviewed,
            findings_rejected=n_rejected,
            validation_reports=validation_reports,
            test_plans=test_plans,
            effort_spent_tokens=self.analysis_pipeline.effort_budget.spent,
            effort_budget_remaining=self.analysis_pipeline.effort_budget.remaining,
            effort_budget_warning=current_budget_reason,
        )
        
        # Cache the result
        if not bypass_cache and not force_agents and not cache_hit:
            current_prompt_versions = {
                agent.name: agent._prompt_version()
                for agent in self.agent_manager.agents.values()
            }
            cache.get_cache().put(
                exchange, response, self.coordinator.model, current_prompt_versions
            )
            log.debug(
                "Cached analysis result for exchange %s",
                cache.compute_exchange_hash(exchange)[:16],
            )
        
        return response

    def estimate_for_urls(self, urls: list[UrlEstimateItem]) -> dict:
        """
        Estimate token cost for analyzing multiple URLs.
        
        Args:
            urls: List of URLs to estimate
            
        Returns:
            Dictionary with token estimates
        """
        inputs = [
            effort.UrlEstimateInput(
                url=u.url,
                risk_score=u.risk_score,
                category=u.category,
            )
            for u in urls
        ]
        return effort.estimate_for_urls(
            inputs, self.analysis_pipeline.effort_budget.ledger
        )

    def effort_status(self) -> EffortStatus:
        """Get current effort budget status."""
        return EffortStatus(
            mode=self.analysis_pipeline.effort_budget.mode.value,
            total_tokens=self.analysis_pipeline.effort_budget.total_tokens,
            spent_tokens=self.analysis_pipeline.effort_budget.spent,
            remaining_tokens=self.analysis_pipeline.effort_budget.remaining,
            exhausted=self.analysis_pipeline.effort_budget.exhausted(),
            breakdown=self.analysis_pipeline.effort_budget.ledger.breakdown(),
        )
