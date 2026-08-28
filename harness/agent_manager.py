"""
Agent management module.

This module handles agent lifecycle, registration, and dispatching.
It separates agent-related concerns from the main orchestrator.
"""
from __future__ import annotations
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ollama_client import OllamaClient
    from models import HttpExchange, AgentReport

log = logging.getLogger("harness.agent_manager")


class AgentManager:
    """
    Manages the lifecycle of security testing agents.
    
    Responsibilities:
    - Register and initialize agents
    - Dispatch agents to analyze exchanges
    - Track agent health and performance
    - Provide agent metadata and capabilities
    """
    
    def __init__(self, config: dict, ollama: OllamaClient):
        """
        Initialize the agent manager.
        
        Args:
            config: Full application configuration
            ollama: Ollama client for LLM access
        """
        self.config = config
        self.ollama = ollama
        self.agents: dict[str, any] = {}
        self._agent_configs = config.get("agents", {})
        
        # Import agent classes
        from agents.sqli_agent import SqliAgent
        from agents.xss_agent import XssAgent
        from agents.idor_agent import IdorAgent
        from agents.ssrf_agent import SsrfAgent
        from agents.auth_agent import AuthAgent
        from agents.business_logic_agent import BusinessLogicAgent
        from agents.misconfig_agent import MisconfigAgent
        from agents.ai_llm_agent import AiLlmAgent
        from agents.supply_chain_agent import SupplyChainAgent
        from agents.rate_limit_agent import RateLimitAgent
        
        self._AGENT_CLASSES = {
            "sqli": SqliAgent,
            "xss": XssAgent,
            "idor": IdorAgent,
            "ssrf": SsrfAgent,
            "auth": AuthAgent,
            "business_logic": BusinessLogicAgent,
            "misconfig": MisconfigAgent,
            "ai_llm": AiLlmAgent,
            "supply_chain": SupplyChainAgent,
            "rate_limit": RateLimitAgent,
        }
        
        self._initialize_agents()
    
    def _initialize_agents(self) -> None:
        """Initialize all enabled agents."""
        for key, cls in self._AGENT_CLASSES.items():
            acfg = self._agent_configs.get(key, {})
            if not acfg.get("enabled", True):
                log.debug(f"Agent {key} is disabled")
                continue
            
            try:
                self.agents[key] = cls(
                    ollama=self.ollama,
                    model=acfg.get("model", self.config["coordinator"]["model"]),
                    temperature=acfg.get("temperature", 0.1),
                )
                log.info(f"Initialized agent: {key}")
            except Exception as e:
                log.error(f"Failed to initialize agent {key}: {e}")
                raise
    
    def get_agent(self, name: str) -> any:
        """Get an agent by name."""
        return self.agents.get(name)
    
    def get_enabled_agents(self) -> list[str]:
        """Get list of enabled agent names."""
        return list(self.agents.keys())
    
    def get_agent_config(self, name: str) -> dict:
        """Get configuration for a specific agent."""
        return self._agent_configs.get(name, {})
    
    def is_agent_enabled(self, name: str) -> bool:
        """Check if an agent is enabled."""
        return name in self.agents
    
    async def run_agent(
        self,
        name: str,
        exchange: HttpExchange,
        max_body_chars: int,
        prior_context: str,
        effort_budget: any,
    ) -> AgentReport:
        """
        Run a specific agent on an exchange.
        
        Args:
            name: Agent name
            exchange: HTTP exchange to analyze
            max_body_chars: Maximum body characters to process
            prior_context: Prior findings context
            effort_budget: Effort budget tracker
            
        Returns:
            Agent report with findings
        """
        if name not in self.agents:
            raise ValueError(f"Agent {name} not found or disabled")
        
        agent = self.agents[name]
        return await agent.run(exchange, max_body_chars, prior_context, effort_budget)
    
    async def run_multiple_agents(
        self,
        names: list[str],
        exchange: HttpExchange,
        max_body_chars: int,
        prior_context: str,
        effort_budget: any,
    ) -> list[AgentReport]:
        """
        Run multiple agents on an exchange.
        
        Args:
            names: List of agent names to run
            exchange: HTTP exchange to analyze
            max_body_chars: Maximum body characters to process
            prior_context: Prior findings context
            effort_budget: Effort budget tracker
            
        Returns:
            List of agent reports
        """
        import asyncio
        
        tasks = [
            self.run_agent(name, exchange, max_body_chars, prior_context, effort_budget)
            for name in names
        ]
        
        return list(await asyncio.gather(*tasks))
    
    def get_agent_metadata(self, name: str) -> dict:
        """
        Get metadata about an agent.
        
        Args:
            name: Agent name
            
        Returns:
            Dictionary with agent metadata
        """
        if name not in self.agents:
            return {}
        
        agent = self.agents[name]
        return {
            "name": name,
            "class": type(agent).__name__,
            "model": getattr(agent, "model", None),
            "temperature": getattr(agent, "temperature", None),
            "enabled": True,
        }
    
    def get_all_metadata(self) -> list[dict]:
        """Get metadata for all agents."""
        return [self.get_agent_metadata(name) for name in self.get_enabled_agents()]
