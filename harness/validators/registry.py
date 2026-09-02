from __future__ import annotations
from .base import Validator
from .sqlmap import SqlmapValidator
from .cors_validator import CorsValidator
from .recon_validator import ReconValidator
from .http_request_smuggling_validator import HttpRequestSmugglingValidator
from .web_cache_poisoning_validator import WebCachePoisoningValidator
from .oauth_validator import OAuthValidator
from .subdomain_takeover_validator import SubdomainTakeoverValidator
from .crypto_validator import CryptoValidator
from .csp_validator import CspValidator
from .header_injection_validator import HeaderInjectionValidator
from .api_security_validator import ApiSecurityValidator
from .websocket_validator import WebsocketValidator
from .race_condition_validator import RaceConditionValidator
from .deserialization_validator import DeserializationValidator
from .browser_xss_validator import BrowserXssValidator
from .cross_identity_validator import CrossIdentityValidator
from safety_gate import get_default_gate, reset_default_gate


class ValidatorRegistry:
    def __init__(self, config: dict):
        cfg = config.get("validators", {})
        self.enabled = bool(cfg.get("enabled", True))
        self.active_enabled = bool(cfg.get("active_enabled", False))
        # Seed the process-wide safety gate from the real config now,
        # before any validator's validate() call can lazily initialize
        # it with defaults. reset_default_gate() first so re-creating a
        # ValidatorRegistry (e.g. in tests, or a config reload) doesn't
        # keep stale gate settings from a previous instantiation.
        reset_default_gate()
        get_default_gate(cfg)
        sqlmap_cfg = cfg.get("sqlmap", {})
        self.validators: dict[str, Validator] = {}
        if sqlmap_cfg.get("enabled", True):
            self.validators["sqlmap"] = SqlmapValidator(
                binary=sqlmap_cfg.get("binary", "sqlmap"),
                timeout_seconds=int(sqlmap_cfg.get("timeout_seconds", 90)),
                level=int(sqlmap_cfg.get("level", 1)),
                risk=int(sqlmap_cfg.get("risk", 1)),
            )
        
        # CORS validator
        cors_cfg = cfg.get("cors", {})
        if cors_cfg.get("enabled", True):
            self.validators["cors"] = CorsValidator(
                timeout=float(cors_cfg.get("timeout", 10.0)),
                max_redirects=int(cors_cfg.get("max_redirects", 5)),
            )
        
        # Recon validator
        recon_cfg = cfg.get("recon", {})
        if recon_cfg.get("enabled", True):
            self.validators["recon"] = ReconValidator(
                timeout=float(recon_cfg.get("timeout", 15.0)),
                max_redirects=int(recon_cfg.get("max_redirects", 10)),
                max_depth=int(recon_cfg.get("max_depth", 5)),
            )
        
        # HTTP Request Smuggling validator
        hrs_cfg = cfg.get("http_request_smuggling", {})
        if hrs_cfg.get("enabled", True):
            self.validators["http_request_smuggling"] = HttpRequestSmugglingValidator(
                timeout=float(hrs_cfg.get("timeout", 30.0)),
                max_redirects=int(hrs_cfg.get("max_redirects", 0)),
            )

        # Web Cache Poisoning validator
        cache_cfg = cfg.get("web_cache_poisoning", {})
        if cache_cfg.get("enabled", True):
            self.validators["web_cache_poisoning"] = WebCachePoisoningValidator(
                timeout=float(cache_cfg.get("timeout", 15.0)),
                max_redirects=int(cache_cfg.get("max_redirects", 5)),
            )

        # OAuth / OIDC validator
        oauth_cfg = cfg.get("oauth", {})
        if oauth_cfg.get("enabled", True):
            self.validators["oauth"] = OAuthValidator(
                timeout=float(oauth_cfg.get("timeout", 10.0)),
                max_redirects=int(oauth_cfg.get("max_redirects", 0)),
            )

        # Subdomain Takeover validator
        takeover_cfg = cfg.get("subdomain_takeover", {})
        if takeover_cfg.get("enabled", True):
            self.validators["subdomain_takeover"] = SubdomainTakeoverValidator(
                timeout=float(takeover_cfg.get("timeout", 15.0)),
                max_redirects=int(takeover_cfg.get("max_redirects", 3)),
            )

        # Crypto / TLS validator
        crypto_cfg = cfg.get("crypto", {})
        if crypto_cfg.get("enabled", True):
            self.validators["crypto"] = CryptoValidator(
                timeout=float(crypto_cfg.get("timeout", 10.0)),
            )

        # CSP / Clickjacking validator
        csp_cfg = cfg.get("csp", {})
        if csp_cfg.get("enabled", True):
            self.validators["csp"] = CspValidator(
                timeout=float(csp_cfg.get("timeout", 10.0)),
                max_redirects=int(csp_cfg.get("max_redirects", 5)),
            )

        # Header Injection validator
        header_inj_cfg = cfg.get("header_injection", {})
        if header_inj_cfg.get("enabled", True):
            self.validators["header_injection"] = HeaderInjectionValidator(
                timeout=float(header_inj_cfg.get("timeout", 10.0)),
            )

        # API Security validator
        api_sec_cfg = cfg.get("api_security", {})
        if api_sec_cfg.get("enabled", True):
            self.validators["api_security"] = ApiSecurityValidator(
                timeout=float(api_sec_cfg.get("timeout", 10.0)),
            )

        # WebSocket validator
        websocket_cfg = cfg.get("websocket", {})
        if websocket_cfg.get("enabled", True):
            self.validators["websocket"] = WebsocketValidator(
                timeout=float(websocket_cfg.get("timeout", 10.0)),
            )

        # Race Condition validator
        race_cfg = cfg.get("race_condition", {})
        if race_cfg.get("enabled", True):
            self.validators["race_condition"] = RaceConditionValidator(
                timeout=float(race_cfg.get("timeout", 15.0)),
                burst_size=int(race_cfg.get("burst_size", 12)),
            )

        # Insecure Deserialization validator (passive local inspection, not active)
        deser_cfg = cfg.get("deserialization", {})
        if deser_cfg.get("enabled", True):
            self.validators["deserialization"] = DeserializationValidator()

        # Browser-driven XSS validator (A2) -- active: loads candidate URLs in a
        # real headless browser and confirms only on observed script execution.
        # Enabled here just registers it; it still only RUNS when
        # validators.active_enabled is set (active=True) AND a browser engine is
        # installed (else it skips). Scope comes from server.allowed_hosts.
        bxss_cfg = cfg.get("browser_xss", {})
        if bxss_cfg.get("enabled", True):
            self.validators["browser_xss"] = BrowserXssValidator(
                timeout=float(bxss_cfg.get("timeout", 15.0)),
                allowed_hosts=config.get("server", {}).get("allowed_hosts", []),
                wait_ms=int(bxss_cfg.get("wait_ms", 1200)),
                max_visits=int(bxss_cfg.get("max_visits", 8)),
            )

        # Cross-identity (Autorize-style) access-control validator. DEFAULT OFF
        # (opt-in): it sends live requests and needs tester-supplied identities.
        # Registering it only arms it; it still runs only when active_enabled is
        # set (active=True) AND identities are configured for the host.
        xid_cfg = cfg.get("cross_identity", {})
        if xid_cfg.get("enabled", False):
            self.validators["cross_identity"] = CrossIdentityValidator(
                allowed_hosts=config.get("server", {}).get("allowed_hosts", []),
                timeout=float(xid_cfg.get("timeout", 10.0)),
                max_identities=int(xid_cfg.get("max_identities", 3)),
            )

    def for_finding(self, finding, exchange):
        if not self.enabled:
            return []
        return [v for v in self.validators.values()
                if v.applies(finding, exchange) and (not v.active or self.active_enabled)]
