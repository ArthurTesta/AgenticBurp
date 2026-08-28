from __future__ import annotations
from .base import Validator
from .sqlmap import SqlmapValidator
from .cors_validator import CorsValidator
from .recon_validator import ReconValidator
from .http_request_smuggling_validator import HttpRequestSmugglingValidator


class ValidatorRegistry:
    def __init__(self, config: dict):
        cfg = config.get("validators", {})
        self.enabled = bool(cfg.get("enabled", True))
        self.active_enabled = bool(cfg.get("active_enabled", False))
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

    def for_finding(self, finding, exchange):
        if not self.enabled:
            return []
        return [v for v in self.validators.values()
                if v.applies(finding, exchange) and (not v.active or self.active_enabled)]
