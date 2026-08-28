from __future__ import annotations
from .base import Validator
from .sqlmap import SqlmapValidator


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

    def for_finding(self, finding, exchange):
        if not self.enabled:
            return []
        return [v for v in self.validators.values()
                if v.applies(finding, exchange) and (not v.active or self.active_enabled)]
