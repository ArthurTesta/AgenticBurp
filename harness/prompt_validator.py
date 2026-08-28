"""
Input validation for LLM prompts.

This module provides comprehensive validation for all LLM prompts to prevent:
1. Prompt injection attacks
2. Excessive token usage
3. Sensitive data leakage
4. Malicious content patterns
5. Input size limits

Security Principles:
- Validate, don't sanitize: we reject bad input rather than trying to fix it
- Defense in depth: multiple layers of validation (length, content, structure)
- Fail securely: reject when in doubt
- Log violations: track rejected inputs for security monitoring
"""
from __future__ import annotations
import re
import logging
from typing import Optional
from dataclasses import dataclass, field

log = logging.getLogger("harness.prompt_validator")


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class ValidationConfig:
    """Configuration for prompt validation."""
    
    # Length limits
    max_system_prompt_chars: int = 32000
    max_user_prompt_chars: int = 32000
    max_total_prompt_chars: int = 64000
    max_prompt_lines: int = 200
    
    # Token limits (approximate, based on characters)
    max_system_prompt_tokens: int = 8000
    max_user_prompt_tokens: int = 8000
    max_total_prompt_tokens: int = 16000
    
    # Content patterns to reject
    blocked_patterns: list[str] = field(default_factory=lambda: [
        # Prompt injection attempts - be specific to actual injection patterns
        r'\b(ignore|forget|disregard)\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|guidelines?|system\s+prompt)\b',
        r'\b(your\s+)?system\s+prompt\s+(is|was|are|were)\s+(ignored|irrelevant|wrong|false)\b',
        r'\b(act\s+as|behave\s+as|pretend\s+to\s+be)\s+[if\s+]+.*\b(user|assistant|system|model)\b',
        r'\b(you\s+are\s+now\s+ignoring|from\s+now\s+on\s+ignore)\s+.*\b',
        
        # Jailbreak attempts - more specific patterns
        r'\b(DAN|d\.?a\.?n\.?)\b',
        r'\b(developer|admin|root|superuser)\s+mode\b',
        r'\b(bypass|disable|ignore|skip)\s+(safety|security|content|filter|moderation)\s+(checks?|mechanisms?|systems?)\b',
        r'\b(enable|activate|turn\s+on)\s+(debug|dev|developer|test)\s+mode\b',
        
        # Code execution attempts
        r'\b(exec|execute|run|spawn|fork|system|popen|os\.|subprocess\.)\s*[("\']',
        r'\b(import|from|require|eval|exec|compile)\s+.*\b(os|sys|subprocess|shutil|ctypes)\b',
        r'\b(__import__|__builtins__|__code__|__class__|__mro__)\b',
        
        # File system access
        r'\b(open|read|write|delete|remove|unlink|rm|cat|less|more|head|tail)\s+["\']\s*/\s*',
        r'\b(file://|/etc/passwd|/etc/shadow|/etc/group|/etc/sudoers|\.ssh/|\.bashrc|\.bash_profile)\b',
        
        # Network access
        r'\b(wget|curl|fetch|axios|requests\.|httpx\.|urllib\.)\s+',
        r'\b(connect|socket|bind|listen|accept)\s*[("\']',
        
        # Dangerous patterns
        r'\b(rm\s+-rf\s+/|chmod\s+777|chown\s+0:0|mv\s+.*\s+/tmp/)\b',
        r'\b(;\s*\w+|&&\s*\w+|\|\|\s*\w+|`\s*\w+)\b',
        
        # Data exfiltration patterns
        r'\b(print|echo|write|log|send|post|put|upload)\s+.*\b(password|secret|token|key|credential|api_key)\b',
    ])
    
    # Allowed patterns (whitelist for certain contexts)
    allowed_patterns: list[str] = field(default_factory=lambda: [
        # Safe import patterns
        r'^\s*(import|from)\s+[a-zA-Z0-9_]+\s+(import|as)\s+[a-zA-Z0-9_]+',
        # Safe function calls
        r'\b(def|class|return|if|else|for|while|try|except|finally)\b',
    ])
    
    # Character restrictions
    max_consecutive_newlines: int = 10
    max_consecutive_spaces: int = 50
    
    # Enabled validation checks
    check_length: bool = True
    check_patterns: bool = True
    check_lines: bool = True
    check_characters: bool = True
    check_encoding: bool = True


# Default configuration
_DEFAULT_CONFIG = ValidationConfig()


# =============================================================================
# Validation Errors
# =============================================================================

class ValidationError(Exception):
    """Base class for validation errors."""
    
    def __init__(self, message: str, code: str = "VALIDATION_ERROR", details: dict = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


class LengthValidationError(ValidationError):
    """Raised when input exceeds length limits."""
    
    def __init__(self, message: str, actual: int, limit: int):
        super().__init__(message, code="LENGTH_EXCEEDED", details={"actual": actual, "limit": limit})
        self.actual = actual
        self.limit = limit


class PatternValidationError(ValidationError):
    """Raised when blocked patterns are detected."""
    
    def __init__(self, message: str, pattern: str, matched_text: str = None):
        super().__init__(message, code="BLOCKED_PATTERN", 
                        details={"pattern": pattern, "matched_text": matched_text})
        self.pattern = pattern
        self.matched_text = matched_text


class EncodingValidationError(ValidationError):
    """Raised when encoding issues are detected."""
    pass


# =============================================================================
# Validator Class
# =============================================================================

class PromptValidator:
    """
    Validates LLM prompts for security and stability.
    
    This validator performs multiple checks on prompts before they're
    sent to the LLM to prevent injection attacks, excessive resource usage,
    and other security issues.
    """
    
    def __init__(self, config: ValidationConfig = None):
        self.config = config or _DEFAULT_CONFIG
        self._compiled_patterns = None
        self._stats = {
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'blocked_patterns': 0,
            'length_violations': 0,
        }
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency."""
        if self._compiled_patterns is None:
            self._compiled_patterns = [
                (re.compile(p, re.IGNORECASE), p) 
                for p in self.config.blocked_patterns
            ]
        return self._compiled_patterns
    
    def validate_system_prompt(self, prompt: str) -> str:
        """Validate a system prompt."""
        return self._validate_prompt(prompt, "system")
    
    def validate_user_prompt(self, prompt: str) -> str:
        """Validate a user prompt."""
        return self._validate_prompt(prompt, "user")
    
    def validate_prompts(self, system_prompt: str, user_prompt: str) -> tuple[str, str]:
        """Validate both system and user prompts together."""
        system_validated = self.validate_system_prompt(system_prompt)
        user_validated = self.validate_user_prompt(user_prompt)
        
        # Check combined length
        if self.config.check_length:
            total_chars = len(system_validated) + len(user_validated)
            if total_chars > self.config.max_total_prompt_chars:
                self._stats['failed'] += 1
                self._stats['length_violations'] += 1
                raise LengthValidationError(
                    f"Combined prompt length ({total_chars}) exceeds maximum ({self.config.max_total_prompt_chars})",
                    total_chars, self.config.max_total_prompt_chars
                )
        
        return system_validated, user_validated
    
    def _validate_prompt(self, prompt: str, prompt_type: str) -> str:
        """Internal validation method."""
        self._stats['total_checks'] += 1
        
        if prompt is None:
            self._stats['failed'] += 1
            raise ValidationError(f"{prompt_type.capitalize()} prompt cannot be None")
        
        # Check type
        if not isinstance(prompt, str):
            self._stats['failed'] += 1
            raise ValidationError(f"{prompt_type.capitalize()} prompt must be a string, got {type(prompt).__name__}")
        
        # Check encoding
        if self.config.check_encoding:
            try:
                prompt.encode('utf-8')
            except UnicodeEncodeError as e:
                self._stats['failed'] += 1
                raise EncodingValidationError(
                    f"{prompt_type.capitalize()} prompt contains invalid UTF-8: {e}"
                )
        
        # Check length
        if self.config.check_length:
            max_chars = getattr(self.config, f'max_{prompt_type}_prompt_chars', self.config.max_user_prompt_chars)
            if len(prompt) > max_chars:
                self._stats['failed'] += 1
                self._stats['length_violations'] += 1
                raise LengthValidationError(
                    f"{prompt_type.capitalize()} prompt length ({len(prompt)}) exceeds maximum ({max_chars})",
                    len(prompt), max_chars
                )
        
        # Check lines
        if self.config.check_lines:
            lines = prompt.split('\n')
            if len(lines) > self.config.max_prompt_lines:
                self._stats['failed'] += 1
                self._stats['length_violations'] += 1
                raise LengthValidationError(
                    f"{prompt_type.capitalize()} prompt has too many lines ({len(lines)} > {self.config.max_prompt_lines})",
                    len(lines), self.config.max_prompt_lines
                )
        
        # Check consecutive newlines
        if self.config.check_characters:
            max_newlines = self.config.max_consecutive_newlines
            if '\n' * (max_newlines + 1) in prompt:
                self._stats['failed'] += 1
                raise ValidationError(
                    f"{prompt_type.capitalize()} prompt has too many consecutive newlines (>{max_newlines})"
                )
            
            # Check consecutive spaces
            max_spaces = self.config.max_consecutive_spaces
            if ' ' * (max_spaces + 1) in prompt:
                self._stats['failed'] += 1
                raise ValidationError(
                    f"{prompt_type.capitalize()} prompt has too many consecutive spaces (>{max_spaces})"
                )
        
        # Check blocked patterns
        if self.config.check_patterns:
            for compiled_pattern, original_pattern in self._compile_patterns():
                match = compiled_pattern.search(prompt)
                if match:
                    self._stats['failed'] += 1
                    self._stats['blocked_patterns'] += 1
                    matched_text = match.group(0)[:100]  # Truncate for logging
                    log.warning(
                        "Blocked pattern detected in %s prompt: %s (matched: %s)",
                        prompt_type, original_pattern[:50], matched_text
                    )
                    raise PatternValidationError(
                        f"Blocked pattern detected in {prompt_type} prompt",
                        original_pattern,
                        matched_text
                    )
        
        self._stats['passed'] += 1
        return prompt
    
    def sanitize_for_logging(self, prompt: str, max_length: int = 200) -> str:
        """Sanitize a prompt for safe logging."""
        if not isinstance(prompt, str):
            return f"<{type(prompt).__name__}>"
        
        # Truncate
        if len(prompt) > max_length:
            prompt = prompt[:max_length] + "..."
        
        # Remove potentially sensitive patterns
        sensitive_patterns = [
            r'\b(password|secret|token|key|credential|api_key|auth|bearer)\s*[=:]\s*[^\s]+',
            r'[0-9]{16,}',  # Credit card-like numbers
            r'\b(http|https)://[^\s]+',  # URLs
        ]
        
        for pattern in sensitive_patterns:
            prompt = re.sub(pattern, "[REDACTED]", prompt, flags=re.IGNORECASE)
        
        return prompt
    
    def get_stats(self) -> dict:
        """Get validation statistics."""
        return self._stats.copy()
    
    def reset_stats(self) -> None:
        """Reset validation statistics."""
        self._stats = {
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'blocked_patterns': 0,
            'length_violations': 0,
        }


# =============================================================================
# Global Validator Instance
# =============================================================================

# Default validator instance
_default_validator: Optional[PromptValidator] = None


def get_validator() -> PromptValidator:
    """Get the default prompt validator instance."""
    global _default_validator
    if _default_validator is None:
        _default_validator = PromptValidator()
    return _default_validator


def set_default_validator(validator: PromptValidator) -> None:
    """Set the default prompt validator instance."""
    global _default_validator
    _default_validator = validator


# =============================================================================
# Convenience Functions
# =============================================================================

def validate_system_prompt(prompt: str) -> str:
    """Validate a system prompt using the default validator."""
    return get_validator().validate_system_prompt(prompt)


def validate_user_prompt(prompt: str) -> str:
    """Validate a user prompt using the default validator."""
    return get_validator().validate_user_prompt(prompt)


def validate_prompts(system_prompt: str, user_prompt: str) -> tuple[str, str]:
    """Validate both prompts using the default validator."""
    return get_validator().validate_prompts(system_prompt, user_prompt)


# =============================================================================
# HTTP-Specific Validation
# =============================================================================

class HttpPromptValidator:
    """
    Specialized validator for HTTP request/response data.
    
    This validator handles the specific patterns found in HTTP exchanges
    and provides additional validation for headers, URLs, and body content.
    """
    
    def __init__(self, config: ValidationConfig = None):
        self.validator = PromptValidator(config)
        self._http_patterns = [
            # Block dangerous HTTP methods
            (re.compile(r'\b(TRACE|TRACK|CONNECT|DEBUG)\b', re.IGNORECASE), "dangerous_http_method"),
            
            # Block internal/private IPs in URLs
            (re.compile(r'\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)\d+\.\d+\b'), "private_ip"),
            (re.compile(r'\b169\.254\.\d+\.\d+\b'), "link_local"),
            (re.compile(r'\b127\.\d+\.\d+\.\d+\b'), "loopback"),
            (re.compile(r'\b(localhost|localhost\.localdomain|\.local|\.internal|\.private)\b', re.IGNORECASE), "localhost"),
            
            # Block sensitive headers
            (re.compile(r'\b(Authorization|Cookie|Set-Cookie|Proxy-Authorization|WWW-Authenticate)\s*[::]\s*[^\s]+', re.IGNORECASE), "sensitive_header"),
            
            # Block sensitive header values
            (re.compile(r'\b(Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b'), "bearer_token"),
            (re.compile(r'\b(Basic\s+[A-Za-z0-9+/=]+)\b'), "basic_auth"),
        ]
    
    def validate_exchange(self, url: str, method: str, headers: dict, body: str) -> tuple[str, str, dict, str]:
        """Validate HTTP exchange data before including in prompts."""
        # Validate URL
        validated_url = self._validate_url(url)
        
        # Validate method
        validated_method = self._validate_method(method)
        
        # Validate headers
        validated_headers = self._validate_headers(headers)
        
        # Validate body
        validated_body = self._validate_body(body)
        
        return validated_url, validated_method, validated_headers, validated_body
    
    def _validate_url(self, url: str) -> str:
        """Validate URL for inclusion in prompts."""
        if not url:
            return url
        
        for pattern, name in self._http_patterns:
            if pattern.search(url):
                log.warning("Blocked pattern in URL: %s", name)
                raise PatternValidationError(
                    f"Blocked pattern in URL: {name}",
                    pattern.pattern,
                    url[:100]
                )
        
        return url
    
    def _validate_method(self, method: str) -> str:
        """Validate HTTP method."""
        if not method:
            return method
        
        # Check for dangerous methods
        dangerous_methods = {'TRACE', 'TRACK', 'CONNECT', 'DEBUG'}
        if method.upper() in dangerous_methods:
            raise PatternValidationError(
                f"Dangerous HTTP method: {method}",
                method,
                method
            )
        
        return method
    
    def _validate_headers(self, headers: dict) -> dict:
        """Validate HTTP headers."""
        if not headers:
            return headers
        
        validated = {}
        sensitive_headers = {
            'authorization', 'cookie', 'set-cookie', 'proxy-authorization',
            'www-authenticate', 'x-api-key', 'x-auth-token', 'x-access-token'
        }
        
        for key, value in headers.items():
            # Check header name
            for pattern, name in self._http_patterns:
                if pattern.search(key):
                    log.warning("Blocked pattern in header name: %s", name)
                    raise PatternValidationError(
                        f"Blocked pattern in header name: {name}",
                        pattern.pattern,
                        key
                    )
            
            # Redact sensitive header values
            if key.lower() in sensitive_headers:
                validated[key] = "[REDACTED]"
            else:
                validated[key] = value
        
        return validated
    
    def _validate_body(self, body: str) -> str:
        """Validate HTTP body."""
        if not body:
            return body
        
        # Check body length
        if len(body) > self.validator.config.max_user_prompt_chars:
            # Truncate body for inclusion in prompts
            body = body[:self.validator.config.max_user_prompt_chars] + "...[TRUNCATED]"
        
        # Check for sensitive data in body
        sensitive_patterns = [
            r'\b(password|secret|token|key|credential|api_key)\s*["\']?\s*[=:]\s*["\']?[^\s"\'<>]+',
            r'\b(access_token|refresh_token|id_token|session_id|csrf_token)\s*[=:]\s*[^\s]+',
        ]
        
        for pattern in sensitive_patterns:
            body = re.sub(pattern, lambda m: f"{m.group(1)}: [REDACTED]", body, flags=re.IGNORECASE)
        
        return body
