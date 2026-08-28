"""
Anomaly Detection System for Unknown Vulnerability Discovery

This module implements behavioral anomaly detection to identify potential
security issues that don't match known vulnerability patterns. It uses
statistical analysis, machine learning-inspired heuristics, and behavioral
patterns to flag suspicious application behavior.

The detector works by:
1. Building a baseline profile of "normal" application behavior
2. Comparing each exchange against the baseline
3. Flagging deviations that may indicate security issues
4. Grouping similar anomalies to identify new vulnerability classes
"""

from __future__ import annotations
import re
import json
import hashlib
import statistics
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs
from pathlib import Path

from models import HttpExchange, Finding


@dataclass
class BehaviorProfile:
    """Profile of normal application behavior."""
    # Response characteristics
    avg_response_size: float = 0
    response_size_stddev: float = 0
    common_status_codes: Counter = field(default_factory=Counter)
    
    # Parameter characteristics
    avg_param_count: float = 0
    param_name_length_avg: float = 0
    param_value_length_avg: float = 0
    
    # Header characteristics
    common_headers: Counter = field(default_factory=Counter)
    header_count_avg: float = 0
    
    # URL characteristics
    url_length_avg: float = 0
    url_depth_avg: float = 0  # Number of path segments
    common_path_patterns: Counter = field(default_factory=Counter)
    
    # Content type distribution
    content_types: Counter = field(default_factory=Counter)
    
    # Timing characteristics (if available)
    avg_response_time: float = 0
    
    # Method distribution
    method_counts: Counter = field(default_factory=Counter)
    
    # Exchange count
    exchange_count: int = 0


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_type: str
    severity: str = "medium"
    confidence: float = 0.5
    description: str = ""
    evidence: str = ""
    exchange_fingerprint: str = ""
    affected_field: str = ""
    expected_value: Any = None
    actual_value: Any = None
    deviation_score: float = 0.0


@dataclass
class AnomalyCluster:
    """Group of similar anomalies that may represent a new vulnerability class."""
    cluster_id: str
    anomalies: list[Anomaly] = field(default_factory=list)
    common_patterns: list[str] = field(default_factory=list)
    suggested_vulnerability_class: str = ""
    confidence: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    host: str = ""


class AnomalyDetector:
    """
    Detects anomalous behavior that may indicate unknown vulnerabilities.
    
    This detector uses multiple detection strategies:
    1. Statistical outliers (response sizes, timing, etc.)
    2. Pattern matching (suspicious input patterns)
    3. Behavioral deviations (unexpected parameter usage)
    4. Temporal anomalies (unusual sequences)
    5. Clustering (grouping similar anomalies)
    """
    
    def __init__(self, min_exchanges_for_baseline: int = 10):
        self.min_exchanges = min_exchanges_for_baseline
        self.profiles: dict[str, BehaviorProfile] = {}
        self.anomalies: list[Anomaly] = []
        self.clusters: list[AnomalyCluster] = []
        self.exchange_history: list[HttpExchange] = []
        
        # Pattern-based detectors
        self.suspicious_patterns = [
            # Path traversal
            r'\.\./',
            r'\.\.\\',
            r'/etc/passwd',
            r'/etc/shadow',
            r'\.git/',
            r'\.svn/',
            r'\.hg/',
            r'\.env',
            r'config\.(json|yml|yaml|ini)',
            r'\.bak$',
            r'\.old$',
            r'\.swp$',
            r'~$',
            
            # Command injection
            r';\s*\w+',
            r'\|\s*\w+',
            r'&&\s*\w+',
            r'\$\(',
            r'`\w+`',
            r'\b(sh|bash|cmd|powershell|python|php|perl|ruby)\b',
            
            # SQL injection
            r"'\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE)",
            r'"\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE)',
            r'\b(DROP|TRUNCATE|ALTER)\b',
            r'\b(WAITFOR\s+DELAY|SLEEP\()',
            r'\b(BENCHMARK\()',
            
            # XSS
            r'<script[^>]*>',
            r'on\w+\s*=',
            r'javascript:',
            r'data:text/html',
            r'<iframe[^>]*>',
            r'<img[^>]*src\s*=\s*["\']?\s*data:',
            
            # SSRF
            r'http(s)?://(localhost|127\.0\.0\.1|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))',
            r'file://',
            r'gopher://',
            r'dict://',
            
            # NoSQL
            r'\$\w+',
            r'\b(ne|gt|lt|gte|lte|in|nin|regex|where)\b',
            
            # JWT
            r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+',
            
            # File upload
            r'\.(php|asp|aspx|jsp|js|py|pl|rb|sh|bat|cmd|exe|dll|so)$',
            r'Content-Type:\s*application/octet-stream',
            
            # Information disclosure
            r'stack\s*trace',
            r'at\s+\w+\.\w+\s*\(',
            r'Exception\s*:',
            r'Error\s*:',
            r'Warning\s*:',
            r'Fatal\s*:',
        ]
        
        # Header-based anomalies
        self.suspicious_headers = [
            'server',
            'x-powered-by',
            'x-aspnet-version',
            'x-php-version',
            'x-generator',
        ]
        
        # Parameter-based anomalies
        self.sensitive_param_names = [
            'password',
            'passwd',
            'pwd',
            'secret',
            'token',
            'api_key',
            'apikey',
            'api-key',
            'access_token',
            'auth',
            'authorization',
            'session',
            'sessionid',
            'cookie',
            'credit_card',
            'creditcard',
            'cc_number',
            'ssn',
            'social_security',
        ]
        
        # Status code anomalies
        self.unexpected_status_for_method = {
            'GET': [500, 400, 403],  # GET should rarely cause server errors
            'POST': [200],  # POST usually returns 201 for creation
            'PUT': [200],   # PUT usually returns 200 or 204
            'DELETE': [200],  # DELETE usually returns 200 or 204
        }
    
    def update_profile(self, exchange: HttpExchange) -> None:
        """Update the behavior profile with a new exchange."""
        host = self._get_host(exchange.url)
        
        if host not in self.profiles:
            self.profiles[host] = BehaviorProfile()
        
        profile = self.profiles[host]
        
        # Update response statistics
        response_size = len(exchange.response_body) if exchange.response_body else 0
        if profile.exchange_count > 0:
            profile.avg_response_size = (
                profile.avg_response_size * (profile.exchange_count - 1) + response_size
            ) / profile.exchange_count
        else:
            profile.avg_response_size = response_size
        
        # Update status code counts
        if exchange.response_status:
            profile.common_status_codes[str(exchange.response_status)] += 1
        
        # Update parameter statistics
        params = self._extract_parameters(exchange)
        profile.avg_param_count = (
            profile.avg_param_count * (profile.exchange_count - 1) + len(params)
        ) / profile.exchange_count if profile.exchange_count > 0 else len(params)
        
        # Update URL statistics
        url_length = len(exchange.url)
        url_depth = len([p for p in exchange.url.split('/') if p])
        profile.url_length_avg = (
            profile.url_length_avg * (profile.exchange_count - 1) + url_length
        ) / profile.exchange_count if profile.exchange_count > 0 else url_length
        profile.url_depth_avg = (
            profile.url_depth_avg * (profile.exchange_count - 1) + url_depth
        ) / profile.exchange_count if profile.exchange_count > 0 else url_depth
        
        # Update content type statistics
        content_type = exchange.response_headers.get('content-type', '').lower().split(';')[0]
        if content_type:
            profile.content_types[content_type] += 1
        
        # Update method statistics
        profile.method_counts[exchange.method.upper()] += 1
        
        profile.exchange_count += 1
        self.exchange_history.append(exchange)
    
    def detect_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect anomalies in a single exchange."""
        anomalies = []
        host = self._get_host(exchange.url)
        
        # Only detect if we have a baseline
        if host not in self.profiles or self.profiles[host].exchange_count < self.min_exchanges:
            return anomalies
        
        profile = self.profiles[host]
        
        # 1. Statistical anomalies
        anomalies.extend(self._detect_statistical_anomalies(exchange, profile))
        
        # 2. Pattern-based anomalies
        anomalies.extend(self._detect_pattern_anomalies(exchange))
        
        # 3. Parameter-based anomalies
        anomalies.extend(self._detect_parameter_anomalies(exchange))
        
        # 4. Header-based anomalies
        anomalies.extend(self._detect_header_anomalies(exchange))
        
        # 5. Status code anomalies
        anomalies.extend(self._detect_status_anomalies(exchange, profile))
        
        # 6. Content-type anomalies
        anomalies.extend(self._detect_content_type_anomalies(exchange, profile))
        
        # 7. Temporal anomalies (if we have history)
        anomalies.extend(self._detect_temporal_anomalies(exchange))
        
        # Store anomalies
        self.anomalies.extend(anomalies)
        
        return anomalies
    
    def _detect_statistical_anomalies(self, exchange: HttpExchange, profile: BehaviorProfile) -> list[Anomaly]:
        """Detect statistical outliers."""
        anomalies = []
        
        # Response size anomaly (3+ standard deviations)
        response_size = len(exchange.response_body) if exchange.response_body else 0
        if profile.exchange_count > 1:
            if response_size > profile.avg_response_size * 3:
                anomalies.append(Anomaly(
                    anomaly_type="response_size_outlier",
                    severity="low",
                    confidence=0.7,
                    description="Response size is significantly larger than average",
                    evidence=f"Response size: {response_size}, Average: {profile.avg_response_size:.0f}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="response_body",
                    expected_value=profile.avg_response_size,
                    actual_value=response_size,
                    deviation_score=response_size / profile.avg_response_size if profile.avg_response_size > 0 else 0
                ))
            elif response_size < profile.avg_response_size * 0.1:
                anomalies.append(Anomaly(
                    anomaly_type="response_size_outlier",
                    severity="low",
                    confidence=0.6,
                    description="Response size is significantly smaller than average",
                    evidence=f"Response size: {response_size}, Average: {profile.avg_response_size:.0f}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="response_body",
                    expected_value=profile.avg_response_size,
                    actual_value=response_size,
                    deviation_score=profile.avg_response_size / response_size if response_size > 0 else 0
                ))
        
        # Parameter count anomaly
        params = self._extract_parameters(exchange)
        if profile.exchange_count > 1 and len(params) > profile.avg_param_count * 3:
            anomalies.append(Anomaly(
                anomaly_type="parameter_count_outlier",
                severity="low",
                confidence=0.6,
                description="Number of parameters is significantly higher than average",
                evidence=f"Parameter count: {len(params)}, Average: {profile.avg_param_count:.1f}",
                exchange_fingerprint=self._fingerprint(exchange),
                affected_field="parameters",
                expected_value=profile.avg_param_count,
                actual_value=len(params),
                deviation_score=len(params) / profile.avg_param_count if profile.avg_param_count > 0 else 0
            ))
        
        # URL depth anomaly
        url_depth = len([p for p in exchange.url.split('/') if p])
        if profile.exchange_count > 1 and url_depth > profile.url_depth_avg * 2:
            anomalies.append(Anomaly(
                anomaly_type="url_depth_outlier",
                severity="low",
                confidence=0.5,
                description="URL depth is significantly higher than average",
                evidence=f"URL depth: {url_depth}, Average: {profile.url_depth_avg:.1f}",
                exchange_fingerprint=self._fingerprint(exchange),
                affected_field="url",
                expected_value=profile.url_depth_avg,
                actual_value=url_depth,
                deviation_score=url_depth / profile.url_depth_avg if profile.url_depth_avg > 0 else 0
            ))
        
        return anomalies
    
    def _detect_pattern_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect suspicious patterns in request/response."""
        anomalies = []
        
        # Check request URL
        anomalies.extend(self._check_patterns(
            exchange.url, 
            "url", 
            exchange,
            severity="high"
        ))
        
        # Check request headers
        for header_name, header_value in exchange.request_headers.items():
            anomalies.extend(self._check_patterns(
                header_value,
                f"request_header_{header_name}",
                exchange,
                severity="high"
            ))
        
        # Check request body
        if exchange.request_body:
            anomalies.extend(self._check_patterns(
                exchange.request_body,
                "request_body",
                exchange,
                severity="high"
            ))
        
        # Check response headers
        for header_name, header_value in exchange.response_headers.items():
            # Skip content-length and similar
            if header_name.lower() in ['content-length', 'date', 'cache-control']:
                continue
            anomalies.extend(self._check_patterns(
                header_value,
                f"response_header_{header_name}",
                exchange,
                severity="medium"
            ))
        
        # Check response body
        if exchange.response_body:
            anomalies.extend(self._check_patterns(
                exchange.response_body,
                "response_body",
                exchange,
                severity="medium"
            ))
        
        return anomalies
    
    def _check_patterns(self, text: str, field: str, exchange: HttpExchange, 
                        severity: str = "medium") -> list[Anomaly]:
        """Check text against suspicious patterns."""
        anomalies = []
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                # Calculate confidence based on pattern specificity
                confidence = 0.8 if any(c.isalpha() for c in pattern) else 0.6
                
                anomalies.append(Anomaly(
                    anomaly_type="suspicious_pattern",
                    severity=severity,
                    confidence=confidence,
                    description=f"Suspicious pattern detected: {pattern[:50]}",
                    evidence=f"Pattern '{pattern}' found in {field}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field=field,
                    expected_value="No suspicious patterns",
                    actual_value=f"Pattern: {pattern}",
                    deviation_score=1.0
                ))
        
        return anomalies
    
    def _detect_parameter_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect anomalies in request parameters."""
        anomalies = []
        params = self._extract_parameters(exchange)
        
        # Check for sensitive parameter names
        for param_name, param_values in params.items():
            if any(sensitive in param_name.lower() for sensitive in self.sensitive_param_names):
                # Check if parameter is in request (not just response)
                if param_name in exchange.request_headers or param_name in exchange.request_body:
                    anomalies.append(Anomaly(
                        anomaly_type="sensitive_parameter",
                        severity="high",
                        confidence=0.9,
                        description=f"Sensitive parameter name detected: {param_name}",
                        evidence=f"Parameter '{param_name}' may contain sensitive data",
                        exchange_fingerprint=self._fingerprint(exchange),
                        affected_field=f"parameter_{param_name}",
                        expected_value="No sensitive parameter names",
                        actual_value=param_name,
                        deviation_score=1.0
                    ))
        
        # Check for unusual parameter values
        for param_name, param_values in params.items():
            for param_value in param_values:
                if param_value:
                    # Check for long values (potential DoS)
                    if len(param_value) > 1000:
                        anomalies.append(Anomaly(
                            anomaly_type="long_parameter_value",
                            severity="medium",
                            confidence=0.7,
                            description=f"Unusually long parameter value: {param_name}",
                            evidence=f"Parameter '{param_name}' has value of length {len(param_value)}",
                            exchange_fingerprint=self._fingerprint(exchange),
                            affected_field=f"parameter_{param_name}",
                            expected_value="< 1000 characters",
                            actual_value=len(param_value),
                            deviation_score=len(param_value) / 1000
                        ))
                    
                    # Check for repeated characters (potential DoS)
                    if len(param_value) > 100:
                        char_counts = Counter(param_value)
                        max_count = max(char_counts.values()) if char_counts else 0
                        if max_count > len(param_value) * 0.9:
                            anomalies.append(Anomaly(
                                anomaly_type="repeated_characters",
                                severity="medium",
                                confidence=0.7,
                                description=f"Parameter value contains mostly repeated characters: {param_name}",
                                evidence=f"Parameter '{param_name}' has {max_count}/{len(param_value)} of one character",
                                exchange_fingerprint=self._fingerprint(exchange),
                                affected_field=f"parameter_{param_name}",
                                expected_value="Diverse characters",
                                actual_value=f"{max_count}/{len(param_value)} repeated",
                                deviation_score=max_count / len(param_value)
                            ))
        
        return anomalies
    
    def _detect_header_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect anomalies in HTTP headers."""
        anomalies = []
        
        # Check for information disclosure in headers
        for header_name, header_value in exchange.response_headers.items():
            if header_name.lower() in self.suspicious_headers:
                anomalies.append(Anomaly(
                    anomaly_type="information_disclosure_header",
                    severity="medium",
                    confidence=0.8,
                    description=f"Information disclosure in header: {header_name}",
                    evidence=f"Header '{header_name}': {header_value}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field=f"response_header_{header_name}",
                    expected_value="No version information",
                    actual_value=header_value,
                    deviation_score=1.0
                ))
        
        # Check for missing security headers
        security_headers = ['x-frame-options', 'x-content-type-options', 'x-xss-protection', 
                           'content-security-policy', 'strict-transport-security', 'referrer-policy']
        for header in security_headers:
            if header not in exchange.response_headers:
                anomalies.append(Anomaly(
                    anomaly_type="missing_security_header",
                    severity="low",
                    confidence=0.5,
                    description=f"Missing security header: {header}",
                    evidence=f"Security header '{header}' is not present in response",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="response_headers",
                    expected_value=f"{header} present",
                    actual_value="Missing",
                    deviation_score=0.5
                ))
        
        return anomalies
    
    def _detect_status_anomalies(self, exchange: HttpExchange, profile: BehaviorProfile) -> list[Anomaly]:
        """Detect anomalies in HTTP status codes."""
        anomalies = []
        
        if exchange.response_status is None:
            return anomalies
        
        status_str = str(exchange.response_status)
        
        # Check for unexpected status codes for method
        expected_statuses = self.unexpected_status_for_method.get(exchange.method.upper(), [])
        if status_str.startswith('5') and exchange.method.upper() == 'GET':
            anomalies.append(Anomaly(
                anomaly_type="unexpected_server_error",
                severity="medium",
                confidence=0.7,
                description=f"GET request returned server error: {exchange.response_status}",
                evidence=f"Method: {exchange.method}, Status: {exchange.response_status}",
                exchange_fingerprint=self._fingerprint(exchange),
                affected_field="response_status",
                expected_value="200 or 404",
                actual_value=exchange.response_status,
                deviation_score=1.0
            ))
        
        # Check for rare status codes
        total = sum(profile.common_status_codes.values())
        if total > 0:
            status_frequency = profile.common_status_codes.get(status_str, 0) / total
            if status_frequency < 0.01:  # Less than 1% of requests
                anomalies.append(Anomaly(
                    anomaly_type="rare_status_code",
                    severity="low",
                    confidence=0.6,
                    description=f"Rare status code: {exchange.response_status}",
                    evidence=f"Status code {exchange.response_status} appears in {status_frequency*100:.2f}% of requests",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="response_status",
                    expected_value="Common status code",
                    actual_value=exchange.response_status,
                    deviation_score=1.0 - status_frequency
                ))
        
        return anomalies
    
    def _detect_content_type_anomalies(self, exchange: HttpExchange, profile: BehaviorProfile) -> list[Anomaly]:
        """Detect anomalies in content types."""
        anomalies = []
        
        if 'content-type' not in exchange.response_headers:
            return anomalies
        
        content_type = exchange.response_headers['content-type'].lower().split(';')[0]
        
        # Check for unexpected content types
        total = sum(profile.content_types.values())
        if total > 0:
            ct_frequency = profile.content_types.get(content_type, 0) / total
            if ct_frequency < 0.05:  # Less than 5% of requests
                anomalies.append(Anomaly(
                    anomaly_type="rare_content_type",
                    severity="low",
                    confidence=0.5,
                    description=f"Rare content type: {content_type}",
                    evidence=f"Content type {content_type} appears in {ct_frequency*100:.2f}% of responses",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="content_type",
                    expected_value="Common content type",
                    actual_value=content_type,
                    deviation_score=1.0 - ct_frequency
                ))
        
        # Check for plain text responses that look like JSON
        if content_type == 'text/plain' and exchange.response_body:
            try:
                json.loads(exchange.response_body)
                anomalies.append(Anomaly(
                    anomaly_type="json_as_plain_text",
                    severity="medium",
                    confidence=0.8,
                    description="JSON data returned with text/plain content type",
                    evidence=f"Response body appears to be JSON but content type is text/plain",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="content_type",
                    expected_value="application/json",
                    actual_value="text/plain",
                    deviation_score=1.0
                ))
            except (json.JSONDecodeError, ValueError):
                pass
        
        # Check for HTML responses that look like JSON
        if 'html' in content_type and exchange.response_body:
            try:
                json.loads(exchange.response_body)
                anomalies.append(Anomaly(
                    anomaly_type="json_as_html",
                    severity="medium",
                    confidence=0.7,
                    description="JSON data returned with HTML content type",
                    evidence=f"Response body appears to be JSON but content type is {content_type}",
                    exchange_fingerprint=self._fingerprint(exchange),
                    affected_field="content_type",
                    expected_value="application/json",
                    actual_value=content_type,
                    deviation_score=1.0
                ))
            except (json.JSONDecodeError, ValueError):
                pass
        
        return anomalies
    
    def _detect_temporal_anomalies(self, exchange: HttpExchange) -> list[Anomaly]:
        """Detect temporal anomalies (if we have timing data)."""
        anomalies = []
        
        # This would require timing data to be available
        # For now, we'll skip temporal detection
        # In a real implementation, we would compare response times
        # against the average for similar requests
        
        return anomalies
    
    def cluster_anomalies(self) -> list[AnomalyCluster]:
        """Cluster similar anomalies to identify new vulnerability classes."""
        # Group anomalies by host
        by_host = defaultdict(list)
        for anomaly in self.anomalies:
            host = self._get_host_from_fingerprint(anomaly.exchange_fingerprint)
            by_host[host].append(anomaly)
        
        clusters = []
        
        for host, host_anomalies in by_host.items():
            # Group by anomaly type and affected field
            groups = defaultdict(list)
            for anomaly in host_anomalies:
                key = (anomaly.anomaly_type, anomaly.affected_field)
                groups[key].append(anomaly)
            
            # Create clusters from groups with multiple anomalies
            for (anomaly_type, affected_field), group_anomalies in groups.items():
                if len(group_anomalies) >= 3:  # At least 3 similar anomalies
                    # Calculate cluster properties
                    timestamps = []
                    for a in group_anomalies:
                        # In a real implementation, we'd have timestamps
                        # For now, we'll use the order in the list
                        pass
                    
                    # Suggest vulnerability class based on anomaly type
                    suggested_class = self._suggest_vulnerability_class(anomaly_type, affected_field)
                    
                    cluster = AnomalyCluster(
                        cluster_id=hashlib.sha256(f"{host}:{anomaly_type}:{affected_field}".encode()).hexdigest()[:16],
                        anomalies=group_anomalies,
                        suggested_vulnerability_class=suggested_class,
                        confidence=min(0.9, 0.5 + len(group_anomalies) * 0.1),
                        host=host
                    )
                    clusters.append(cluster)
        
        self.clusters = clusters
        return clusters
    
    def _suggest_vulnerability_class(self, anomaly_type: str, affected_field: str) -> str:
        """Suggest a vulnerability class based on anomaly type and field."""
        mappings = {
            ('suspicious_pattern', 'url'): 'path_traversal',
            ('suspicious_pattern', 'request_body'): 'injection',
            ('suspicious_pattern', 'response_body'): 'information_disclosure',
            ('sensitive_parameter', ''): 'sensitive_data_exposure',
            ('long_parameter_value', ''): 'denial_of_service',
            ('repeated_characters', ''): 'denial_of_service',
            ('information_disclosure_header', ''): 'information_disclosure',
            ('missing_security_header', ''): 'security_misconfiguration',
            ('unexpected_server_error', ''): 'server_error',
            ('rare_status_code', ''): 'unusual_behavior',
            ('rare_content_type', ''): 'content_type_mismatch',
            ('json_as_plain_text', ''): 'content_type_mismatch',
            ('json_as_html', ''): 'content_type_mismatch',
            ('response_size_outlier', ''): 'information_disclosure',
        }
        
        return mappings.get((anomaly_type, affected_field), 'unknown_anomaly')
    
    def generate_findings(self, anomalies: list[Anomaly]) -> list[Finding]:
        """Convert anomalies to Finding objects."""
        findings = []
        
        # Cluster anomalies first
        clusters = self.cluster_anomalies()
        
        # Group anomalies by cluster
        clustered_anomalies = set()
        for cluster in clusters:
            if len(cluster.anomalies) >= 3:
                # Create a finding for the cluster
                findings.append(Finding(
                    vulnerability_class=cluster.suggested_vulnerability_class,
                    severity="high" if cluster.confidence > 0.8 else "medium",
                    confidence=cluster.confidence,
                    summary=f"Multiple anomalies detected: {cluster.suggested_vulnerability_class}",
                    evidence=f"Cluster of {len(cluster.anomalies)} similar anomalies on {cluster.host}",
                    suggested_test=f"Investigate {cluster.suggested_vulnerability_class} on {cluster.host}",
                    basis="derived",
                    validation_hints=[]
                ))
                clustered_anomalies.update(a.exchange_fingerprint for a in cluster.anomalies)
        
        # Create findings for unclustered anomalies
        for anomaly in anomalies:
            if anomaly.exchange_fingerprint not in clustered_anomalies:
                findings.append(Finding(
                    vulnerability_class=anomaly.anomaly_type,
                    severity=anomaly.severity,
                    confidence=anomaly.confidence,
                    summary=anomaly.description,
                    evidence=anomaly.evidence,
                    suggested_test=f"Investigate {anomaly.anomaly_type} in {anomaly.affected_field}",
                    basis="derived",
                    validation_hints=[]
                ))
        
        return findings
    
    def _get_host(self, url: str) -> str:
        """Extract host from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0] or "unknown"
        except Exception:
            return "unknown"
    
    def _get_host_from_fingerprint(self, fingerprint: str) -> str:
        """Extract host from exchange fingerprint."""
        # Fingerprint contains URL, so we can extract host from it
        # This is a simplified approach
        for exchange in self.exchange_history:
            if self._fingerprint(exchange) == fingerprint:
                return self._get_host(exchange.url)
        return "unknown"
    
    def _extract_parameters(self, exchange: HttpExchange) -> dict[str, list[str]]:
        """Extract all parameters from an exchange."""
        params = defaultdict(list)
        
        # URL query parameters
        try:
            parsed = urlparse(exchange.url)
            query_params = parse_qs(parsed.query)
            for param, values in query_params.items():
                params[param].extend(values)
        except Exception:
            pass
        
        # Request body parameters (for form data)
        if exchange.request_body:
            try:
                if 'application/x-www-form-urlencoded' in exchange.request_headers.get('content-type', ''):
                    body_params = parse_qs(exchange.request_body)
                    for param, values in body_params.items():
                        params[param].extend(values)
            except Exception:
                pass
        
        # Request header parameters
        for header, value in exchange.request_headers.items():
            params[header].append(value)
        
        return dict(params)
    
    def _fingerprint(self, exchange: HttpExchange) -> str:
        """Create a fingerprint for an exchange."""
        material = f"{exchange.method}:{exchange.url}".encode()
        return hashlib.sha256(material).hexdigest()[:16]


# Global detector instance for convenience
detector = AnomalyDetector()
