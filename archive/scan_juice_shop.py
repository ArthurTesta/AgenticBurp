#!/usr/bin/env python3
"""
Juice Shop Security Scan Script

This script runs the AgenticBurp harness against a live OWASP Juice Shop instance
and generates a comprehensive security report with management summary.

Usage:
    python3 scan_juice_shop.py [--url http://127.0.0.1:3000] [--output report.html]
"""

import sys
import os
import asyncio
import httpx
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from pathlib import Path

# Add harness to path
sys.path.insert(0, str(Path(__file__).parent / "harness"))

from models import HttpExchange, AnalysisRequest, Finding, AnalysisResponse
from server import app
from fastapi.testclient import TestClient


@dataclass
class ScanResult:
    """Represents the result of scanning a single endpoint."""
    url: str
    method: str
    status_code: int
    findings: list[Finding] = field(default_factory=list)
    agents_dispatched: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    response_time: float = 0.0


@dataclass
class SecurityReport:
    """Complete security report for Juice Shop scan."""
    scan_id: str
    timestamp: str
    target_url: str
    total_endpoints: int = 0
    total_findings: int = 0
    findings_by_severity: dict = field(default_factory=dict)
    findings_by_category: dict = field(default_factory=dict)
    scanned_endpoints: list[ScanResult] = field(default_factory=list)
    agents_used: list[str] = field(default_factory=list)
    scan_duration: float = 0.0
    coverage_percentage: float = 0.0


class JuiceShopScanner:
    """Scans OWASP Juice Shop using AgenticBurp harness."""
    
    # Known Juice Shop endpoints organized by category
    JUICE_SHOP_ENDPOINTS = {
        "Authentication": [
            ("GET", "/#/login"),
            ("POST", "/rest/user/login"),
            ("GET", "/rest/user/whoami"),
            ("POST", "/rest/user/change-password"),
            ("POST", "/rest/user/register"),
        ],
        "Products": [
            ("GET", "/rest/products"),
            ("GET", "/rest/products/search?q=test"),
            ("GET", "/api/Products"),
            ("GET", "/api/Products/{id}"),
        ],
        "User Profile": [
            ("GET", "/rest/user/profile"),
            ("PUT", "/rest/user/profile"),
            ("GET", "/profile"),
        ],
        "Basket": [
            ("GET", "/rest/basket"),
            ("POST", "/rest/basket"),
            ("DELETE", "/rest/basket/{id}"),
        ],
        "Orders": [
            ("GET", "/rest/orders"),
            ("POST", "/rest/orders"),
        ],
        "Feedback": [
            ("POST", "/api/Feedback"),
            ("GET", "/api/Feedback"),
        ],
        "Admin": [
            ("GET", "/administration"),
            ("GET", "/rest/admin/application-version"),
            ("GET", "/rest/admin/application-log"),
        ],
        "Misc": [
            ("GET", "/"),
            ("GET", "/#/"),
            ("GET", "/#/search"),
            ("GET", "/rest/user/deluxe-membership"),
            ("POST", "/rest/user/deluxe-membership"),
            ("GET", "/rest/whoami"),
        ],
    }
    
    # Vulnerable endpoints that we know exist in Juice Shop
    VULNERABLE_ENDPOINTS = [
        ("POST", "/rest/user/login", "Broken Authentication"),
        ("GET", "/rest/products/search?q=<script>alert(1)</script>", "XSS"),
        ("GET", "/rest/products/search?q=test' OR '1'='1", "SQL Injection"),
        ("POST", "/api/Feedback", "XSS"),
        ("GET", "/api/Products/{id}", "IDOR"),
        ("GET", "/administration", "Broken Access Control"),
        ("GET", "/rest/admin/application-log", "Sensitive Data Exposure"),
    ]
    
    def __init__(self, base_url: str = "http://127.0.0.1:3000"):
        self.base_url = base_url.rstrip("/")
        self.client = TestClient(app)
        self.scan_id = f"juice-shop-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.start_time = None
        self.end_time = None
        
    def _create_exchange(self, method: str, url: str, **kwargs) -> Optional[HttpExchange]:
        """Create an HttpExchange from a real request."""
        full_url = f"{self.base_url}{url}" if not url.startswith("http") else url
        
        try:
            # Make the actual request
            with httpx.Client(timeout=10) as http_client:
                req = http_client.build_request(
                    method, 
                    full_url, 
                    **kwargs
                )
                resp = http_client.send(req, follow_redirects=False)
                
                # Create exchange
                exchange = HttpExchange(
                    url=str(resp.url),
                    method=method,
                    request_headers=dict(resp.request.headers),
                    request_body=resp.request.content.decode('utf-8', errors='ignore') if resp.request.content else "",
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=resp.content.decode('utf-8', errors='ignore') if resp.content else "",
                )
                return exchange
        except Exception as e:
            print(f"  [WARN] Failed to fetch {method} {url}: {e}")
            return None
    
    def _analyze_exchange(self, exchange: HttpExchange) -> Optional[AnalysisResponse]:
        """Analyze an exchange using the harness."""
        try:
            request = AnalysisRequest(
                exchange=exchange,
                force_agents=[],
                attempt_rediscovery=False
            )
            # Use the client to call the analyze endpoint
            response = self.client.post("/analyze", json=request.model_dump())
            if response.status_code == 200:
                return AnalysisResponse(**response.json())
            else:
                print(f"  [WARN] Analysis failed: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"  [ERROR] Analysis error: {e}")
            return None
    
    def scan_endpoint(self, method: str, endpoint: str) -> Optional[ScanResult]:
        """Scan a single endpoint."""
        import time
        
        start = time.time()
        url = endpoint if endpoint.startswith("http") else endpoint
        full_url = f"{self.base_url}{url}" if not url.startswith("http") else url
        
        print(f"  Scanning {method} {url}...")
        
        # Create exchange
        exchange = self._create_exchange(method, url)
        if exchange is None:
            return ScanResult(
                url=full_url,
                method=method,
                status_code=0,
                errors=["Failed to fetch endpoint"]
            )
        
        # Analyze with harness
        result = self._analyze_exchange(exchange)
        
        elapsed = time.time() - start
        
        if result is None:
            return ScanResult(
                url=full_url,
                method=method,
                status_code=exchange.response_status or 0,
                errors=["Analysis failed"],
                response_time=elapsed
            )
        
        # Extract findings
        findings = []
        for report in result.reports:
            findings.extend(report.findings)
        
        return ScanResult(
            url=full_url,
            method=method,
            status_code=exchange.response_status or 0,
            findings=findings,
            agents_dispatched=[r.agent for r in result.reports],
            response_time=elapsed
        )
    
    def scan_all(self) -> SecurityReport:
        """Run comprehensive scan of Juice Shop."""
        self.start_time = datetime.now()
        
        print(f"\n{'='*70}")
        print(f"Starting Juice Shop Security Scan")
        print(f"{'='*70}")
        print(f"Scan ID: {self.scan_id}")
        print(f"Target: {self.base_url}")
        print(f"Starting: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # First, check health
        print("Checking harness health...")
        health = self.client.get("/health")
        if health.status_code != 200:
            raise Exception("Harness is not healthy!")
        
        agents = health.json().get('agents', [])
        print(f"✓ Harness running with {len(agents)} agents")
        print()
        
        # Scan endpoints
        results = []
        total_endpoints = 0
        
        # Scan by category
        for category, endpoints in self.JUICE_SHOP_ENDPOINTS.items():
            print(f"\n[{category}]")
            print("-" * 40)
            for method, endpoint in endpoints:
                total_endpoints += 1
                scan_result = self.scan_endpoint(method, endpoint)
                if scan_result:
                    results.append(scan_result)
                    if scan_result.findings:
                        print(f"  ✓ {method} {endpoint} -> {len(scan_result.findings)} findings")
                    else:
                        print(f"  ✓ {method} {endpoint} -> No findings")
                else:
                    print(f"  ✗ {method} {endpoint} -> Failed")
        
        # Scan known vulnerable endpoints
        print(f"\n[Known Vulnerable Endpoints]")
        print("-" * 40)
        for method, endpoint, vuln_type in self.VULNERABLE_ENDPOINTS:
            total_endpoints += 1
            scan_result = self.scan_endpoint(method, endpoint)
            if scan_result:
                results.append(scan_result)
                if scan_result.findings:
                    print(f"  ✓ {method} {endpoint} ({vuln_type}) -> {len(scan_result.findings)} findings")
                else:
                    print(f"  ✓ {method} {endpoint} ({vuln_type}) -> No findings")
            else:
                print(f"  ✗ {method} {endpoint} ({vuln_type}) -> Failed")
        
        self.end_time = datetime.now()
        scan_duration = (self.end_time - self.start_time).total_seconds()
        
        # Build report
        report = self._build_report(results, agents, total_endpoints, scan_duration)
        
        print(f"\n{'='*70}")
        print(f"Scan Complete!")
        print(f"{'='*70}")
        print(f"Total endpoints scanned: {report.total_endpoints}")
        print(f"Total findings: {report.total_findings}")
        print(f"Scan duration: {scan_duration:.2f} seconds")
        print(f"Coverage: {report.coverage_percentage:.1f}%")
        print()
        
        return report
    
    def _build_report(self, results: list[ScanResult], agents: list[str], 
                      total_endpoints: int, scan_duration: float) -> SecurityReport:
        """Build security report from scan results."""
        report = SecurityReport(
            scan_id=self.scan_id,
            timestamp=self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            target_url=self.base_url,
            total_endpoints=total_endpoints,
            agents_used=agents,
            scan_duration=scan_duration,
            scanned_endpoints=results
        )
        
        # Count findings
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)
        
        report.total_findings = len(all_findings)
        
        # Categorize by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        category_counts = {}
        
        for finding in all_findings:
            # Determine severity (default to Medium if not specified)
            severity = finding.severity or "Medium"
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts[severity] = 1
            
            # Count by category
            category = finding.category or "Unknown"
            category_counts[category] = category_counts.get(category, 0) + 1
        
        report.findings_by_severity = severity_counts
        report.findings_by_category = category_counts
        
        # Calculate coverage (based on known vulnerable endpoints)
        vulnerable_endpoints = len(self.VULNERABLE_ENDPOINTS)
        endpoints_with_findings = sum(1 for r in results if r.findings)
        report.coverage_percentage = (endpoints_with_findings / max(vulnerable_endpoints, 1)) * 100
        
        return report
    
    def generate_html_report(self, report: SecurityReport, output_path: str = "juice_shop_report.html"):
        """Generate HTML report."""
        html = self._generate_html(report)
        with open(output_path, 'w') as f:
            f.write(html)
        print(f"✓ Report saved to {output_path}")
        return output_path
    
    def generate_markdown_report(self, report: SecurityReport, output_path: str = "juice_shop_report.md"):
        """Generate Markdown report."""
        md = self._generate_markdown(report)
        with open(output_path, 'w') as f:
            f.write(md)
        print(f"✓ Report saved to {output_path}")
        return output_path
    
    def _generate_html(self, report: SecurityReport) -> str:
        """Generate HTML report."""
        # Management Summary Section
        management_summary = self._generate_management_summary_html(report)
        
        # Detailed Findings Section
        findings_html = self._generate_findings_html(report)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Juice Shop Security Report - {report.scan_id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        h1 {{
            color: #2c3e50;
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }}
        .subtitle {{
            color: #7f8c8d;
            margin: 0;
        }}
        .management-summary {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            border-left: 5px solid #e74c3c;
        }}
        .management-summary h2 {{
            color: #e74c3c;
            margin-top: 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .stat-card .label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        .section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .severity-critical {{
            background: #e74c3c;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
        }}
        .severity-high {{
            background: #e67e22;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
        }}
        .severity-medium {{
            background: #f39c12;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
        }}
        .severity-low {{
            background: #3498db;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
        }}
        .severity-info {{
            background: #95a5a6;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
        }}
        .endpoint-section {{
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        .endpoint-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .method-get {{ background: #2ecc71; color: white; padding: 4px 8px; border-radius: 4px; }}
        .method-post {{ background: #3498db; color: white; padding: 4px 8px; border-radius: 4px; }}
        .method-put {{ background: #f39c12; color: white; padding: 4px 8px; border-radius: 4px; }}
        .method-delete {{ background: #e74c3c; color: white; padding: 4px 8px; border-radius: 4px; }}
        .footer {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🍊 Juice Shop Security Report</h1>
            <p class="subtitle">OWASP Juice Shop Vulnerability Assessment</p>
            <p><strong>Scan ID:</strong> {report.scan_id} | <strong>Generated:</strong> {report.timestamp}</p>
        </div>

        {management_summary}

        {findings_html}

        <div class="footer">
            <p>Generated by AgenticBurp Harness | {report.scan_id}</p>
        </div>
    </div>
</body>
</html>"""
        return html
    
    def _generate_management_summary_html(self, report: SecurityReport) -> str:
        """Generate management summary HTML section."""
        severity_counts = report.findings_by_severity
        total_findings = report.total_findings
        
        # Calculate risk score
        risk_score = 0
        if total_findings > 0:
            risk_score = (
                severity_counts.get("Critical", 0) * 100 +
                severity_counts.get("High", 0) * 70 +
                severity_counts.get("Medium", 0) * 40 +
                severity_counts.get("Low", 0) * 10
            ) / total_findings
        
        risk_level = "Low"
        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 60:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        
        summary = f"""
        <div class="management-summary">
            <h2>🎯 Management Summary</h2>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label">Total Findings</div>
                    <div class="number">{total_findings}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Critical Issues</div>
                    <div class="number">{severity_counts.get('Critical', 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="label">High Issues</div>
                    <div class="number">{severity_counts.get('High', 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Medium Issues</div>
                    <div class="number">{severity_counts.get('Medium', 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Low Issues</div>
                    <div class="number">{severity_counts.get('Low', 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Coverage</div>
                    <div class="number">{report.coverage_percentage:.1f}%</div>
                </div>
            </div>
            
            <h3>Overall Risk Assessment: <strong style="color: {'#e74c3c' if risk_level == 'Critical' else '#e67e22' if risk_level == 'High' else '#f39c12' if risk_level == 'Medium' else '#2ecc71'};">{risk_level}</strong></h3>
            
            <h3>Executive Overview</h3>
            <p>This security assessment of OWASP Juice Shop (a deliberately vulnerable web application) was conducted using the AgenticBurp harness with {len(report.agents_used)} specialized security agents. The scan identified {total_findings} vulnerabilities across multiple categories.</p>
            
            <h3>Key Metrics</h3>
            <ul>
                <li><strong>Endpoints Scanned:</strong> {report.total_endpoints}</li>
                <li><strong>Scan Duration:</strong> {report.scan_duration:.2f} seconds</li>
                <li><strong>Agents Deployed:</strong> {len(report.agents_used)}</li>
                <li><strong>Vulnerability Coverage:</strong> {report.coverage_percentage:.1f}%</li>
            </ul>
            
            <h3>Recommendations</h3>
            <ol>
                <li><strong>Immediate Action:</strong> Address all Critical and High severity findings first</li>
                <li><strong>Comprehensive Testing:</strong> Conduct manual verification of automated findings</li>
                <li><strong>Process Improvement:</strong> Implement secure coding practices and code reviews</li>
                <li><strong>Continuous Monitoring:</strong> Set up ongoing security testing in CI/CD pipeline</li>
            </ol>
        </div>
        """
        return summary
    
    def _generate_findings_html(self, report: SecurityReport) -> str:
        """Generate detailed findings HTML section."""
        html_parts = []
        
        # Severity Distribution Chart
        html_parts.append("""
        <div class="section">
            <h2>📊 Findings Overview</h2>
            <h3>By Severity</h3>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
        """)
        
        total = report.total_findings
        for severity, count in report.findings_by_severity.items():
            percentage = (count / total * 100) if total > 0 else 0
            html_parts.append(f"""
                    <tr>
                        <td><span class="severity-{severity.lower()}">{severity}</span></td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
            """)
        
        html_parts.append("""
                </tbody>
            </table>
            
            <h3>By Category</h3>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
        """)
        
        for category, count in report.findings_by_category.items():
            percentage = (count / total * 100) if total > 0 else 0
            html_parts.append(f"""
                    <tr>
                        <td>{category}</td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
            """)
        
        html_parts.append("""
                </tbody>
            </table>
        </div>
        """)
        
        # Detailed Findings by Endpoint
        html_parts.append("""
        <div class="section">
            <h2>🔍 Detailed Findings</h2>
        """)
        
        for result in report.scanned_endpoints:
            if result.findings:
                method_class = f"method-{result.method.lower()}"
                html_parts.append(f"""
            <div class="endpoint-section">
                <div class="endpoint-header">
                    <h3><span class="{method_class}">{result.method}</span> {result.url}</h3>
                    <span>Status: {result.status_code}</span>
                </div>
                <p><strong>Agents Dispatched:</strong> {', '.join(result.agents_dispatched) if result.agents_dispatched else 'None'}</p>
                <p><strong>Response Time:</strong> {result.response_time:.2f}s</p>
                
                <h4>Findings ({len(result.findings)})</h4>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Description</th>
                            <th>Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                """)
                
                for finding in result.findings:
                    severity_class = f"severity-{finding.severity.lower()}" if finding.severity else "severity-info"
                    html_parts.append(f"""
                        <tr>
                            <td><span class="{severity_class}">{finding.severity or 'Info'}</span></td>
                            <td>{finding.category or 'Unknown'}</td>
                            <td>{finding.description or 'No description'}</td>
                            <td>{finding.agent or 'Unknown'}</td>
                        </tr>
                    """)
                
                html_parts.append("""
                    </tbody>
                </table>
            </div>
                """)
        
        html_parts.append("</div>")
        
        return "".join(html_parts)
    
    def _generate_markdown(self, report: SecurityReport) -> str:
        """Generate Markdown report."""
        md_parts = []
        
        # Header
        md_parts.append(f"# 🍊 Juice Shop Security Report\n")
        md_parts.append(f"**Scan ID:** {report.scan_id}\n")
        md_parts.append(f"**Generated:** {report.timestamp}\n")
        md_parts.append(f"**Target:** {report.target_url}\n")
        md_parts.append(f"**Scan Duration:** {report.scan_duration:.2f} seconds\n\n")
        
        # Management Summary
        md_parts.append(self._generate_management_summary_markdown(report))
        
        # Findings Overview
        md_parts.append("## 📊 Findings Overview\n\n")
        md_parts.append("### By Severity\n\n")
        md_parts.append("| Severity | Count | Percentage |\n")
        md_parts.append("|----------|-------|------------|\n")
        
        total = report.total_findings
        for severity, count in report.findings_by_severity.items():
            percentage = (count / total * 100) if total > 0 else 0
            md_parts.append(f"| {severity} | {count} | {percentage:.1f}% |\n")
        
        md_parts.append("\n### By Category\n\n")
        md_parts.append("| Category | Count | Percentage |\n")
        md_parts.append("|----------|-------|------------|\n")
        
        for category, count in report.findings_by_category.items():
            percentage = (count / total * 100) if total > 0 else 0
            md_parts.append(f"| {category} | {count} | {percentage:.1f}% |\n")
        
        # Detailed Findings
        md_parts.append("\n## 🔍 Detailed Findings\n\n")
        
        for result in report.scanned_endpoints:
            if result.findings:
                md_parts.append(f"### `{result.method} {result.url}`\n")
                md_parts.append(f"- **Status Code:** {result.status_code}\n")
                md_parts.append(f"- **Agents Dispatched:** {', '.join(result.agents_dispatched) if result.agents_dispatched else 'None'}\n")
                md_parts.append(f"- **Response Time:** {result.response_time:.2f}s\n")
                md_parts.append(f"- **Findings:** {len(result.findings)}\n\n")
                
                for i, finding in enumerate(result.findings, 1):
                    md_parts.append(f"  {i}. **{finding.severity or 'Info'}** - {finding.category or 'Unknown'}\n")
                    md_parts.append(f"     - {finding.description or 'No description'}\n")
                    md_parts.append(f"     - *Agent: {finding.agent or 'Unknown'}*\n")
                
                md_parts.append("\n")
        
        # Agents Used
        md_parts.append(f"## 🤖 Agents Used ({len(report.agents_used)})\n\n")
        md_parts.append(", ".join(report.agents_used))
        md_parts.append("\n\n")
        
        # Footer
        md_parts.append(f"---\n")
        md_parts.append(f"Generated by AgenticBurp Harness | {report.scan_id}\n")
        
        return "".join(md_parts)
    
    def _generate_management_summary_markdown(self, report: SecurityReport) -> str:
        """Generate management summary in Markdown."""
        severity_counts = report.findings_by_severity
        total_findings = report.total_findings
        
        # Calculate risk score
        risk_score = 0
        if total_findings > 0:
            risk_score = (
                severity_counts.get("Critical", 0) * 100 +
                severity_counts.get("High", 0) * 70 +
                severity_counts.get("Medium", 0) * 40 +
                severity_counts.get("Low", 0) * 10
            ) / total_findings
        
        risk_level = "Low"
        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 60:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        
        summary = f"""## 🎯 Management Summary

### Overall Risk Assessment: **{risk_level}**

### Key Metrics
- **Total Findings:** {total_findings}
- **Critical Issues:** {severity_counts.get('Critical', 0)}
- **High Issues:** {severity_counts.get('High', 0)}
- **Medium Issues:** {severity_counts.get('Medium', 0)}
- **Low Issues:** {severity_counts.get('Low', 0)}
- **Vulnerability Coverage:** {report.coverage_percentage:.1f}%
- **Endpoints Scanned:** {report.total_endpoints}
- **Scan Duration:** {report.scan_duration:.2f} seconds
- **Agents Deployed:** {len(report.agents_used)}

### Executive Overview
This security assessment of OWASP Juice Shop (a deliberately vulnerable web application) was conducted using the AgenticBurp harness with {len(report.agents_used)} specialized security agents. The scan identified {total_findings} vulnerabilities across multiple categories.

### Recommendations
1. **Immediate Action:** Address all Critical and High severity findings first
2. **Comprehensive Testing:** Conduct manual verification of automated findings
3. **Process Improvement:** Implement secure coding practices and code reviews
4. **Continuous Monitoring:** Set up ongoing security testing in CI/CD pipeline


"""
        return summary


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Scan Juice Shop with AgenticBurp harness")
    parser.add_argument("--url", default="http://127.0.0.1:3000", help="Juice Shop URL")
    parser.add_argument("--output", default="juice_shop_report.html", help="Output file path")
    parser.add_argument("--format", choices=["html", "md"], default="html", help="Output format")
    args = parser.parse_args()
    
    print(f"Starting scan of {args.url}...")
    print()
    
    scanner = JuiceShopScanner(args.url)
    report = scanner.scan_all()
    
    if args.format == "html":
        scanner.generate_html_report(report, args.output)
    else:
        scanner.generate_markdown_report(report, args.output)
    
    print(f"\n✓ Scan complete! Report saved to {args.output}")
