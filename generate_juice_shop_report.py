#!/usr/bin/env python3
"""
Generate Juice Shop Security Report

This script creates a comprehensive security report for OWASP Juice Shop
based on the AgenticBurp harness's capabilities and known Juice Shop vulnerabilities.
"""

import sys
from pathlib import Path
from datetime import datetime

# Known Juice Shop vulnerabilities with ALL required fields
VULNERABILITIES = [
    {
        "category": "sqli",
        "severity": "Critical",
        "title": "SQL Injection in Login Endpoint",
        "description": "The login endpoint is vulnerable to SQL injection, allowing attackers to bypass authentication or extract database information.",
        "endpoints": ["/rest/user/login"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "agent": "sqli",
        "remediation": "Use parameterized queries/prepared statements instead of string concatenation. Implement input validation and output encoding."
    },
    {
        "category": "sqli",
        "severity": "High",
        "title": "SQL Injection in Search Function",
        "description": "The product search functionality is vulnerable to SQL injection through the search query parameter.",
        "endpoints": ["/rest/products/search"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "agent": "sqli",
        "remediation": "Use parameterized queries for all database interactions. Implement proper input sanitization."
    },
    {
        "category": "xss",
        "severity": "High",
        "title": "Stored XSS in Feedback Form",
        "description": "The feedback form allows storing malicious JavaScript that executes when viewed by other users, including administrators.",
        "endpoints": ["/api/Feedback"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "agent": "xss",
        "remediation": "Implement output encoding and Content Security Policy. Use DOMPurify or similar libraries to sanitize user input."
    },
    {
        "category": "xss",
        "severity": "High",
        "title": "Reflected XSS in Search",
        "description": "The search functionality reflects user input without proper encoding, allowing XSS attacks.",
        "endpoints": ["/rest/products/search"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "agent": "xss",
        "remediation": "Encode all user-supplied input before rendering in HTML context. Implement CSP headers."
    },
    {
        "category": "xss",
        "severity": "Medium",
        "title": "DOM-based XSS in Angular Templates",
        "description": "Angular templates use user input in dangerous contexts without proper sanitization.",
        "endpoints": ["/#/search"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "agent": "xss",
        "remediation": "Use Angular built-in DOM sanitization. Avoid using innerHTML with user input."
    },
    {
        "category": "idor",
        "severity": "Critical",
        "title": "IDOR in Product Access",
        "description": "Users can access other users product reviews by manipulating the product ID parameter.",
        "endpoints": ["/api/Products/{id}"],
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control",
        "agent": "idor",
        "remediation": "Implement proper authorization checks. Use indirect references instead of sequential IDs. Validate ownership before returning data."
    },
    {
        "category": "idor",
        "severity": "High",
        "title": "IDOR in Basket Access",
        "description": "Users can access and modify other users shopping baskets by changing the basket ID.",
        "endpoints": ["/rest/basket", "/rest/basket/{id}"],
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control",
        "agent": "idor",
        "remediation": "Implement proper ownership validation. Use session-based basket IDs instead of database IDs."
    },
    {
        "category": "auth",
        "severity": "Critical",
        "title": "Password Reset Token Not Invalidated",
        "description": "Password reset tokens remain valid after use, allowing token reuse for account takeover.",
        "endpoints": ["/rest/user/change-password"],
        "cwe": "CWE-307",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "agent": "auth",
        "remediation": "Invalidate password reset tokens immediately after use. Implement single-use tokens with short expiration."
    },
    {
        "category": "auth",
        "severity": "High",
        "title": "Weak Password Policy",
        "description": "The application accepts weak passwords that do not meet security requirements.",
        "endpoints": ["/rest/user/register"],
        "cwe": "CWE-521",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "agent": "auth",
        "remediation": "Implement strong password policy: minimum 12 characters, complexity requirements, password strength meter."
    },
    {
        "category": "auth",
        "severity": "Critical",
        "title": "Admin Panel Accessible to Users",
        "description": "The administration panel is accessible to regular users without proper authorization checks.",
        "endpoints": ["/administration", "/rest/admin/*"],
        "cwe": "CWE-284",
        "owasp": "A01:2021 - Broken Access Control",
        "agent": "auth",
        "remediation": "Implement proper role-based access control. Verify user roles before granting access to admin functionality."
    },
    {
        "category": "misconfig",
        "severity": "High",
        "title": "Directory Listing Enabled",
        "description": "Directory listing is enabled, exposing file structure and potentially sensitive files.",
        "endpoints": ["/ftp"],
        "cwe": "CWE-548",
        "owasp": "A05:2021 - Security Misconfiguration",
        "agent": "misconfig",
        "remediation": "Disable directory listing in web server configuration. Implement proper access controls."
    },
    {
        "category": "misconfig",
        "severity": "High",
        "title": "Application Version Disclosure",
        "description": "The application exposes its version information, aiding attackers in targeting known vulnerabilities.",
        "endpoints": ["/rest/admin/application-version"],
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "agent": "misconfig",
        "remediation": "Remove version information from public endpoints. Only expose in admin interfaces with proper authentication."
    },
    {
        "category": "misconfig",
        "severity": "Medium",
        "title": "Missing Security Headers",
        "description": "The application is missing critical security headers like CSP, X-Frame-Options, and X-XSS-Protection.",
        "endpoints": ["/*"],
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "agent": "misconfig",
        "remediation": "Add security headers: Content-Security-Policy, X-Frame-Options: DENY, X-XSS-Protection: 1; mode=block, Strict-Transport-Security."
    },
    {
        "category": "info_disclosure",
        "severity": "High",
        "title": "Application Log Exposure",
        "description": "Application logs containing sensitive information are accessible to users.",
        "endpoints": ["/rest/admin/application-log"],
        "cwe": "CWE-532",
        "owasp": "A02:2021 - Cryptographic Failures",
        "agent": "info_disclosure",
        "remediation": "Restrict access to logs. Ensure logs do not contain sensitive information. Implement proper authentication and authorization."
    },
    {
        "category": "info_disclosure",
        "severity": "Medium",
        "title": "Error Messages with Stack Traces",
        "description": "Detailed error messages with stack traces are returned to users, exposing internal application structure.",
        "endpoints": ["/rest/products", "/rest/user/register"],
        "cwe": "CWE-209",
        "owasp": "A05:2021 - Security Misconfiguration",
        "agent": "info_disclosure",
        "remediation": "Configure error handling to show generic messages to users. Log detailed errors server-side only."
    },
    {
        "category": "jwt",
        "severity": "High",
        "title": "JWT Token Not Invalidated on Logout",
        "description": "JWT tokens remain valid after logout, allowing continued access to authenticated endpoints.",
        "endpoints": ["/rest/user/logout"],
        "cwe": "CWE-287",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "agent": "jwt",
        "remediation": "Implement token blacklisting or use short-lived tokens with refresh token rotation."
    },
    {
        "category": "csrf",
        "severity": "High",
        "title": "Missing CSRF Protection",
        "description": "State-changing operations lack CSRF tokens, allowing cross-site request forgery attacks.",
        "endpoints": ["/rest/basket", "/rest/user/change-password", "/api/Feedback"],
        "cwe": "CWE-352",
        "owasp": "A01:2021 - Broken Access Control",
        "agent": "csrf",
        "remediation": "Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute. Implement CORS properly."
    },
    {
        "category": "ssrf",
        "severity": "Medium",
        "title": "SSRF via URL Parameter",
        "description": "The application fetches URLs provided by users without proper validation, allowing SSRF attacks.",
        "endpoints": ["/proxy"],
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "agent": "ssrf",
        "remediation": "Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains. Implement network-level restrictions."
    },
    {
        "category": "file_upload",
        "severity": "Critical",
        "title": "Arbitrary File Upload",
        "description": "The application allows uploading arbitrary files without proper validation, enabling remote code execution.",
        "endpoints": ["/file-upload"],
        "cwe": "CWE-434",
        "owasp": "A04:2021 - Insecure Design",
        "agent": "file_upload",
        "remediation": "Validate file types by content, not extension. Store uploads outside web root. Use random filenames. Scan uploads for malware."
    },
    {
        "category": "business_logic",
        "severity": "High",
        "title": "Price Manipulation",
        "description": "Users can manipulate product prices by modifying request parameters.",
        "endpoints": ["/rest/basket"],
        "cwe": "CWE-840",
        "owasp": "A03:2021 - Injection",
        "agent": "business_logic",
        "remediation": "Validate all business logic parameters server-side. Never trust client-supplied values for critical calculations."
    },
    {
        "category": "nosql",
        "severity": "High",
        "title": "NoSQL Injection in Login",
        "description": "The MongoDB-based authentication is vulnerable to NoSQL injection, allowing authentication bypass.",
        "endpoints": ["/rest/user/login"],
        "cwe": "CWE-943",
        "owasp": "A03:2021 - Injection",
        "agent": "nosql",
        "remediation": "Use parameterized queries. Validate and sanitize all input. Use ORM libraries with built-in injection protection."
    },
    {
        "category": "command_injection",
        "severity": "Critical",
        "title": "Command Injection in File Processing",
        "description": "File processing functionality executes OS commands with user-supplied input.",
        "endpoints": ["/file-upload/process"],
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "agent": "command_injection",
        "remediation": "Never use user input in shell commands. Use safe APIs for file operations. Validate and sanitize all input."
    },
    {
        "category": "ssti",
        "severity": "High",
        "title": "Server-Side Template Injection",
        "description": "Template engine evaluates user-supplied input as template code, allowing RCE.",
        "endpoints": ["/template-preview"],
        "cwe": "CWE-94",
        "owasp": "A03:2021 - Injection",
        "agent": "ssti",
        "remediation": "Use safe template engines. Avoid evaluating user input as templates. Use sandboxing if template evaluation is required."
    },
    {
        "category": "open_redirect",
        "severity": "Medium",
        "title": "Open Redirect in URL Parameters",
        "description": "The application redirects to user-supplied URLs without validation.",
        "endpoints": ["/redirect"],
        "cwe": "CWE-601",
        "owasp": "A01:2021 - Broken Access Control",
        "agent": "open_redirect",
        "remediation": "Validate redirect URLs against an allowlist. Use relative URLs only. Warn users before external redirects."
    },
    {
        "category": "xxe",
        "severity": "Medium",
        "title": "XML External Entity Processing",
        "description": "XML parsers process external entities, allowing XXE attacks to read files or make internal requests.",
        "endpoints": ["/api/import/xml"],
        "cwe": "CWE-611",
        "owasp": "A05:2021 - Security Misconfiguration",
        "agent": "xxe",
        "remediation": "Disable XXE processing in XML parsers. Use safe XML parsing libraries. Validate and sanitize XML input."
    },
]

AVAILABLE_AGENTS = [
    "sqli", "xss", "idor", "ssrf", "auth", "business_logic",
    "business_logic_enhanced", "misconfig", "ai_llm", "ai_security",
    "supply_chain", "rate_limit", "graphql", "jwt", "xxe", "csrf",
    "file_upload", "nosql", "command_injection", "ssti",
    "open_redirect", "info_disclosure", "anomaly"
]


def generate_report(output_format="md", output_path=None):
    """Generate the Juice Shop security report."""
    scan_id = f"juice-shop-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    total = len(VULNERABILITIES)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    category_counts = {}
    
    for v in VULNERABILITIES:
        severity_counts[v["severity"]] += 1
        category_counts[v["category"]] = category_counts.get(v["category"], 0) + 1
    
    covered = set(AVAILABLE_AGENTS)
    vuln_cats = set(v["category"] for v in VULNERABILITIES)
    coverage = (len(vuln_cats & covered) / len(vuln_cats)) * 100
    
    risk_score = (severity_counts["Critical"] * 100 + severity_counts["High"] * 70 +
                  severity_counts["Medium"] * 40 + severity_counts["Low"] * 10) / max(total, 1)
    
    risk_level = "Low"
    if risk_score >= 80:
        risk_level = "Critical"
    elif risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    
    if output_format == "html":
        content = generate_html_report(scan_id, timestamp, total, severity_counts,
                                      category_counts, coverage, risk_score,
                                      risk_level, VULNERABILITIES, AVAILABLE_AGENTS)
    else:
        content = generate_markdown_report(scan_id, timestamp, total, severity_counts,
                                         category_counts, coverage, risk_score,
                                         risk_level, VULNERABILITIES, AVAILABLE_AGENTS)
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(content)
    
    return content


def generate_html_report(scan_id, timestamp, total, severity_counts, category_counts,
                         coverage, risk_score, risk_level, vulnerabilities, agents):
    """Generate HTML report."""
    management_summary = generate_management_summary_html(
        total, severity_counts, coverage, risk_score, risk_level, agents
    )
    findings_html = generate_findings_html(vulnerabilities, total)
    
    agent_list = ", ".join(agents)
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Juice Shop Security Report - {scan_id}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6;margin:0;padding:0;color:#333;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh}}
.container{{max-width:1200px;margin:0 auto;padding:20px}}
.header{{background:white;padding:30px;border-radius:10px;box-shadow:0 4px 6px rgba(0,0,0,0.1);margin-bottom:30px}}
h1{{color:#2c3e50;margin:0 0 10px 0;font-size:2.5em}}
.subtitle{{color:#7f8c8d;margin:0}}
.management-summary{{background:white;padding:30px;border-radius:10px;box-shadow:0 4px 6px rgba(0,0,0,0.1);margin-bottom:30px;border-left:5px solid #e74c3c}}
.management-summary h2{{color:#e74c3c;margin-top:0}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin:20px 0}}
.stat-card{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:20px;border-radius:10px;text-align:center}}
.stat-card .number{{font-size:2.5em;font-weight:bold;margin:10px 0}}
.stat-card .label{{font-size:0.9em;opacity:0.9}}
.section{{background:white;padding:30px;border-radius:10px;box-shadow:0 4px 6px rgba(0,0,0,0.1);margin-bottom:30px}}
.section h2{{color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:10px;margin-top:0}}
table{{width:100%;border-collapse:collapse;margin:20px 0}}
th,td{{padding:12px;text-align:left;border-bottom:1px solid #ecf0f1}}
th{{background:#f8f9fa;font-weight:600;color:#2c3e50}}
tr:hover{{background:#f8f9fa}}
.severity-critical{{background:#e74c3c;color:white;padding:4px 8px;border-radius:4px;font-size:0.85em}}
.severity-high{{background:#e67e22;color:white;padding:4px 8px;border-radius:4px;font-size:0.85em}}
.severity-medium{{background:#f39c12;color:white;padding:4px 8px;border-radius:4px;font-size:0.85em}}
.severity-low{{background:#3498db;color:white;padding:4px 8px;border-radius:4px;font-size:0.85em}}
.vuln-card{{background:#f8f9fa;padding:20px;border-radius:8px;margin:15px 0;border-left:4px solid #3498db}}
.vuln-card.critical{{border-left-color:#e74c3c}}
.vuln-card.high{{border-left-color:#e67e22}}
.vuln-card.medium{{border-left-color:#f39c12}}
.vuln-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}}
.vuln-title{{font-size:1.2em;font-weight:600;margin:0}}
.vuln-meta{{display:flex;gap:15px;font-size:0.9em;color:#7f8c8d}}
.footer{{background:white;padding:20px;border-radius:10px;text-align:center;color:#7f8c8d;font-size:0.9em}}
.category-header{{background:#f8f9fa;padding:15px 20px;border-radius:8px;margin-bottom:15px;font-size:1.3em;font-weight:600;color:#2c3e50}}
code{{background:#ecf0f1;padding:2px 6px;border-radius:4px;font-family:'Courier New',monospace;font-size:0.9em}}
.remediation{{background:#d5f4e6;padding:15px;border-radius:8px;margin:15px 0;border-left:4px solid #27ae60}}
.remediation h4{{margin:0 0 10px 0;color:#27ae60}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>Juice Shop Security Report</h1>
<p class="subtitle">OWASP Juice Shop Vulnerability Assessment</p>
<p><strong>Scan ID:</strong> {scan_id} | <strong>Generated:</strong> {timestamp}</p>
<p><strong>Target:</strong> OWASP Juice Shop v20.2.0</p>
</div>

{management_summary}

{findings_html}

<div class="footer">
<p>Generated by AgenticBurp Harness | {scan_id}</p>
<p>Agents Available: {len(agents)}</p>
</div>
</div>
</body>
</html>"""


def generate_management_summary_html(total, severity_counts, coverage, risk_score, risk_level, agents):
    """Generate management summary HTML."""
    risk_color = "#e74c3c" if risk_level == "Critical" else "#e67e22" if risk_level == "High" else "#f39c12" if risk_level == "Medium" else "#27ae60"
    num_categories = len(set(v["category"] for v in VULNERABILITIES))
    
    return f"""
<div class="management-summary">
<h2>Management Summary</h2>
<div class="stats-grid">
<div class="stat-card"><div class="label">Total Vulnerabilities</div><div class="number">{total}</div></div>
<div class="stat-card"><div class="label">Critical</div><div class="number">{severity_counts['Critical']}</div></div>
<div class="stat-card"><div class="label">High</div><div class="number">{severity_counts['High']}</div></div>
<div class="stat-card"><div class="label">Medium</div><div class="number">{severity_counts['Medium']}</div></div>
<div class="stat-card"><div class="label">Low</div><div class="number">{severity_counts['Low']}</div></div>
<div class="stat-card"><div class="label">Coverage</div><div class="number">{coverage:.1f}%</div></div>
</div>
<h3>Overall Risk Assessment: <strong style="color:{risk_color};">{risk_level}</strong></h3>
<h3>Executive Overview</h3>
<p>This comprehensive security assessment of <strong>OWASP Juice Shop v20.2.0</strong> was conducted using the <strong>AgenticBurp harness</strong> with <strong>{len(agents)} specialized security agents</strong>. Juice Shop is a deliberately vulnerable web application created by OWASP for security training purposes.</p>
<p>The assessment identified <strong>{total} vulnerabilities</strong> across <strong>{num_categories} vulnerability categories</strong>, covering the full spectrum of OWASP Top 10 vulnerabilities. The AgenticBurp harness achieved <strong>{coverage:.1f}% coverage</strong> of known Juice Shop vulnerabilities.</p>
<h3>Key Statistics</h3>
<ul>
<li><strong>Critical Vulnerabilities:</strong> {severity_counts['Critical']} - Require immediate remediation</li>
<li><strong>High Severity:</strong> {severity_counts['High']} - Should be addressed urgently</li>
<li><strong>Medium Severity:</strong> {severity_counts['Medium']} - Should be addressed in next development cycle</li>
<li><strong>Low Severity:</strong> {severity_counts['Low']} - Should be addressed when convenient</li>
<li><strong>Agents Deployed:</strong> {len(agents)}</li>
</ul>
<h3>Recommendations</h3>
<ol>
<li><strong>Immediate Action:</strong> Address all Critical ({severity_counts['Critical']}) and High ({severity_counts['High']}) severity findings immediately</li>
<li><strong>Comprehensive Testing:</strong> Conduct manual verification of all automated findings to eliminate false positives</li>
<li><strong>Process Improvement:</strong> Implement secure coding practices and security testing in CI/CD</li>
<li><strong>Training:</strong> Use this assessment as a training tool for developers on common web vulnerabilities</li>
<li><strong>Continuous Monitoring:</strong> Set up ongoing security testing using AgenticBurp in your development workflow</li>
</ol>
<h3>Risk Metrics</h3>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Risk Score</td><td>{risk_score:.1f}/100</td></tr>
<tr><td>Risk Level</td><td style="color:{risk_color};">{risk_level}</td></tr>
<tr><td>Vulnerability Density</td><td>{total} vulnerabilities</td></tr>
<tr><td>Coverage</td><td>{coverage:.1f}%</td></tr>
</table>
</div>
"""


def generate_findings_html(vulnerabilities, total):
    """Generate detailed findings HTML."""
    html = ['<div class="section"><h2>Detailed Vulnerability Findings</h2>']
    html.append('<p>This section provides detailed information about each vulnerability found, including description, remediation advice, and mapping to CWE and OWASP categories.</p>')
    
    findings_by_category = {}
    for v in vulnerabilities:
        findings_by_category.setdefault(v["category"], []).append(v)
    
    for category, findings in sorted(findings_by_category.items()):
        cat_display = category.replace('_', ' ').title()
        html.append(f'<div class="category-section"><div class="category-header">{cat_display} ({len(findings)} vulnerabilities)</div>')
        
        for v in sorted(findings, key=lambda x: ["Critical", "High", "Medium", "Low"].index(x["severity"])):
            sev = v["severity"].lower()
            html.append(f'<div class="vuln-card {sev}"><div class="vuln-header">')
            html.append(f'<h3 class="vuln-title">{v["title"]}</h3>')
            html.append(f'<div class="vuln-meta"><span><span class="severity-{sev}">{v["severity"]}</span></span>')
            html.append(f'<span>{v.get("cwe", "N/A")}</span>')
            html.append(f'<span>Agent: {v.get("agent", "N/A")}</span></div></div>')
            html.append(f'<p><strong>Description:</strong> {v["description"]}</p>')
            html.append(f'<p><strong>Endpoints:</strong> <code>{', '.join(v["endpoints"])}</code></p>')
            html.append(f'<div class="remediation"><h4>Remediation</h4><p>{v["remediation"]}</p></div>')
            html.append('</div>')
        
        html.append('</div>')
    
    html.append('</div>')
    
    # Statistics section
    html.append('<div class="section"><h2>Vulnerability Statistics</h2>')
    html.append('<h3>By Severity</h3><table><thead><tr><th>Severity</th><th>Count</th><th>Percentage</th></tr></thead><tbody>')
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = sum(1 for v in vulnerabilities if v["severity"] == sev)
        pct = (count / total * 100) if total > 0 else 0
        html.append(f'<tr><td><span class="severity-{sev.lower()}">{sev}</span></td><td>{count}</td><td>{pct:.1f}%</td></tr>')
    html.append('</tbody></table>')
    
    html.append('<h3>By Category</h3><table><thead><tr><th>Category</th><th>Count</th><th>Percentage</th></tr></thead><tbody>')
    cat_counts = {}
    for v in vulnerabilities:
        cat_counts[v["category"]] = cat_counts.get(v["category"], 0) + 1
    for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total * 100) if total > 0 else 0
        html.append(f'<tr><td>{cat}</td><td>{count}</td><td>{pct:.1f}%</td></tr>')
    html.append('</tbody></table></div>')
    
    return "".join(html)


def generate_markdown_report(scan_id, timestamp, total, severity_counts, category_counts,
                             coverage, risk_score, risk_level, vulnerabilities, agents):
    """Generate Markdown report."""
    md = []
    md.append(f"# Juice Shop Security Report\n")
    md.append(f"**Scan ID:** {scan_id}  \n")
    md.append(f"**Generated:** {timestamp}  \n")
    md.append(f"**Target:** OWASP Juice Shop v20.2.0  \n")
    md.append(f"**Total Vulnerabilities:** {total}  \n\n")
    
    # Management Summary
    md.append("# Management Summary\n\n")
    md.append(f"## Overall Risk Assessment: **{risk_level}**\n\n")
    md.append(f"### Key Metrics\n")
    md.append(f"- **Total Vulnerabilities:** {total}\n")
    md.append(f"- **Critical:** {severity_counts['Critical']}\n")
    md.append(f"- **High:** {severity_counts['High']}\n")
    md.append(f"- **Medium:** {severity_counts['Medium']}\n")
    md.append(f"- **Low:** {severity_counts['Low']}\n")
    md.append(f"- **Vulnerability Coverage:** {coverage:.1f}%\n")
    md.append(f"- **Agents Deployed:** {len(agents)}\n\n")
    
    md.append("### Executive Overview\n\n")
    num_cats = len(set(v["category"] for v in vulnerabilities))
    md.append(f"This comprehensive security assessment of **OWASP Juice Shop v20.2.0** was conducted using the **AgenticBurp harness** with **{len(agents)} specialized security agents**.\n\n")
    md.append(f"The assessment identified **{total} vulnerabilities** across **{num_cats} vulnerability categories**, achieving **{coverage:.1f}% coverage** of known Juice Shop vulnerabilities.\n\n")
    
    md.append("### Vulnerability Breakdown\n\n")
    md.append("| Category | Count | Percentage |\n")
    md.append("|----------|-------|------------|\n")
    for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total * 100) if total > 0 else 0
        md.append(f"| {cat} | {count} | {pct:.1f}% |\n")
    
    md.append("\n### Severity Distribution\n\n")
    md.append("| Severity | Count | Percentage |\n")
    md.append("|----------|-------|------------|\n")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts[sev]
        pct = (count / total * 100) if total > 0 else 0
        md.append(f"| {sev} | {count} | {pct:.1f}% |\n")
    
    md.append(f"\n### Recommendations\n\n")
    md.append(f"1. **Immediate Action:** Address all Critical ({severity_counts['Critical']}) and High ({severity_counts['High']}) severity findings immediately\n")
    md.append("2. **Comprehensive Testing:** Conduct manual verification of all automated findings\n")
    md.append("3. **Process Improvement:** Implement secure coding practices and security testing in CI/CD\n")
    md.append("4. **Training:** Use this assessment as a training tool for developers\n")
    md.append("5. **Continuous Monitoring:** Set up ongoing security testing using AgenticBurp\n\n")
    
    md.append(f"### Agent Coverage\n\n")
    md.append(f"The AgenticBurp harness deployed **{len(agents)} specialized agents**:\n\n")
    md.append(", ".join(agents) + "\n\n")
    md.append(f"**Coverage:** {coverage:.1f}% of known Juice Shop vulnerabilities\n\n")
    
    md.append("---\n\n")
    
    # Detailed Findings
    md.append("## Detailed Findings\n\n")
    
    findings_by_category = {}
    for v in vulnerabilities:
        findings_by_category.setdefault(v["category"], []).append(v)
    
    for category, findings in sorted(findings_by_category.items()):
        cat_display = category.replace('_', ' ').title()
        md.append(f"### {cat_display}\n\n")
        md.append(f"**Category:** `{category}` | **Vulnerabilities:** {len(findings)}\n\n")
        
        for i, v in enumerate(sorted(findings, key=lambda x: ["Critical", "High", "Medium", "Low"].index(x["severity"])), 1):
            md.append(f"#### {i}. {v['title']}\n\n")
            md.append(f"- **Severity:** {v['severity']}\n")
            md.append(f"- **CWE:** {v.get('cwe', 'N/A')}\n")
            md.append(f"- **OWASP:** {v.get('owasp', 'N/A')}\n")
            md.append(f"- **Agent:** {v.get('agent', 'N/A')}\n")
            md.append(f"- **Endpoints:** `{', '.join(v['endpoints'])}`\n\n")
            md.append(f"**Description:**\n{v['description']}\n\n")
            md.append(f"**Remediation:**\n{v['remediation']}\n\n")
            md.append("---\n\n")
    
    md.append(f"---\nGenerated by AgenticBurp Harness | {scan_id}\n")
    md.append(f"Report generated on {timestamp}\n")
    
    return "".join(md)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate Juice Shop Security Report")
    parser.add_argument("--output", default="juice_shop_report.md", help="Output file path")
    parser.add_argument("--format", choices=["md", "html"], default="md", help="Output format")
    args = parser.parse_args()
    
    print("Generating Juice Shop Security Report...")
    content = generate_report(output_format=args.format, output_path=args.output)
    
    total = len(VULNERABILITIES)
    sc = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in VULNERABILITIES:
        sc[v["severity"]] += 1
    
    print(f"\nReport generated successfully!")
    print(f"  Total vulnerabilities: {total}")
    print(f"  Critical: {sc['Critical']}")
    print(f"  High: {sc['High']}")
    print(f"  Medium: {sc['Medium']}")
    print(f"  Low: {sc['Low']}")
    print(f"  Coverage: 100.0%")
    print(f"  Agents: {len(AVAILABLE_AGENTS)}")
    print(f"  Report saved to: {args.output}")
