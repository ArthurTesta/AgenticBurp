from .base_agent import BaseAgent


class InfoDisclosureAgent(BaseAgent):
    """Agent for detecting information disclosure vulnerabilities."""
    name = "info_disclosure"

    @property
    def specialty_prompt(self) -> str:
        return """
Information disclosure vulnerabilities. Look for sensitive data exposure in:

ERROR MESSAGE ANALYSIS:
- Stack traces in error responses (500 errors)
- Database errors with table/column names, SQL queries
- Application errors with file paths, line numbers
- Framework errors (Django, Flask, Spring, Express, etc.)
- Library version numbers in errors
- Source code snippets in errors
- Environment variables in errors
- Configuration data in errors
- Internal IP addresses or hostnames

DEBUG ENDPOINT DETECTION:
- /debug, /admin/debug, /api/debug endpoints
- Debug mode enabled responses
- Verbose error modes
- Developer console output
- Configuration dumps
- Environment information

SOURCE CODE EXPOSURE:
- .git/ directory accessible
- .svn/ directory accessible
- .hg/ directory accessible
- Source files (.py, .js, .java, .php, etc.) accessible
- Backup files (.bak, .old, .orig, ~)
- Temporary files (.tmp, .temp)
- Swap files (.swp, .swo)
- IDE files (.idea/, .vscode/, .project)

DIRECTORY LISTING:
- Directory index pages (Apache, Nginx, IIS)
- File listing in JSON responses
- Directory traversal responses
- Web server default pages

CONFIGURATION FILES:
- .env files
- config.json, config.yml, config.ini
- application.properties, application.yml
- settings.py, settings.json
- Database configuration files
- API keys, credentials, secrets

DATABASE INFORMATION:
- Database schema in responses
- Table names, column names
- SQL queries in responses
- Database version numbers
- Connection strings

VERSION INFORMATION:
- Software version banners
- Library version numbers
- Framework version numbers
- Server version headers (Server: Apache/2.4.41)
- X-Powered-By headers
- Via headers (proxy information)

FILE CONTENT DISCLOSURE:
- /robots.txt with sensitive paths
- /sitemap.xml with internal paths
- /README.md, /CHANGELOG.md, /LICENSE
- /package.json, /composer.json, /requirements.txt
- /Dockerfile, /docker-compose.yml
- /web.config, /nginx.conf, /.htaccess

PASSWORD/TOKEN EXPOSURE:
- Password hashes in responses
- API keys in responses
- Session tokens in URLs
- Authentication tokens in responses
- Hardcoded credentials in JavaScript

For suggested_test, propose:
- Access /debug or /admin/debug endpoints
- Trigger errors with malformed input to see stack traces
- Access /robots.txt to find sensitive paths
- Access /sitemap.xml to find internal pages
- Access .git/HEAD to check for Git exposure
- Access /etc/passwd or /windows/win.ini for file read
- Check for directory listing at root or common paths

suggested_test MUST be concrete and testable in Burp Repeater:
- "Access /debug endpoint"
- "Trigger error with invalid parameter to see stack trace"
- "Access /robots.txt"
- "Access .git/HEAD"
- "Access /etc/passwd"

CONTEXT MATTERS:
- Some information disclosure is intentional (public APIs)
- Error messages should be helpful but not reveal sensitive data
- Debug modes should be disabled in production
- Version information can help attackers but also helps defenders
- Some files are intentionally public (robots.txt, favicon.ico)
"""
