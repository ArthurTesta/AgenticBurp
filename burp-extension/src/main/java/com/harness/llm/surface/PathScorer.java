package com.harness.llm.surface;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Deterministic, fast scoring of a URL/method (and optionally param names)
 * for "how interesting is this to look at first" -- runs locally on every
 * site-map entry with no network call, so it scales to hundreds of
 * endpoints. This is a prior for triage order, not a vulnerability
 * finding: it never claims something IS vulnerable, only that it's worth
 * a specialist agent's attention before the rest.
 *
 * Categories and keywords below are informed by where reported
 * vulnerabilities have concentrated in bug bounty/CVE data 2021-2025:
 * access control + misconfiguration surface (admin/debug/actuator/
 * swagger/graphql), object-identifier patterns (classic IDOR surface),
 * SSRF-shaped parameters, business-logic-shaped actions, and AI/LLM
 * feature endpoints (fastest-growing category).
 */
public class PathScorer {

    public enum Tier { CRITICAL, HIGH, MEDIUM, LOW }

    public record ScoredPath(
            String method,
            String url,
            double score,
            Tier tier,
            String category,
            List<String> reasons
    ) {}

    private record Rule(Pattern pattern, double weight, String category, String reason) {}

    private static final List<Rule> URL_RULES = List.of(
            // Misconfiguration / exposed management surface
            new Rule(Pattern.compile("/(actuator|management)(/|\\.|$)", 0), 0.9, "misconfig",
                    "Spring Boot actuator / management endpoint pattern"),
            new Rule(Pattern.compile("/(debug|trace|console)(/|\\.|$)", 0), 0.8, "misconfig",
                    "debug/trace/console path"),
            new Rule(Pattern.compile("/(swagger|openapi|api-docs)(/|\\.|$)", 0), 0.6, "misconfig",
                    "API schema/documentation endpoint (info disclosure + attack-surface map for free)"),
            new Rule(Pattern.compile("/graphql", 0), 0.7, "misconfig",
                    "GraphQL endpoint -- check for introspection"),
            new Rule(Pattern.compile("\\.(bak|old|orig|swp|~)$", 0), 0.8, "misconfig",
                    "backup/editor-artifact file extension"),
            new Rule(Pattern.compile("/\\.(git|env|svn|DS_Store)(/|\\.|$)", 0), 0.95, "misconfig",
                    "exposed VCS/config file"),
            new Rule(Pattern.compile("/(metrics|health|status|info)(/|\\.|$)", 0), 0.4, "misconfig",
                    "diagnostics endpoint -- often over-shares"),
            // Missed a real, live instance during testing against OWASP
            // Juice Shop: /ftp serves a directory listing and had no
            // matching rule at all. Anonymous file-listing endpoints
            // (ftp, files, uploads, backups used as a directory root) are
            // a distinct, common misconfig shape from the debug/actuator
            // rules above -- an open listing, not an exposed diagnostic.
            new Rule(Pattern.compile("/(ftp|files|backups?|uploads?)(/|\\.|$)", 0), 0.5, "misconfig",
                    "anonymous file-listing/upload directory pattern"),

            // Access control / IDOR surface -- numeric or UUID-like path segments
            new Rule(Pattern.compile("/(users?|accounts?|orders?|invoices?|documents?|files?)/\\d+(/|\\.|$)", 0),
                    0.6, "access_control", "numeric object ID in a resource path"),
            new Rule(Pattern.compile("/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(/|\\.|$)", 0),
                    0.5, "access_control", "UUID object identifier in path"),
            new Rule(Pattern.compile("/(admin|internal|staff|backoffice)(/|\\.|$)", 0), 0.7, "access_control",
                    "admin/internal-sounding path segment"),

            // SSRF-shaped surface
            new Rule(Pattern.compile("(?i)(url|callback|webhook|target|endpoint|fetch|proxy)=", 0), 0.6, "ssrf",
                    "URL-shaped query parameter name"),

            // Business logic action verbs
            new Rule(Pattern.compile("/(checkout|redeem|transfer|refund|approve|promote|coupon|discount)(/|\\.|$)", 0),
                    0.6, "business_logic", "state-changing action endpoint"),

            // AI/LLM feature surface (fastest-growing category)
            new Rule(Pattern.compile("(?i)/(chat|assistant|copilot|completion|generate|summarize|ask)(/|\\.|$)", 0),
                    0.7, "ai_llm", "AI/LLM feature path"),

            // Auth surface
            new Rule(Pattern.compile("/(login|logout|reset|forgot|oauth|token|session|mfa|2fa)(/|\\.|$)", 0),
                    0.4, "auth", "authentication/session-related path"),

            // File handling
            new Rule(Pattern.compile("(?i)/(upload|import|export|download)(/|\\.|$)", 0), 0.4, "file_handling",
                    "file upload/import/export endpoint"),

            // Supply chain: exposed dependency manifests/lockfiles and CI config.
            // Feeds the same category the harness's supply_chain agent and
            // deterministic GitHub Advisory lookup cover -- flagging these
            // here means the analyst sees them even before sending anything
            // to the harness.
            new Rule(Pattern.compile("(?i)/(package(-lock)?\\.json|yarn\\.lock|requirements\\.txt|" +
                    "pipfile\\.lock|gemfile\\.lock|go\\.(sum|mod)|composer\\.lock|cargo\\.lock)$", 0),
                    0.7, "supply_chain", "exposed dependency manifest/lockfile"),
            new Rule(Pattern.compile("(?i)/\\.github/workflows/.*\\.ya?ml$", 0), 0.8, "supply_chain",
                    "exposed GitHub Actions workflow file"),
            new Rule(Pattern.compile("(?i)/(\\.gitlab-ci\\.yml|jenkinsfile|\\.circleci/config\\.yml|" +
                    "azure-pipelines\\.yml)$", 0), 0.7, "supply_chain", "exposed CI/CD configuration"),

            // Legacy dangerous extensions -- found missing entirely while
            // testing against a real live app (Altoro Mutual serves
            // /cgi.exe): executable/legacy-script paths served directly
            // are themselves a red flag independent of anything else,
            // common on older IIS/CGI-based deployments.
            new Rule(Pattern.compile("(?i)\\.(exe|cgi|dll|pl|sh)(\\?|$)", 0), 0.6, "misconfig",
                    "legacy executable/script extension served directly")
    );

    private static final List<Rule> PARAM_NAME_RULES = List.of(
            new Rule(Pattern.compile("(?i)^(id|user_id|account_id|order_id|doc_id|file_id)$", 0),
                    0.4, "access_control", "identifier-shaped parameter name"),
            new Rule(Pattern.compile("(?i)^(role|is_admin|admin|status|price|amount|quantity|discount)$", 0),
                    0.5, "business_logic", "client-suppliable state/authorization-shaped parameter"),
            new Rule(Pattern.compile("(?i)(^(url|redirect|next|return_to|callback)$|.*(image|avatar|photo|picture).*)", 0),
                    0.5, "ssrf", "redirect/URL/image-fetch-shaped parameter name"),
            new Rule(Pattern.compile("(?i)^(q|query|search|sort|order|filter)$", 0),
                    0.3, "sqli", "query/sort/filter parameter -- common injection surface")
    );

    /**
     * @param method   HTTP method
     * @param url      full URL including query string
     * @param paramNames names of request parameters (query + body), if known; may be empty
     */
    public ScoredPath score(String method, String url, List<String> paramNames) {
        double total = 0.0;
        String bestCategory = "none";
        double bestCategoryWeight = 0.0;
        List<String> reasons = new ArrayList<>();

        for (Rule rule : URL_RULES) {
            if (rule.pattern().matcher(url).find()) {
                total += rule.weight();
                reasons.add(rule.reason());
                if (rule.weight() > bestCategoryWeight) {
                    bestCategoryWeight = rule.weight();
                    bestCategory = rule.category();
                }
            }
        }

        if (paramNames != null) {
            for (String p : paramNames) {
                for (Rule rule : PARAM_NAME_RULES) {
                    if (rule.pattern().matcher(p).matches()) {
                        total += rule.weight();
                        reasons.add(rule.reason() + " (param: " + p + ")");
                        if (rule.weight() > bestCategoryWeight) {
                            bestCategoryWeight = rule.weight();
                            bestCategory = rule.category();
                        }
                    }
                }
            }
        }

        // Mildly reward state-changing methods -- more consequential if
        // access control is missing than an equivalent GET.
        String m = method == null ? "" : method.toUpperCase(Locale.ROOT);
        if (m.equals("POST") || m.equals("PUT") || m.equals("PATCH") || m.equals("DELETE")) {
            total += 0.15;
            reasons.add("state-changing HTTP method (" + m + ")");
        }

        double score = Math.min(1.0, total);
        Tier tier = score >= 0.8 ? Tier.CRITICAL
                : score >= 0.5 ? Tier.HIGH
                : score >= 0.25 ? Tier.MEDIUM
                : Tier.LOW;

        return new ScoredPath(method, url, score, tier, bestCategory, reasons);
    }
}
