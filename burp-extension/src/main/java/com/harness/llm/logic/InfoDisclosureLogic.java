package com.harness.llm.logic;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive scan for info_disclosure_scan. Montoya-free, no new request
 * needed -- classifies the response body Burp already captured.
 *
 * Deliberately pattern-based and conservative rather than "any file path
 * looking string": stack traces and framework error pages are specific,
 * low-false-positive signals. A bare absolute path substring (e.g.
 * "/home/") is common enough in legitimate content (a blog post, a
 * tutorial, a URL) that including it here would make this noisy rather
 * than useful -- CONFIRMED-tier patterns below are all things that
 * essentially never appear in normal application output.
 */
public final class InfoDisclosureLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private record NamedPattern(String label, Pattern pattern, Verdict tier) {}

    private static final List<NamedPattern> PATTERNS = List.of(
            new NamedPattern("Java stack trace", Pattern.compile("\\bat [\\w.$]+\\([\\w.]+\\.java:\\d+\\)"), Verdict.CONFIRMED),
            new NamedPattern("Python traceback", Pattern.compile("Traceback \\(most recent call last\\):"), Verdict.CONFIRMED),
            new NamedPattern(".NET stack trace", Pattern.compile("\\bat System\\.[\\w.]+\\("), Verdict.CONFIRMED),
            new NamedPattern("PHP fatal error", Pattern.compile("(Fatal error|Warning|Notice): .+ in .+\\.php on line \\d+"), Verdict.CONFIRMED),
            new NamedPattern("Spring Boot default error page", Pattern.compile("Whitelabel Error Page"), Verdict.CONFIRMED),
            new NamedPattern("Node.js stack trace", Pattern.compile("at [\\w.]+ \\([^)]+:\\d+:\\d+\\)"), Verdict.CONFIRMED),
            new NamedPattern("Ruby stack trace", Pattern.compile("\\.rb:\\d+:in `"), Verdict.CONFIRMED),
            new NamedPattern("SQL error message", Pattern.compile("(SQL syntax|ORA-\\d{5}|SQLSTATE\\[|pg_query\\(\\)|mysqli?_)", Pattern.CASE_INSENSITIVE), Verdict.CONFIRMED),
            new NamedPattern("Exposed absolute Unix path in an error-shaped context", Pattern.compile("(?i)(error|exception|failed).{0,80}(/home/|/var/www/|/usr/local/)"), Verdict.SUPPORTED),
            new NamedPattern("Exposed absolute Windows path in an error-shaped context", Pattern.compile("(?i)(error|exception|failed).{0,80}[A-Z]:\\\\Users\\\\"), Verdict.SUPPORTED)
    );

    private InfoDisclosureLogic() {}

    public static Evidence evaluate(String body) {
        if (body == null || body.isEmpty()) {
            return new Evidence(Verdict.REJECTED, 0.7, false, "Response body is empty -- nothing to scan.", "");
        }

        Map<String, String> confirmedMatches = new LinkedHashMap<>();
        Map<String, String> supportedMatches = new LinkedHashMap<>();
        for (NamedPattern np : PATTERNS) {
            Matcher m = np.pattern().matcher(body);
            if (m.find()) {
                String snippet = body.substring(m.start(), Math.min(body.length(), m.end() + 40));
                if (np.tier() == Verdict.CONFIRMED) confirmedMatches.put(np.label(), snippet);
                else supportedMatches.put(np.label(), snippet);
            }
        }

        if (!confirmedMatches.isEmpty()) {
            String labels = String.join(", ", confirmedMatches.keySet());
            String detail = confirmedMatches.entrySet().stream()
                    .map(e -> e.getKey() + ": " + e.getValue())
                    .reduce((a, b) -> a + " | " + b).orElse("");
            return new Evidence(Verdict.CONFIRMED, 0.9, true,
                    "Response body contains a specific, low-false-positive information disclosure "
                            + "pattern: " + labels + ".", detail);
        }
        if (!supportedMatches.isEmpty()) {
            String labels = String.join(", ", supportedMatches.keySet());
            String detail = supportedMatches.entrySet().stream()
                    .map(e -> e.getKey() + ": " + e.getValue())
                    .reduce((a, b) -> a + " | " + b).orElse("");
            return new Evidence(Verdict.SUPPORTED, 0.55, false,
                    "Response body contains a weaker information disclosure signal: " + labels
                            + " -- worth a manual look, less specific than a real stack trace.", detail);
        }
        return new Evidence(Verdict.REJECTED, 0.75, false,
                "No recognized stack trace, framework error page, or SQL error pattern found in the "
                        + "response body.", "");
    }
}
