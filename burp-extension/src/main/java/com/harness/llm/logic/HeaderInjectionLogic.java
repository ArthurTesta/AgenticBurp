package com.harness.llm.logic;

/**
 * Classification logic for header_injection_validation (CRLF / HTTP
 * response-header injection). Montoya-free.
 *
 * Scope: the HTTP-response-header variant only, not the email/SMTP
 * header-injection variant the same specialist agent also covers (see
 * agents/header_injection_agent.py's own docstring) -- an outbound
 * email's headers can't be observed from the HTTP exchange the harness
 * captures, so there's nothing for a Burp executor to confirm there;
 * that variant stays analyst-confirmed only.
 *
 * Technique: the executor appends a CRLF sequence (`%0d%0a`, the
 * transport-safe encoded form a real attacker would actually send --
 * see the executor method's own comment for why a literal \r\n
 * wouldn't survive to the target the same way) followed by a
 * harness-chosen marker header name/value to a URL/redirect-shaped
 * parameter (reusing SsrfCallbackLogic's param-name heuristic, the same
 * reuse OpenRedirectLogic already does, since redirect-style params are
 * this bug's highest-yield target per the agent's own guidance) and
 * resends. If the server decodes the value and reflects it into a
 * response header without stripping the newlines, the marker header
 * appears as a genuinely separate, parsed response header -- not just
 * as a substring inside some other header's value -- which is the
 * specific, hard-to-fake signal this class looks for.
 */
public final class HeaderInjectionLogic {

    public enum Verdict { CONFIRMED, REJECTED, INVALID }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private HeaderInjectionLogic() {}

    public static String buildPayload(String originalValue, String markerHeaderName, String markerHeaderValue) {
        return originalValue + "%0d%0a" + markerHeaderName + ": " + markerHeaderValue;
    }

    /**
     * @param baselineHasMarkerHeader whether the ORIGINAL, unmodified response already carried a
     *                                header with this exact name -- checked directly rather than
     *                                assumed, since a false "confirmed" from a marker name that
     *                                happened to already exist would be worse than not trying.
     * @param mutatedMarkerHeaderValue the mutated response's value for the marker header name, or
     *                                 null if that header isn't present at all.
     */
    public static Evidence evaluate(String paramName, String markerHeaderName, String markerHeaderValue,
                                     boolean baselineHasMarkerHeader, String mutatedMarkerHeaderValue) {
        if (baselineHasMarkerHeader) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "The baseline (unmodified) response already carried a header named '" + markerHeaderName
                            + "' before any injection was attempted -- can't use it as a marker for this request.",
                    "");
        }

        boolean injected = mutatedMarkerHeaderValue != null && mutatedMarkerHeaderValue.trim().equals(markerHeaderValue);
        if (injected) {
            return new Evidence(Verdict.CONFIRMED, 0.9, true,
                    "Appending a CRLF sequence followed by a harness-chosen header ('" + markerHeaderName + ": "
                            + markerHeaderValue + "') to parameter '" + paramName + "' caused that exact header "
                            + "to appear as a genuine, separately-parsed response header, not merely as text inside "
                            + "another header's value -- confirmed CRLF/HTTP response-header injection. An attacker "
                            + "can use this to set arbitrary additional response headers (e.g. a forged Set-Cookie), "
                            + "or to split the response and inject a fake body (response splitting).",
                    "param=" + paramName);
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "Injecting a CRLF sequence into parameter '" + paramName + "' did not cause the marker header to "
                        + "appear in the response -- no evidence the newline characters reached response-header "
                        + "construction unsanitized.",
                "param=" + paramName);
    }
}
