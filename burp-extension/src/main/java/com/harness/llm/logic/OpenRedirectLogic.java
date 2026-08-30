package com.harness.llm.logic;

/**
 * Classification logic for open_redirect_validation. Montoya-free. The
 * executor mutates a URL-like parameter (see SsrfCallbackLogic's param-
 * name heuristic, reused here rather than duplicated -- SSRF and open
 * redirect target near-identically-named parameters) to a distinct,
 * harness-controlled external URL and resends; this class decides what
 * the resulting status/Location header pair means.
 */
public final class OpenRedirectLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, INVALID, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private OpenRedirectLogic() {}

    /**
     * @param injectedUrl the external URL the executor placed in the candidate parameter
     * @param statusCode the response status code
     * @param location the response's Location header value, or null if absent
     * @param paramName the parameter that was mutated
     */
    public static Evidence evaluate(String injectedUrl, int statusCode, String location, String paramName) {
        boolean isRedirectStatus = statusCode >= 300 && statusCode < 400;
        if (!isRedirectStatus) {
            return new Evidence(Verdict.REJECTED, 0.7, false,
                    "Response status " + statusCode + " is not a redirect -- the mutated parameter '"
                            + paramName + "' did not cause a redirect to the injected external URL.", "");
        }
        if (location == null) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "Response status was a redirect (" + statusCode + ") but carried no Location header "
                            + "-- cannot evaluate where it points.", "");
        }

        String normalizedLocation = location.trim();
        String normalizedInjected = injectedUrl.trim();
        boolean exactMatch = normalizedLocation.equalsIgnoreCase(normalizedInjected);
        boolean startsWithInjectedHost = normalizedLocation.toLowerCase().contains(hostOf(normalizedInjected).toLowerCase());

        if (exactMatch) {
            return new Evidence(Verdict.CONFIRMED, 0.9, true,
                    "The server issued a " + statusCode + " redirect with Location set exactly to the "
                            + "attacker-controlled external URL placed in parameter '" + paramName + "' -- "
                            + "confirmed open redirect, usable for phishing (a link to the trusted domain "
                            + "that silently forwards to an attacker site) or as a chain step for stealing "
                            + "OAuth tokens/authorization codes via a redirect_uri-style parameter.",
                    "Injected: " + injectedUrl + " | Location: " + location);
        }
        if (startsWithInjectedHost) {
            return new Evidence(Verdict.SUPPORTED, 0.6, false,
                    "The server issued a " + statusCode + " redirect whose Location header references the "
                            + "injected external host, but not as an exact match to what was submitted -- "
                            + "worth a manual check for how the URL was transformed.",
                    "Injected: " + injectedUrl + " | Location: " + location);
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "The server issued a redirect, but Location does not reference the injected external "
                        + "URL at all -- the parameter likely isn't used to build the redirect target, or "
                        + "the value is validated/rejected.",
                "Injected: " + injectedUrl + " | Location: " + location);
    }

    private static String hostOf(String url) {
        try {
            return java.net.URI.create(url).getHost() != null ? java.net.URI.create(url).getHost() : url;
        } catch (Exception e) {
            return url;
        }
    }
}
