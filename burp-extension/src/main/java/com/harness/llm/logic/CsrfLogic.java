package com.harness.llm.logic;

import java.util.regex.Pattern;

/**
 * Classification logic for csrf_validation. Montoya-free.
 *
 * Scope, stated explicitly because it's easy to over-claim here: this
 * only evaluates classic, cookie-based session CSRF on state-changing
 * requests. A request authenticated purely by a Bearer token or a
 * custom API key isn't meaningfully exposed to cross-site request
 * forgery the same way -- browsers don't auto-attach those headers to
 * a cross-origin request the way they do cookies, so REJECTED there
 * means "not applicable", not "definitely safe" (a CORS misconfiguration
 * could still expose it a different way -- that's
 * cors_misconfiguration_detection's job, not this one's).
 */
public final class CsrfLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INVALID }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private static final Pattern SAFE_METHOD = Pattern.compile("^(GET|HEAD|OPTIONS)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern CSRF_TOKEN_NAME = Pattern.compile(
            "(?i)^(csrf[_-]?token|x[_-]?csrf[_-]?token|xsrf[_-]?token|x[_-]?xsrf[_-]?token|"
                    + "authenticity_token|csrfmiddlewaretoken|__requestverificationtoken|_csrf)$");

    private CsrfLogic() {}

    public static boolean isSafeMethod(String method) {
        return method != null && SAFE_METHOD.matcher(method.trim()).matches();
    }

    public static boolean looksLikeCsrfTokenName(String name) {
        return name != null && CSRF_TOKEN_NAME.matcher(name.trim()).matches();
    }

    /**
     * @param method the request method
     * @param cookieAuthPresent true if the request carries a session cookie (vs. pure Bearer/API-key auth)
     * @param tokenFound true if a CSRF-token-shaped header or body/form parameter was found
     * @param originalStatus status code of the original request (with the real token, if any)
     * @param mutatedStatus status code after removing/mutating the token, or -1 if that probe wasn't run
     */
    public static Evidence evaluate(String method, boolean cookieAuthPresent, boolean tokenFound,
                                     int originalStatus, int mutatedStatus) {
        if (isSafeMethod(method)) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "Method " + method + " is a safe/idempotent method -- CSRF protection is conventionally "
                            + "not expected here (a state change performed on GET/HEAD/OPTIONS would be a "
                            + "separate, more unusual finding in its own right).", "");
        }
        if (!cookieAuthPresent) {
            return new Evidence(Verdict.REJECTED, 0.7, false,
                    "This request is not cookie-authenticated -- classic CSRF (relying on a browser "
                            + "auto-attaching session credentials to a cross-site request) does not apply the "
                            + "same way to Bearer-token/API-key authentication. Not evidence the endpoint is "
                            + "safe from every cross-origin issue, just that this specific check doesn't apply.",
                    "");
        }
        if (tokenFound) {
            if (mutatedStatus < 0) {
                return new Evidence(Verdict.SUPPORTED, 0.4, false,
                        "A CSRF-token-shaped field was found but the removal probe was not run -- presence "
                                + "of a token field doesn't by itself prove it's actually validated.", "");
            }
            boolean stillSucceeded = mutatedStatus == originalStatus
                    || (mutatedStatus >= 200 && mutatedStatus < 300 && originalStatus >= 200 && originalStatus < 300);
            if (stillSucceeded) {
                return new Evidence(Verdict.CONFIRMED, 0.88, true,
                        "The request still succeeded (status " + mutatedStatus + ") after the CSRF token "
                                + "field was removed/invalidated -- a token is present in the form but not "
                                + "actually enforced server-side.",
                        "original status=" + originalStatus + " | with token removed=" + mutatedStatus);
            }
            return new Evidence(Verdict.REJECTED, 0.85, false,
                    "The request was rejected (status " + mutatedStatus + ", was " + originalStatus
                            + " with the real token) after the CSRF token field was removed -- the token "
                            + "appears to be genuinely validated.",
                    "original status=" + originalStatus + " | with token removed=" + mutatedStatus);
        }
        return new Evidence(Verdict.SUPPORTED, 0.5, false,
                "This is a cookie-authenticated, state-changing request with no CSRF-token-shaped header "
                        + "or form field observed -- a passive signal, not a proven exploit. The application "
                        + "could still be protected by a mechanism this check doesn't see (e.g. a strict "
                        + "SameSite cookie attribute, or a custom header check this name pattern doesn't "
                        + "recognize).", "");
    }
}
