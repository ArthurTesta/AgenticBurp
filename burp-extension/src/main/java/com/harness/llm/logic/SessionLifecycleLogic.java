package com.harness.llm.logic;

import java.util.Locale;

/**
 * Decision logic for two session-lifecycle checks the WSTG coverage
 * review flagged as unconfirmed for this harness: session fixation
 * (does the server issue a NEW session identifier after login, or
 * does it keep using the pre-authentication one?) and post-logout
 * session reuse (does a logout request actually invalidate the
 * session server-side, or does the old cookie keep working?).
 *
 * These don't fit {@link IdentityCompareLogic}'s model -- that class
 * compares two DIFFERENT identities against each other at the same
 * point in time; this class compares the SAME identity's session
 * across a lifecycle event (login or logout), at two different
 * points in time. Different evidence shape, so a separate class
 * rather than forcing it into the existing one's parameter list.
 */
public final class SessionLifecycleLogic {

    public enum Verdict { CONFIRMED, REJECTED, INCONCLUSIVE, INVALID }

    public static final class Evidence {
        public final Verdict verdict;
        public final double confidence;
        public final boolean confirmed;
        public final String summary;
        public final String detail;

        Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {
            this.verdict = verdict;
            this.confidence = confidence;
            this.confirmed = confirmed;
            this.summary = summary;
            this.detail = detail;
        }
    }

    private SessionLifecycleLogic() {}

    /**
     * @param preLoginSessionValue  the session cookie's value BEFORE authenticating
     * @param postLoginSessionValue the same-named cookie's value AFTER authenticating
     */
    public static Evidence evaluateSessionFixation(String preLoginSessionValue, String postLoginSessionValue) {
        if (isBlank(preLoginSessionValue) || isBlank(postLoginSessionValue)) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "Session fixation check requires a captured session cookie value from both "
                            + "before and after authentication; one or both is missing.", "");
        }
        if (preLoginSessionValue.equals(postLoginSessionValue)) {
            return new Evidence(Verdict.CONFIRMED, 0.9, true,
                    "The session identifier is IDENTICAL before and after login -- the server does not "
                            + "rotate the session ID on authentication. An attacker who can set a victim's "
                            + "pre-login session value (via a URL parameter, a non-HttpOnly cookie write, or "
                            + "session-fixation-friendly session initialization) can pre-establish a known "
                            + "session ID and have it become the victim's authenticated session once they log in.",
                    detailOf("preLoginSession", preLoginSessionValue, "postLoginSession", postLoginSessionValue));
        }
        return new Evidence(Verdict.REJECTED, 0.85, false,
                "The session identifier changed after login -- the server rotates the session ID on "
                        + "authentication, which is the expected mitigation for session fixation.",
                detailOf("preLoginSession", preLoginSessionValue, "postLoginSession", postLoginSessionValue));
    }

    /**
     * @param preLogoutAuth     response using the session BEFORE logout, against the protected resource
     *                          (establishes what "still authenticated" looks like for this resource)
     * @param postLogoutReuse   response using the SAME (now stale) session, replayed against the same
     *                          resource AFTER the logout request completed
     * @param anon              unauthenticated baseline against the same resource, or null if one
     *                          couldn't be captured -- without it, a resource that happens to look the
     *                          same to everyone (public content) can't be told apart from a session
     *                          that's still genuinely authenticated, so the verdict is capped below CONFIRMED
     */
    public static Evidence evaluateLogoutInvalidation(Probe preLogoutAuth, Probe postLogoutReuse, Probe anon) {
        if (preLogoutAuth == null || postLogoutReuse == null) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "Logout invalidation check requires both a pre-logout authenticated baseline and a "
                            + "post-logout reuse attempt against the same resource.", "");
        }

        double reuseVsAuth = IdentityCompareLogic.similarity(postLogoutReuse.body, preLogoutAuth.body);
        boolean reuseMatchesAuth = postLogoutReuse.status == preLogoutAuth.status && reuseVsAuth >= IdentityCompareLogic.MATCH_THRESHOLD;

        if (!reuseMatchesAuth) {
            return new Evidence(Verdict.REJECTED, 0.8, false,
                    "The old session was rejected when reused after logout -- the server appears to "
                            + "invalidate the session server-side, not just clear the client-side cookie.",
                    detailOf("statusPreLogout", preLogoutAuth.status, "statusPostLogout", postLogoutReuse.status,
                            "bodySimilarity", reuseVsAuth));
        }

        if (anon == null) {
            return new Evidence(Verdict.INCONCLUSIVE, 0.5, false,
                    "The old session still produced a response matching the pre-logout authenticated one, "
                            + "but no unauthenticated baseline was captured for this resource, so a public/"
                            + "non-personalized resource can't be ruled out. Treat as supporting evidence only.",
                    detailOf("statusPreLogout", preLogoutAuth.status, "statusPostLogout", postLogoutReuse.status,
                            "bodySimilarity", reuseVsAuth));
        }

        double reuseVsAnon = IdentityCompareLogic.similarity(postLogoutReuse.body, anon.body);
        boolean reuseMatchesAnon = postLogoutReuse.status == anon.status && reuseVsAnon >= IdentityCompareLogic.MATCH_THRESHOLD;

        if (reuseMatchesAnon) {
            return new Evidence(Verdict.INCONCLUSIVE, 0.3, false,
                    "The old session's post-logout response matches what an unauthenticated request sees -- "
                            + "this resource may simply be public, which would explain the match without the "
                            + "session actually still being valid.",
                    detailOf("statusPostLogout", postLogoutReuse.status, "statusAnon", anon.status));
        }

        return new Evidence(Verdict.CONFIRMED, 0.88, true,
                "The old session, reused after logout, still produced a response matching the pre-logout "
                        + "authenticated state -- and that response differs from what an unauthenticated request "
                        + "sees, ruling out 'this is just public content'. The session was not invalidated server-side.",
                detailOf("statusPreLogout", preLogoutAuth.status, "statusPostLogout", postLogoutReuse.status,
                        "statusAnon", anon.status, "reuseVsAuth", reuseVsAuth, "reuseVsAnon", reuseVsAnon));
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String detailOf(Object... kv) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) sb.append(' ');
            Object v = kv[i + 1];
            String vs = (v instanceof Double) ? String.format(Locale.ROOT, "%.3f", (Double) v) : String.valueOf(v);
            sb.append(kv[i]).append('=').append(vs);
        }
        return sb.toString();
    }

    /** Reuses the same Probe shape as IdentityCompareLogic for consistency. */
    public static final class Probe {
        public final int status;
        public final String body;

        public Probe(int status, String body) {
            this.status = status;
            this.body = body == null ? "" : body;
        }
    }
}
