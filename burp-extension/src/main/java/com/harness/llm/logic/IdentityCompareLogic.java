package com.harness.llm.logic;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Decision logic for the {@code cross_identity_compare} and
 * {@code authorization_boundary_compare} capabilities.
 *
 * This exists as a Montoya-free class specifically so it can be compiled
 * and unit-tested in environments (like this one) that cannot pull the
 * Montoya API jar or run a full Gradle build. ValidationExecutor (which
 * does depend on Montoya, for sending requests) should call into this
 * class rather than re-implementing the decision rules inline.
 *
 * Why this class exists at all (v4 -> v4.1 correction)
 * ------------------------------------------------------
 * The v4 implementation confirmed an IDOR/authorization finding whenever
 * two different captured identities received a similar response for the
 * same URL. That is insufficient: a completely public, non-personalized
 * endpoint (a homepage, a public product page) trivially produces
 * "different session, same response" without any authorization failure
 * existing at all.
 *
 * The corrected model requires THREE distinct observations, not two:
 *
 *   source     - identity A's own original response.
 *   candidate  - identity B's own original response (the resource
 *                identity A is not supposed to be able to reach).
 *   attempt    - identity A's own credentials/session used against
 *                identity B's resource. For an object-level IDOR test
 *                this is identity A's session replayed with B's object
 *                identifier substituted in; for a same-URL authorization
 *                boundary test (no identifier to swap) this is simply
 *                identity A's original request replayed as-is, since the
 *                "attempt" and the "source" are the same request.
 *   anon       - an unauthenticated probe against the same resource
 *                candidate protects (credentials/cookies stripped).
 *                This is what lets the logic tell "this is public" apart
 *                from "this is a real authorization failure" -- exactly
 *                the distinction the naive version could not make.
 *
 * Confirmation requires: the identifier genuinely differs (IDOR only);
 * an unauthenticated probe is meaningfully denied relative to the
 * candidate's protected response (rules out "it's just public"); and
 * identity A's attempt matches identity B's protected response rather
 * than matching the denied/anonymous response.
 */
public final class IdentityCompareLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INCONCLUSIVE, INVALID }

    /** One observed HTTP outcome: status code + response body. */
    public static final class Probe {
        public final int status;
        public final String body;

        public Probe(int status, String body) {
            this.status = status;
            this.body = body == null ? "" : body;
        }
    }

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

    /**
     * Similarity at/above this is treated as "materially the same response".
     *
     * Calibrated empirically, not guessed: a same-resource response that
     * differs only in one volatile token (session id, CSRF token,
     * timestamp) scored 0.77-0.92 trigram-Jaccard depending on body
     * length, while two genuinely different resources sharing the same
     * JSON shape/boilerplate scored 0.43-0.50. 0.70 sits in the gap with
     * margin on both sides. A stricter threshold (e.g. 0.90) produced
     * false negatives on short bodies with one differing token -- caught
     * by IdentityCompareLogicTest actually failing when first run.
     *
     * Residual risk: this is a generic string metric, not a semantic
     * JSON diff. It is the corroborating signal, not the sole gate --
     * status-code agreement and the unauthenticated-baseline check below
     * are what prevent false CONFIRMED verdicts; body similarity alone
     * being loose is a false-negative risk (missed confirmation), which
     * fails toward under-claiming rather than over-claiming.
     */
    static final double MATCH_THRESHOLD = 0.70;

    private IdentityCompareLogic() {}

    /**
     * @param capability        "cross_identity_compare" or "authorization_boundary_compare"
     * @param identifierChanged whether source/candidate reference different object
     *                          identifiers. Required true for cross_identity_compare;
     *                          irrelevant for authorization_boundary_compare (same URL
     *                          is expected there -- there is no identifier to swap).
     * @param source            identity A's own original captured response.
     * @param candidate         identity B's own original captured response.
     * @param attempt           identity A's credentials used against B's resource.
     * @param anon              unauthenticated probe of the same resource, or null if
     *                          one could not be sent (e.g. no way to strip auth cleanly).
     */
    public static Evidence evaluate(String capability, boolean identifierChanged,
                                     Probe source, Probe candidate, Probe attempt, Probe anon) {
        if ("cross_identity_compare".equals(capability) && !identifierChanged) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "IDOR test requires the candidate to reference a different object "
                            + "identifier than the source request; none was found.", "");
        }

        if (anon == null) {
            // No unauthenticated baseline available -- we cannot rule out a public
            // resource, so this can never reach CONFIRMED, only a weaker tier.
            boolean matches = sameStatus(attempt, candidate) && similarity(attempt.body, candidate.body) >= MATCH_THRESHOLD;
            if (matches) {
                return new Evidence(Verdict.SUPPORTED, 0.55, false,
                        "Identity A's credentials returned a response materially matching identity B's, "
                                + "but no unauthenticated baseline could be captured, so a public/non-personalized "
                                + "resource cannot be ruled out. Treat as supporting evidence only.",
                        detailOf("statusAttempt", attempt.status, "statusCandidate", candidate.status,
                                "bodySimilarity", similarity(attempt.body, candidate.body)));
            }
            return new Evidence(Verdict.REJECTED, 0.6, false,
                    "Identity A's credentials did not reproduce identity B's response.",
                    detailOf("statusAttempt", attempt.status, "statusCandidate", candidate.status,
                            "bodySimilarity", similarity(attempt.body, candidate.body)));
        }

        double anonVsCandidate = similarity(anon.body, candidate.body);
        boolean anonLooksDenied = !sameStatus(anon, candidate) || anonVsCandidate < MATCH_THRESHOLD;

        if (!anonLooksDenied) {
            return new Evidence(Verdict.INCONCLUSIVE, 0.3, false,
                    "An unauthenticated request received materially the same response as identity B; "
                            + "this resource appears to be public rather than access-controlled, so a matching "
                            + "response from identity A is not evidence of an authorization failure.",
                    detailOf("statusAnon", anon.status, "statusCandidate", candidate.status,
                            "bodySimilarity", anonVsCandidate));
        }

        double attemptVsCandidate = similarity(attempt.body, candidate.body);
        double attemptVsAnon = similarity(attempt.body, anon.body);
        boolean attemptMatchesCandidate = sameStatus(attempt, candidate) && attemptVsCandidate >= MATCH_THRESHOLD;
        boolean attemptMatchesAnon = sameStatus(attempt, anon) && attemptVsAnon >= MATCH_THRESHOLD;

        if (attemptMatchesCandidate && !attemptMatchesAnon) {
            return new Evidence(Verdict.CONFIRMED, 0.91, true,
                    "Identity A's own credentials, applied to identity B's resource, returned a response "
                            + "materially matching identity B's protected access. An unauthenticated probe of the "
                            + "same resource was denied, ruling out a public resource.",
                    detailOf("statusAttempt", attempt.status, "statusCandidate", candidate.status,
                            "statusAnon", anon.status, "attemptVsCandidate", attemptVsCandidate,
                            "attemptVsAnon", attemptVsAnon, "anonVsCandidate", anonVsCandidate));
        }

        if (attemptMatchesAnon) {
            return new Evidence(Verdict.REJECTED, 0.8, false,
                    "Identity A's attempt against identity B's resource matched the unauthenticated/denied "
                            + "response, not identity B's protected response -- access appears correctly restricted.",
                    detailOf("statusAttempt", attempt.status, "statusAnon", anon.status,
                            "attemptVsAnon", attemptVsAnon));
        }

        return new Evidence(Verdict.INCONCLUSIVE, 0.4, false,
                "Identity A's attempt matched neither identity B's protected response nor the "
                        + "unauthenticated baseline.",
                detailOf("statusAttempt", attempt.status, "attemptVsCandidate", attemptVsCandidate,
                        "attemptVsAnon", attemptVsAnon));
    }

    private static boolean sameStatus(Probe a, Probe b) {
        return a.status == b.status;
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

    /**
     * Trigram Jaccard similarity. Deliberately not the old
     * common-prefix + length-ratio heuristic: that metric scores two
     * completely different bodies of equal length as 50% similar before
     * any content is compared, and scores a single early differing
     * character as catastrophic even when the rest of the body matches.
     * Trigram Jaccard is order-sensitive at a local level but tolerant of
     * insertions/deletions elsewhere in the body (e.g. a per-request CSRF
     * token or timestamp embedded in otherwise-identical HTML).
     */
    public static double similarity(String a, String b) {
        if (a == null) a = "";
        if (b == null) b = "";
        if (a.equals(b)) return 1.0;
        if (a.isEmpty() || b.isEmpty()) return 0.0;
        Set<String> ga = shingles(a);
        Set<String> gb = shingles(b);
        if (ga.isEmpty() || gb.isEmpty()) return 0.0;
        Set<String> inter = new HashSet<>(ga);
        inter.retainAll(gb);
        Set<String> union = new HashSet<>(ga);
        union.addAll(gb);
        return union.isEmpty() ? 0.0 : (double) inter.size() / union.size();
    }

    private static Set<String> shingles(String s) {
        int n = 3;
        Set<String> out = new HashSet<>();
        if (s.length() < n) {
            out.add(s);
            return out;
        }
        for (int i = 0; i + n <= s.length(); i++) out.add(s.substring(i, i + n));
        return out;
    }
}
