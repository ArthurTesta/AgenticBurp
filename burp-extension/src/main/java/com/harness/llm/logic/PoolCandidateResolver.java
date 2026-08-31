package com.harness.llm.logic;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Generic candidate-selection decision logic shared by
 * sessionFixationCompare and logoutInvalidationCompare -- both need "scan
 * the exchange pool for candidates matching some criterion, excluding the
 * source itself" and nothing more (no identifier-diff computation, unlike
 * IdentityCandidateResolver, which cross_identity_compare/
 * authorization_boundary_compare genuinely need). Extracted the same way
 * and for the same reason: Montoya-stub-only, headlessly testable, and
 * reusable by a future headless caller without a JOptionPane.
 */
public final class PoolCandidateResolver {

    private PoolCandidateResolver() {}

    public enum Outcome { RESOLVED, NEEDS_PICKER, NO_CANDIDATES }

    public static final class Resolution {
        public final Outcome outcome;
        public final HttpRequestResponse candidate;             // set iff RESOLVED
        public final List<HttpRequestResponse> pickerCandidates; // set iff NEEDS_PICKER

        private Resolution(Outcome outcome, HttpRequestResponse candidate, List<HttpRequestResponse> pickerCandidates) {
            this.outcome = outcome;
            this.candidate = candidate;
            this.pickerCandidates = pickerCandidates;
        }

        static Resolution resolved(HttpRequestResponse candidate) {
            return new Resolution(Outcome.RESOLVED, candidate, null);
        }

        static Resolution needsPicker(List<HttpRequestResponse> candidates) {
            return new Resolution(Outcome.NEEDS_PICKER, null, candidates);
        }

        static Resolution noCandidates() {
            return new Resolution(Outcome.NO_CANDIDATES, null, null);
        }
    }

    /**
     * @param source            identity/exchange being validated.
     * @param exchangePool      the full pool of captured exchanges, keyed by
     *                          ExchangeFingerprint.compute(rr).
     * @param filter            criterion a pool entry must satisfy to be a
     *                          candidate (e.g. "has a Set-Cookie header" for
     *                          session fixation; "accept anything" for
     *                          logout invalidation). Never applied to an
     *                          explicitly-supplied candidate -- a caller
     *                          that already knows which exchange it wants
     *                          is trusted the same way identityCompare's
     *                          explicit-candidate path is.
     * @param explicitCandidate when non-null, resolve to exactly this
     *                          exchange and skip the picker entirely --
     *                          the headless entry point. Null reproduces
     *                          the original pool-scan-then-ask-a-human
     *                          behavior.
     */
    public static Resolution resolve(HttpRequestResponse source,
                                      Map<String, HttpRequestResponse> exchangePool,
                                      Predicate<HttpRequestResponse> filter,
                                      HttpRequestResponse explicitCandidate) {
        if (explicitCandidate != null) {
            return Resolution.resolved(explicitCandidate);
        }

        List<HttpRequestResponse> candidates = new ArrayList<>();
        String sourceFingerprint = ExchangeFingerprint.compute(source);
        for (HttpRequestResponse rr : exchangePool.values()) {
            if (rr == null || rr == source) continue;
            try {
                if (ExchangeFingerprint.compute(rr).equals(sourceFingerprint)) continue;
                if (filter.test(rr)) candidates.add(rr);
            } catch (Exception ignored) {}
        }

        return candidates.isEmpty() ? Resolution.noCandidates() : Resolution.needsPicker(candidates);
    }
}
