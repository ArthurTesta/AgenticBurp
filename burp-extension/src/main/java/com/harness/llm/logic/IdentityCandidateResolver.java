package com.harness.llm.logic;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Candidate-selection decision logic for {@code identityCompare}
 * (cross_identity_compare / authorization_boundary_compare), extracted
 * out of {@code ValidationExecutor} so it can be compiled and unit-tested
 * headlessly (plain javac against dev-tools/stubs, run via
 * dev-tools/RunTests.java -- no Gradle, no Maven, no live Burp), the same
 * way every other class in this package already is.
 *
 * This class only touches Montoya *interface types* (HttpRequestResponse),
 * never Montoya I/O (no api.http().sendRequest, no JOptionPane) -- it
 * decides WHICH candidate to compare against, not how to compare it. The
 * actual comparison stays in IdentityCompareLogic, unchanged.
 *
 * Two ways a candidate is resolved: an explicit fingerprint/object supplied
 * by a headless caller (RESOLVED, skipping the human picker entirely), or
 * -- when none is supplied, exactly today's behavior -- a pool scan whose
 * results are handed back to the caller to show a human (NEEDS_PICKER).
 */
public final class IdentityCandidateResolver {

    private IdentityCandidateResolver() {}

    public enum Outcome { RESOLVED, NEEDS_PICKER, NO_CANDIDATES }

    public static final class Resolution {
        public final Outcome outcome;
        public final HttpRequestResponse candidate;             // set iff RESOLVED
        public final UrlIdentifierDiff.Diff diff;                // may be null even if RESOLVED
        public final List<HttpRequestResponse> pickerCandidates; // set iff NEEDS_PICKER
        public final List<UrlIdentifierDiff.Diff> pickerDiffs;   // parallel to pickerCandidates

        private Resolution(Outcome outcome, HttpRequestResponse candidate, UrlIdentifierDiff.Diff diff,
                            List<HttpRequestResponse> pickerCandidates, List<UrlIdentifierDiff.Diff> pickerDiffs) {
            this.outcome = outcome;
            this.candidate = candidate;
            this.diff = diff;
            this.pickerCandidates = pickerCandidates;
            this.pickerDiffs = pickerDiffs;
        }

        static Resolution resolved(HttpRequestResponse candidate, UrlIdentifierDiff.Diff diff) {
            return new Resolution(Outcome.RESOLVED, candidate, diff, null, null);
        }

        static Resolution needsPicker(List<HttpRequestResponse> candidates, List<UrlIdentifierDiff.Diff> diffs) {
            return new Resolution(Outcome.NEEDS_PICKER, null, null, candidates, diffs);
        }

        static Resolution noCandidates() {
            return new Resolution(Outcome.NO_CANDIDATES, null, null, null, null);
        }
    }

    /**
     * @param source            identity A's own captured request/response.
     * @param exchangePool      the full pool of captured exchanges, keyed by
     *                          exchangeFingerprint(rr) (ValidationExecutor's field).
     * @param isIdor            true for cross_identity_compare, false for
     *                          authorization_boundary_compare.
     * @param explicitCandidate when non-null, resolve against exactly this
     *                          exchange and skip the picker entirely -- the
     *                          headless entry point. Null reproduces the
     *                          original pool-scan-then-ask-a-human behavior.
     */
    public static Resolution resolve(HttpRequestResponse source,
                                      Map<String, HttpRequestResponse> exchangePool,
                                      boolean isIdor,
                                      HttpRequestResponse explicitCandidate) {
        if (explicitCandidate != null) {
            UrlIdentifierDiff.Diff diff = isIdor
                    ? UrlIdentifierDiff.singleDifferingIdentifier(
                            source.request().url(), explicitCandidate.request().url()).orElse(null)
                    : null;
            // Deliberately unconditional: a candidate that shares the
            // source's identifier (or a different-shape URL) still
            // resolves here, with diff == null -- IdentityCompareLogic.evaluate()'s
            // existing INVALID verdict is the correct place for that
            // outcome (identifierChanged = !isIdor || diff != null), not a
            // pre-filter here.
            return Resolution.resolved(explicitCandidate, diff);
        }

        List<HttpRequestResponse> candidates = new ArrayList<>();
        List<UrlIdentifierDiff.Diff> diffs = new ArrayList<>();
        String sourceFingerprint = ExchangeFingerprint.compute(source);
        for (HttpRequestResponse rr : exchangePool.values()) {
            if (rr == null || rr == source) continue;
            try {
                if (ExchangeFingerprint.compute(rr).equals(sourceFingerprint)) continue;
                if (isIdor) {
                    Optional<UrlIdentifierDiff.Diff> d =
                            UrlIdentifierDiff.singleDifferingIdentifier(source.request().url(), rr.request().url());
                    if (d.isPresent()) { candidates.add(rr); diffs.add(d.get()); }
                } else if (rr.request().url().equals(source.request().url())) {
                    candidates.add(rr); diffs.add(null);
                }
            } catch (Exception ignored) {}
        }

        return candidates.isEmpty() ? Resolution.noCandidates() : Resolution.needsPicker(candidates, diffs);
    }
}
