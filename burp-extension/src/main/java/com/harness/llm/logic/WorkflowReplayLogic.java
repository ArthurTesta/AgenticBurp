package com.harness.llm.logic;

import java.util.regex.Pattern;

/**
 * Decision logic for the {@code workflow_replay_compare} capability
 * (category: {@code business_logic}).
 *
 * This exists as a Montoya-free class for the same reason
 * {@link IdentityCompareLogic} does: it can be compiled and unit-tested in
 * environments that cannot pull the Montoya API jar or run a full Gradle
 * build. {@code ValidationExecutor} depends on Montoya only to gather the
 * three HTTP observations this class needs; the decision itself lives here.
 *
 * Scope, stated honestly
 * -----------------------
 * "Business logic" as a category is not something a single deterministic
 * check can cover in general -- workflow_replay_compare does NOT attempt
 * that. What it confirms is one specific, common, and dangerous shape: a
 * numeric parameter (price, quantity, amount, discount) that the server
 * accepts a boundary-violating value for (typically negative, where the
 * business meaning of "negative quantity" or "negative amount" is never
 * legitimate) without rejecting it. This was the exact shape of the real,
 * live-reproduced vulnerability this capability was built against
 * (Juice Shop accepting a basket quantity of -500 with zero validation --
 * see HANDOVER.md item 6, "business_logic" row).
 *
 * Three observations are required, mirroring the "prove a negative"
 * structure IdentityCompareLogic uses for the same reason -- a single
 * accepted request is not enough to confirm a missing bounds check,
 * because plenty of endpoints return 2xx unconditionally regardless of
 * body content, and that alone would produce a false CONFIRMED on totally
 * healthy code:
 *
 *   baseline  - the original request, unmodified value. Must succeed;
 *               otherwise there is no working request to compare against.
 *   boundary  - the same request with the target parameter mutated to a
 *               genuine boundary violation (e.g. the original value
 *               negated, or an extreme-magnitude value if the original
 *               was already <= 0). If this is rejected, bounds validation
 *               appears to be enforced -- REJECTED, not CONFIRMED.
 *   malformed - a negative control: the same request with the target
 *               parameter set to a type-invalid value (non-numeric junk).
 *               This is what lets the logic tell "the server specifically
 *               skips range/bounds validation" apart from "the server
 *               doesn't validate this field at all" -- if a boundary
 *               violation is accepted but type-invalid junk is rejected,
 *               that is strong, specific evidence of a missing bounds
 *               check. If BOTH are accepted, the endpoint may simply not
 *               validate the field's content at all; this is still worth
 *               reporting but is a weaker, less specific signal and is
 *               capped below CONFIRMED.
 */
public final class WorkflowReplayLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INCONCLUSIVE, INVALID }

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
     * Numeric-quantity-shaped parameter names. Deliberately narrower than
     * PathScorer's PARAM_NAME_RULES business_logic rule
     * ("role|is_admin|admin|status|price|amount|quantity|discount"): that
     * rule mixes numeric fields (price, amount, quantity, discount) with
     * non-numeric state/authorization fields (role, is_admin, status),
     * which is fine for triage scoring but wrong for a bounds-violation
     * probe -- "role" doesn't have a boundary to violate the way a
     * quantity does. This list keeps only the parameters a numeric
     * boundary-violation replay actually makes sense against, and adds a
     * few common synonyms (qty, count, total, balance) PathScorer doesn't
     * currently have.
     */
    private static final Pattern NUMERIC_CANDIDATE = Pattern.compile(
            "(?i)^(price|amount|quantity|qty|discount|count|total|balance|value)$");

    public static boolean isNumericBoundaryCandidateParam(String name) {
        return name != null && NUMERIC_CANDIDATE.matcher(name).matches();
    }

    private WorkflowReplayLogic() {}

    /**
     * @param paramName     the mutated parameter's name, for reporting only.
     * @param originalValue the parameter's captured original value.
     * @param boundaryValue the boundary-violating value that was substituted in.
     * @param baseline      response to the unmodified request.
     * @param boundary      response to the request with boundaryValue substituted.
     * @param malformed     response to the request with a type-invalid value
     *                      substituted, or null if that probe could not be sent.
     */
    public static Evidence evaluate(String paramName, String originalValue, String boundaryValue,
                                     IdentityCompareLogic.Probe baseline,
                                     IdentityCompareLogic.Probe boundary,
                                     IdentityCompareLogic.Probe malformed) {
        if (!isGenuineBoundaryViolation(originalValue, boundaryValue)) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "The supplied boundary value ('" + boundaryValue + "') does not appear to be a genuine "
                            + "boundary violation of the original value ('" + originalValue + "') for parameter '"
                            + paramName + "'; nothing to test.", "");
        }

        if (baseline == null || !isSuccess(baseline.status)) {
            return new Evidence(Verdict.INCONCLUSIVE, 0.0, false,
                    "The baseline replay with the original value did not succeed"
                            + (baseline == null ? "." : " (status " + baseline.status + ")."
                            + " Cannot establish a meaningful comparison."), "");
        }

        if (boundary == null) {
            return new Evidence(Verdict.INCONCLUSIVE, 0.0, false,
                    "No response was captured for the boundary-violating value.", "");
        }

        if (!isSuccess(boundary.status)) {
            return new Evidence(Verdict.REJECTED, 0.75, false,
                    "The boundary-violating value ('" + boundaryValue + "') for parameter '" + paramName
                            + "' was rejected (status " + boundary.status + "); bounds validation appears to be enforced.",
                    detailOf("statusBaseline", baseline.status, "statusBoundary", boundary.status));
        }

        if (malformed == null) {
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "The boundary-violating value ('" + boundaryValue + "') for parameter '" + paramName
                            + "' was accepted (status " + boundary.status + "), but no negative-control probe with a "
                            + "type-invalid value could be captured to distinguish a missing bounds check from an "
                            + "endpoint that simply accepts arbitrary input for this field.",
                    detailOf("statusBaseline", baseline.status, "statusBoundary", boundary.status));
        }

        if (isSuccess(malformed.status)) {
            return new Evidence(Verdict.SUPPORTED, 0.55, false,
                    "Parameter '" + paramName + "' accepted both the boundary-violating value ('" + boundaryValue
                            + "') and a type-invalid control value, suggesting little or no input validation on this "
                            + "field generally, rather than a specifically missing bounds check. Still worth reporting, "
                            + "but this is a weaker and less specific signal than a clean bounds-check miss.",
                    detailOf("statusBaseline", baseline.status, "statusBoundary", boundary.status,
                            "statusMalformed", malformed.status));
        }

        return new Evidence(Verdict.CONFIRMED, 0.85, true,
                "The endpoint rejected a type-invalid control value (status " + malformed.status + ") for parameter '"
                        + paramName + "' but accepted a boundary-violating value ('" + boundaryValue + "', status "
                        + boundary.status + "). This indicates the server performs some validation on this field but "
                        + "does not enforce a valid range/bounds check.",
                detailOf("statusBaseline", baseline.status, "statusBoundary", boundary.status,
                        "statusMalformed", malformed.status));
    }

    private static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    /**
     * A boundary violation is either a sign flip away from non-negative
     * (the common "negative price/quantity/amount" bug class), or a jump
     * in magnitude of three or more orders relative to the original value.
     * Deliberately conservative: this is a gate against testing something
     * that isn't actually a boundary case, not an attempt to be clever
     * about every possible numeric bound.
     */
    static boolean isGenuineBoundaryViolation(String originalValue, String boundaryValue) {
        Double orig = tryParse(originalValue);
        Double bound = tryParse(boundaryValue);
        if (orig == null || bound == null) return false;
        if (orig >= 0 && bound < 0) return true;
        double origMag = Math.abs(orig);
        double boundMag = Math.abs(bound);
        if (origMag > 0 && boundMag >= origMag * 1000.0) return true;
        return false;
    }

    private static Double tryParse(String s) {
        if (s == null) return null;
        try { return Double.parseDouble(s.trim()); } catch (Exception e) { return null; }
    }

    private static String detailOf(Object... kv) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) sb.append(' ');
            sb.append(kv[i]).append('=').append(kv[i + 1]);
        }
        return sb.toString();
    }
}
