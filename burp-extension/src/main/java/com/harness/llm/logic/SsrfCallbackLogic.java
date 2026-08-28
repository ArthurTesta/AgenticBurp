package com.harness.llm.logic;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Decision logic for the {@code controlled_callback_probe} capability
 * (category: {@code ssrf}).
 *
 * Montoya-free for the same reason as IdentityCompareLogic and
 * WorkflowReplayLogic: ValidationExecutor gathers the observations (via
 * Burp Collaborator), this class decides what they mean.
 *
 * How this is meant to be used
 * -----------------------------
 * ValidationExecutor generates a unique Burp Collaborator payload per
 * candidate parameter, substitutes it into that parameter as a URL, sends
 * the request, and polls the Collaborator server for interactions over a
 * bounded window. If any candidate parameter's unique payload produces a
 * real DNS/HTTP/SMTP interaction, that is about as close to unambiguous
 * ground truth as exists for blind SSRF: an outbound network action the
 * server took, caused by input this harness controlled, matched by a
 * unique token so it cannot be confused with unrelated background
 * traffic. There is deliberately no weaker, non-Collaborator fallback
 * confirmation path -- a guess based on response timing or error-message
 * shape is not the same class of evidence, and this project's philosophy
 * (see HANDOVER.md) is to not manufacture a confirmation signal that
 * isn't actually there. If Collaborator is unavailable (Community
 * Edition, or no server configured) ValidationExecutor reports that
 * directly and never reaches this class.
 *
 * Candidate parameter selection
 * -------------------------------
 * Reuses and extends the SSRF-shaped parameter-name heuristic already in
 * PathScorer's PARAM_NAME_RULES ("url|redirect|next|return_to|callback").
 * That list was found, while building this class, to miss the exact
 * live SSRF ground truth this session reproduced against Juice Shop
 * (HANDOVER.md item 6, "ssrf" row): a profile-image-from-URL field named
 * "profileImage", which doesn't match any existing rule. Broadened here
 * to also match target/endpoint/fetch/proxy/dest/destination/uri/link
 * (already used in PathScorer's URL-pattern rule) and any parameter name
 * containing image/avatar/photo/picture. PathScorer's own scoring rule
 * has the same narrow list and should be broadened the same way in a
 * follow-up pass -- not changed here, since that's a scoring heuristic
 * (affects triage order only) rather than a correctness gap in an
 * executor that would otherwise silently skip testing the real thing.
 */
public final class SsrfCallbackLogic {

    public enum Verdict { CONFIRMED, INCONCLUSIVE, INVALID }

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

    /** One candidate parameter's probe result. Montoya-free abstraction of a
     *  real Collaborator Interaction: the executor converts. */
    public static final class CallbackAttempt {
        public final String paramName;
        public final String payloadToken;
        public final List<String> interactionTypes; // e.g. ["DNS"], ["HTTP"], or empty if none observed

        public CallbackAttempt(String paramName, String payloadToken, List<String> interactionTypes) {
            this.paramName = paramName;
            this.payloadToken = payloadToken;
            this.interactionTypes = interactionTypes == null ? List.of() : interactionTypes;
        }
    }

    private static final Pattern CANDIDATE_EXACT = Pattern.compile(
            "(?i)^(url|uri|link|redirect|next|return_to|callback|webhook|target|endpoint|fetch|proxy|dest|destination)$");
    private static final Pattern CANDIDATE_SUBSTRING = Pattern.compile("(?i)(image|avatar|photo|picture)");

    private SsrfCallbackLogic() {}

    public static boolean isCallbackCandidateParam(String name) {
        if (name == null || name.isBlank()) return false;
        return CANDIDATE_EXACT.matcher(name).matches() || CANDIDATE_SUBSTRING.matcher(name).find();
    }

    public static Evidence evaluate(List<CallbackAttempt> attempts) {
        if (attempts == null || attempts.isEmpty()) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "No URL/callback/image-like parameter was available on this request for controlled_callback_probe "
                            + "to target.", "");
        }
        for (CallbackAttempt a : attempts) {
            if (!a.interactionTypes.isEmpty()) {
                return new Evidence(Verdict.CONFIRMED, 0.93, true,
                        "A Collaborator interaction (" + String.join(",", a.interactionTypes) + ") was observed "
                                + "resulting from a unique payload placed in parameter '" + a.paramName + "', "
                                + "confirming the server made an outbound network request to infrastructure this "
                                + "harness controlled.",
                        "param=" + a.paramName + " payload=" + a.payloadToken
                                + " interactionTypes=" + a.interactionTypes + " attempted=" + attempts.size());
            }
        }
        return new Evidence(Verdict.INCONCLUSIVE, 0.35, false,
                "No Collaborator interaction was observed within the polling window across " + attempts.size()
                        + " candidate parameter(s). Absence of an interaction in a bounded window is not proof the "
                        + "server never made the request -- it may be delayed beyond the window, filtered on "
                        + "egress, or require a different payload shape (e.g. a scheme other than http/https).",
                "attempted=" + attempts.size());
    }
}
