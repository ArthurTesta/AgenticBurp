package com.harness.llm.logic;

/**
 * Classification logic for http_request_smuggling_detection. Montoya-free.
 *
 * SAFETY: real smuggling confirmation needs a timing/differential probe that can
 * desync a shared connection -- destructive and out of scope for a single bounded
 * request. This executor sends ONE non-destructive framing-hygiene probe (a
 * request carrying an obfuscated/duplicated Transfer-Encoding alongside
 * Content-Length) and only reports how the server framed it: a clean 400/501
 * rejection is good hygiene; silent acceptance is a SUPPORTED indicator worth a
 * manual timing test -- never a standalone CONFIRMED.
 *
 * NOTE: authored without a JDK (hazard #6); compiled/unit-run at gradle build.
 */
public final class RequestSmugglingLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INCONCLUSIVE }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private RequestSmugglingLogic() {}

    /**
     * @param baselineStatus status of the unmodified request
     * @param probeStatus    status when the ambiguous framing header was added (-1 if none)
     * @param probeErrored   the probe raised a transport error / timed out
     */
    public static Evidence evaluate(int baselineStatus, int probeStatus, boolean probeErrored) {
        if (probeErrored) {
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "The ambiguous-framing probe (conflicting Transfer-Encoding/Content-Length) caused a "
                            + "transport error or hang rather than a clean rejection -- a possible desync signal. "
                            + "Confirm with a deliberate CL.TE/TE.CL timing test before reporting.",
                    "baseline=" + baselineStatus + " probe=error");
        }
        if (probeStatus < 0) {
            return new Evidence(Verdict.INCONCLUSIVE, 0, false,
                    "No response was received for the framing-hygiene probe.", "");
        }
        if (probeStatus == 400 || probeStatus == 501) {
            return new Evidence(Verdict.REJECTED, 0.7, false,
                    "The server rejected a request with conflicting framing headers (" + probeStatus + ") -- "
                            + "it does not silently accept ambiguous Transfer-Encoding/Content-Length framing.",
                    "baseline=" + baselineStatus + " probe=" + probeStatus);
        }
        return new Evidence(Verdict.SUPPORTED, 0.45, false,
                "The server accepted a request carrying conflicting Transfer-Encoding/Content-Length framing "
                        + "(status " + probeStatus + ") instead of rejecting it -- ambiguous framing that MAY be "
                        + "exploitable for request smuggling. Requires a deliberate timing/desync test to confirm; "
                        + "not a standalone confirmation.",
                "baseline=" + baselineStatus + " probe=" + probeStatus);
    }
}
