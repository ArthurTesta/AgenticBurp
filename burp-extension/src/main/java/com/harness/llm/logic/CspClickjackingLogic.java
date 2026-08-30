package com.harness.llm.logic;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Passive clickjacking-protection check for csp_clickjacking_validation.
 * Montoya-free, like the other *Logic classes -- takes plain strings the
 * caller already has from the already-captured exchange, no new request
 * needed. This is deliberately narrow: it checks specifically for framing
 * protection (X-Frame-Options / CSP frame-ancestors), not a general CSP
 * quality audit -- that's a different, broader question than the
 * capability name asks.
 */
public final class CspClickjackingLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, INVALID, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private static final Pattern FRAME_ANCESTORS = Pattern.compile("frame-ancestors", Pattern.CASE_INSENSITIVE);
    private static final Pattern VALID_XFO = Pattern.compile("^\\s*(DENY|SAMEORIGIN)\\s*$", Pattern.CASE_INSENSITIVE);

    private CspClickjackingLogic() {}

    /**
     * @param contentType   the response's Content-Type header value, or null
     * @param xFrameOptions the response's X-Frame-Options header value, or null if absent
     * @param csp           the response's Content-Security-Policy header value, or null if absent
     */
    public static Evidence evaluate(String contentType, String xFrameOptions, String csp) {
        boolean rendersInBrowser = contentType != null && contentType.toLowerCase().contains("text/html");
        if (!rendersInBrowser) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "Response Content-Type is not text/html -- clickjacking framing protection is not "
                            + "a meaningful question for a response that isn't rendered as a page.", "");
        }

        boolean hasCspFrameAncestors = csp != null && FRAME_ANCESTORS.matcher(csp).find();
        if (hasCspFrameAncestors) {
            return new Evidence(Verdict.REJECTED, 0.85, false,
                    "Content-Security-Policy declares frame-ancestors, which takes precedence over "
                            + "X-Frame-Options in browsers that support it -- framing is restricted.",
                    "CSP: " + csp);
        }

        boolean hasValidXfo = xFrameOptions != null && VALID_XFO.matcher(xFrameOptions).matches();
        if (hasValidXfo) {
            return new Evidence(Verdict.REJECTED, 0.8, false,
                    "X-Frame-Options is present with a recognized value -- framing is restricted in "
                            + "browsers that honor it (older/non-Chromium browsers may not support "
                            + "frame-ancestors, so this header still matters even where CSP is also set).",
                    "X-Frame-Options: " + xFrameOptions);
        }

        boolean hasMalformedXfo = xFrameOptions != null;
        if (hasMalformedXfo) {
            return new Evidence(Verdict.SUPPORTED, 0.6, false,
                    "X-Frame-Options is present but its value is not a recognized directive (DENY/"
                            + "SAMEORIGIN) -- browsers may ignore it entirely, leaving the page framable.",
                    "X-Frame-Options: " + xFrameOptions);
        }

        return new Evidence(Verdict.SUPPORTED, 0.75, false,
                "This HTML response has neither a CSP frame-ancestors directive nor an X-Frame-Options "
                        + "header -- nothing observed here prevents the page from being framed by another "
                        + "origin. This is a passive header check, not proof the page is exploitable via "
                        + "clickjacking (that also depends on what a framed click could actually do).", "");
    }
}
