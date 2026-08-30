package com.harness.llm.logic;

import java.util.List;

/**
 * Payload selection + differential-timing classification for
 * command_injection_validation. Montoya-free.
 *
 * Deliberately uses a DIFFERENTIAL design (two different injected sleep
 * durations, compared against each other) rather than a single
 * sleep-vs-baseline comparison. A single measurement is fragile against
 * ordinary network/server jitter -- a slow response proves nothing by
 * itself. But if the RESPONSE TIME DELTA between two requests differing
 * only in requested sleep duration tracks the REQUESTED duration delta
 * (e.g. asking for 2s vs 6s more sleep produces roughly 4s more actual
 * delay), that's specific evidence the server is actually executing the
 * injected command, not just being generically slow -- ordinary jitter
 * doesn't scale proportionally with an attacker-chosen number baked
 * into the payload.
 *
 * This is real, industry-standard technique (the same principle
 * sqlmap's time-based blind SQLi detection uses), but timing-based
 * evidence is inherently less certain than content-based evidence --
 * confidence levels here are calibrated lower than e.g. XssPayloadLogic
 * or SstiPayloadLogic's CONFIRMED tier for exactly that reason.
 */
public final class CommandInjectionTimingLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    public record Payload(String osHint, String template) {
        /** Substitutes the requested sleep duration (seconds) into this payload's template. */
        public String render(int seconds) { return template.replace("{N}", String.valueOf(seconds)); }
    }

    public static final List<Payload> PAYLOADS = List.of(
            new Payload("Unix", "; sleep {N} ;"),
            new Payload("Unix", "| sleep {N}"),
            new Payload("Unix", "`sleep {N}`"),
            new Payload("Windows", "& timeout /t {N} & echo done"),
            new Payload("Windows", "| timeout /t {N}")
    );

    // Deliberately not 5 vs 10 or similar round numbers -- values that
    // could coincide with an unrelated server-side timeout setting.
    public static final int SHORT_SECONDS = 2;
    public static final int LONG_SECONDS = 6;

    private CommandInjectionTimingLogic() {}

    public static Payload nextPayload(List<String> triedTemplates) {
        for (Payload p : PAYLOADS) if (!triedTemplates.contains(p.template())) return p;
        return null;
    }

    /**
     * @param payload the payload template that was tried
     * @param baselineMs response time of the original, unmodified request
     * @param shortMs response time with the SHORT_SECONDS-duration payload
     * @param longMs response time with the LONG_SECONDS-duration payload
     */
    public static Evidence evaluate(Payload payload, long baselineMs, long shortMs, long longMs) {
        long expectedDeltaMs = (long) (LONG_SECONDS - SHORT_SECONDS) * 1000;
        long actualDeltaMs = longMs - shortMs;
        boolean bothMeaningfullySlowerThanBaseline =
                shortMs > baselineMs + (SHORT_SECONDS * 1000L * 0.4)
                        && longMs > baselineMs + (LONG_SECONDS * 1000L * 0.4);
        boolean deltaTracksRequestedDifference =
                actualDeltaMs >= expectedDeltaMs * 0.5 && actualDeltaMs <= expectedDeltaMs * 2.5;

        if (bothMeaningfullySlowerThanBaseline && deltaTracksRequestedDifference) {
            return new Evidence(Verdict.CONFIRMED, 0.75, true,
                    "A " + payload.osHint() + "-style command injection payload (" + payload.template()
                            + ") produced a response-time delta (" + actualDeltaMs + "ms) that tracks the "
                            + "requested sleep-duration difference (" + expectedDeltaMs + "ms expected) between "
                            + "two otherwise-identical requests -- consistent with the injected sleep command "
                            + "actually executing server-side, not general network/server jitter.",
                    "baseline=" + baselineMs + "ms short(" + SHORT_SECONDS + "s)=" + shortMs
                            + "ms long(" + LONG_SECONDS + "s)=" + longMs + "ms");
        }
        if (bothMeaningfullySlowerThanBaseline) {
            return new Evidence(Verdict.SUPPORTED, 0.4, false,
                    "Both probes were slower than baseline, but the response-time delta (" + actualDeltaMs
                            + "ms) did not clearly track the requested duration difference (" + expectedDeltaMs
                            + "ms expected) -- could be command injection with imprecise timing, or unrelated "
                            + "server-side slowness affecting both requests similarly.",
                    "baseline=" + baselineMs + "ms short=" + shortMs + "ms long=" + longMs + "ms");
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "Neither probe showed a response time meaningfully longer than baseline -- no evidence of "
                        + "command execution for the " + payload.osHint() + "-style payload " + payload.template() + ".",
                "baseline=" + baselineMs + "ms short=" + shortMs + "ms long=" + longMs + "ms");
    }
}
