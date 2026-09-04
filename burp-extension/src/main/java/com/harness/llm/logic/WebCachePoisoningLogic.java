package com.harness.llm.logic;

/**
 * Classification logic for web_cache_poisoning_detection. Montoya-free. The
 * executor sends an unkeyed-header probe (e.g. X-Forwarded-Host: attacker) then
 * a SECOND, clean request to the same URL, and hands over: whether the attacker
 * marker was reflected in that second (potentially cache-served) response, and
 * the cache-status/Age headers. Reflection persisting into a request that did
 * NOT carry the header is the poisoning signal.
 *
 * NOTE: authored without a JDK (hazard #6); compiled/unit-run at gradle build.
 */
public final class WebCachePoisoningLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INCONCLUSIVE }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private WebCachePoisoningLogic() {}

    private static boolean looksCached(String cacheStatus, String age) {
        if (cacheStatus != null && cacheStatus.toLowerCase().contains("hit")) return true;
        if (age != null && !age.isBlank()) {
            try { return Integer.parseInt(age.trim()) > 0; } catch (NumberFormatException ignore) {}
        }
        return false;
    }

    /**
     * @param injectedMarker            the attacker value sent in the unkeyed header
     * @param secondResponseReflectsIt  the marker appeared in the clean follow-up response's body/headers
     * @param secondCarriedHeader       whether that follow-up itself carried the header (should be false)
     * @param cacheStatusHeader         X-Cache / CF-Cache-Status style header on the follow-up (may be null)
     * @param ageHeader                 Age header on the follow-up (may be null)
     */
    public static Evidence evaluate(String injectedMarker, boolean secondResponseReflectsIt,
                                    boolean secondCarriedHeader, String cacheStatusHeader, String ageHeader) {
        if (injectedMarker == null || injectedMarker.isBlank()) {
            return new Evidence(Verdict.INCONCLUSIVE, 0, false,
                    "No probe marker was available for the cache-poisoning check.", "");
        }
        boolean cached = looksCached(cacheStatusHeader, ageHeader);
        if (secondResponseReflectsIt && !secondCarriedHeader) {
            if (cached) {
                return new Evidence(Verdict.CONFIRMED, 0.88, true,
                        "An attacker-controlled unkeyed header was reflected into a SUBSEQUENT request that did "
                                + "not carry it, and the response is cache-served (cache hit / Age>0) -- the cache is "
                                + "poisoned: the injected value is served to other clients.",
                        "cacheStatus=" + cacheStatusHeader + " age=" + ageHeader);
            }
            return new Evidence(Verdict.SUPPORTED, 0.6, false,
                    "An unkeyed header value persisted into a follow-up request that did not send it -- "
                            + "reflection is unkeyed, but no explicit cache-hit indicator was seen. Confirm the value "
                            + "is actually cached and served cross-client before reporting.",
                    "cacheStatus=" + cacheStatusHeader + " age=" + ageHeader);
        }
        return new Evidence(Verdict.REJECTED, 0.65, false,
                "The attacker marker did not survive into an independent follow-up request -- the tested "
                        + "header is keyed or not reflected; no cache poisoning demonstrated.",
                "reflected=" + secondResponseReflectsIt + " carriedHeader=" + secondCarriedHeader);
    }
}
