package com.harness.llm.logic;

import java.util.List;

/**
 * Classification logic for crypto_transport_validation. Montoya-free. Passive:
 * the executor hands over what the captured exchange already shows about
 * transport security -- whether the request went over TLS, the HSTS header, the
 * Set-Cookie flags, and whether the request carried credentials -- and this
 * class decides what that means.
 *
 * NOTE: written without a JDK on the authoring machine (hazard #6) -- compiled
 * and unit-run at the maintainer's `gradle shadowJar`, not here.
 */
public final class CryptoTransportLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private CryptoTransportLogic() {}

    private static boolean cookieMissingSecure(List<String> setCookies) {
        if (setCookies == null) return false;
        for (String c : setCookies) {
            if (c == null) continue;
            String low = c.toLowerCase();
            if (!low.contains("secure")) return true;
        }
        return false;
    }

    /**
     * @param isHttps            whether the captured request used https
     * @param hsts               Strict-Transport-Security header value, or null if absent
     * @param setCookieValues    Set-Cookie response header values (may be empty/null)
     * @param requestCarriesAuth whether the request sent a cookie or Authorization header
     */
    public static Evidence evaluate(boolean isHttps, String hsts, List<String> setCookieValues,
                                    boolean requestCarriesAuth) {
        boolean hasCookies = setCookieValues != null && !setCookieValues.isEmpty();

        if (!isHttps) {
            // Cleartext transport. If credentials/session material is in play, the
            // exposure is direct and confirmable from the exchange alone.
            if (requestCarriesAuth || hasCookies) {
                return new Evidence(Verdict.CONFIRMED, 0.9, true,
                        "Credentials or session cookies are transmitted over plaintext HTTP -- anyone on "
                                + "the network path can read or replay them. Serve this endpoint over HTTPS only.",
                        "scheme=http requestCarriesAuth=" + requestCarriesAuth + " setCookies=" + hasCookies);
            }
            return new Evidence(Verdict.SUPPORTED, 0.6, false,
                    "Endpoint is served over plaintext HTTP. No credentials were observed on this exact "
                            + "request, but any sensitive content or later auth on this origin is exposed in transit.",
                    "scheme=http");
        }

        // HTTPS: look for the weaker-but-real transport hardening gaps.
        boolean missingHsts = hsts == null || hsts.isBlank();
        boolean insecureCookie = cookieMissingSecure(setCookieValues);
        if (insecureCookie) {
            return new Evidence(Verdict.SUPPORTED, 0.6, false,
                    "A Set-Cookie on an HTTPS response omits the Secure attribute -- the cookie can be "
                            + "sent over a downgraded/plaintext request to the same host.",
                    "missingHsts=" + missingHsts);
        }
        if (missingHsts) {
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "HTTPS response does not set Strict-Transport-Security -- a first/downgraded request "
                            + "can still be attempted over http and stripped by a network attacker.", "");
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "Transport is HTTPS with HSTS present and no insecure cookie observed on this exchange.", "");
    }
}
