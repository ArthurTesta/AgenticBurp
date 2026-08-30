package com.harness.llm.logic;

/**
 * Classification logic for cors_misconfiguration_detection. Montoya-free.
 * The executor's job is just to resend the request with an added,
 * clearly-foreign Origin header and hand the two response header values
 * to evaluate() -- this class decides what they mean.
 */
public final class CorsMisconfigLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private CorsMisconfigLogic() {}

    /**
     * @param injectedOrigin the foreign Origin value the executor sent
     * @param acao the response's Access-Control-Allow-Origin value, or null if absent
     * @param acac the response's Access-Control-Allow-Credentials value, or null if absent
     */
    public static Evidence evaluate(String injectedOrigin, String acao, String acac) {
        if (acao == null) {
            return new Evidence(Verdict.REJECTED, 0.75, false,
                    "No Access-Control-Allow-Origin header was returned for a request carrying a "
                            + "foreign Origin -- cross-origin reads are not permitted for this origin.", "");
        }

        boolean reflectsExactOrigin = acao.trim().equalsIgnoreCase(injectedOrigin.trim());
        boolean isWildcard = acao.trim().equals("*");
        boolean credentialsAllowed = acac != null && acac.trim().equalsIgnoreCase("true");

        if (reflectsExactOrigin && credentialsAllowed) {
            return new Evidence(Verdict.CONFIRMED, 0.92, true,
                    "The server reflects an arbitrary, attacker-chosen Origin back in "
                            + "Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true -- "
                            + "this lets any origin read authenticated (cookie-bearing) responses via "
                            + "cross-origin fetch/XHR, effectively bypassing the same-origin policy for "
                            + "logged-in users.",
                    "Injected Origin: " + injectedOrigin + " | ACAO: " + acao + " | ACAC: " + acac);
        }
        if (reflectsExactOrigin) {
            return new Evidence(Verdict.SUPPORTED, 0.65, false,
                    "The server reflects an arbitrary, attacker-chosen Origin back in "
                            + "Access-Control-Allow-Origin, but Access-Control-Allow-Credentials is not "
                            + "'true' -- cross-origin reads are possible but won't carry cookies/auth, "
                            + "limiting impact to non-authenticated responses.",
                    "Injected Origin: " + injectedOrigin + " | ACAO: " + acao);
        }
        if (isWildcard && credentialsAllowed) {
            // Technically invalid per the Fetch spec (browsers reject ACAO:*
            // combined with credentials), but a server sending this combination
            // is still a real misconfiguration worth flagging -- some older or
            // non-browser HTTP clients enforce this less strictly.
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "The server sends Access-Control-Allow-Origin: * together with "
                            + "Access-Control-Allow-Credentials: true -- an invalid combination per the Fetch "
                            + "spec that browsers reject, but still indicates a real misconfiguration on the "
                            + "server side.",
                    "ACAO: " + acao + " | ACAC: " + acac);
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "Access-Control-Allow-Origin does not reflect the injected foreign origin, and is not "
                        + "an unsafe wildcard+credentials combination.",
                "Injected Origin: " + injectedOrigin + " | ACAO: " + acao);
    }
}
