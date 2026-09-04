package com.harness.llm.logic;

/**
 * Classification logic for nosql_validation. Montoya-free. The executor sends an
 * operator-injection probe (e.g. a {@code [$ne]} / {@code $gt} style value) into
 * a candidate parameter and hands over: the injected response's status/body plus
 * the baseline status. This class decides whether a NoSQL error surfaced or an
 * auth/logic response flipped.
 *
 * NOTE: authored without a JDK (hazard #6); compiled/unit-run at gradle build.
 */
public final class NoSqlInjectionLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INCONCLUSIVE }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private NoSqlInjectionLogic() {}

    // Signatures emitted by common NoSQL engines/drivers when a malformed
    // operator reaches them -- distinctive enough not to false-match generic text.
    private static final String[] ERROR_SIGNATURES = {
            "mongoerror", "bson", "$where", "unexpected token", "castfromstring",
            "com.mongodb", "e11000", "unknown operator", "couchdb", "n1ql", "cassandra"
    };

    private static boolean hasNoSqlError(String body) {
        if (body == null) return false;
        String low = body.toLowerCase();
        for (String s : ERROR_SIGNATURES) if (low.contains(s)) return true;
        return false;
    }

    /**
     * @param baselineStatus status of the unmodified request
     * @param injectedStatus status when the operator payload was injected (-1 if none)
     * @param injectedBody   response body of the injected request (may be null)
     */
    public static Evidence evaluate(int baselineStatus, int injectedStatus, String injectedBody) {
        if (injectedStatus < 0) {
            return new Evidence(Verdict.INCONCLUSIVE, 0, false,
                    "No response was received for the NoSQL operator-injection probe.", "");
        }
        if (hasNoSqlError(injectedBody)) {
            return new Evidence(Verdict.CONFIRMED, 0.85, true,
                    "A NoSQL operator injected into a parameter produced a database/driver error in the "
                            + "response -- the value reaches a NoSQL query unsanitised, so operator injection "
                            + "(e.g. authentication bypass via {\"$ne\": null}) is possible.",
                    "baseline=" + baselineStatus + " injected=" + injectedStatus + " (error signature present)");
        }
        // An auth/lookup endpoint that DENIED the baseline but ACCEPTED the
        // operator payload is a classic NoSQL auth bypass.
        boolean baselineDenied = baselineStatus == 401 || baselineStatus == 403 || baselineStatus == 404;
        boolean injectedAllowed = injectedStatus >= 200 && injectedStatus < 300;
        if (baselineDenied && injectedAllowed) {
            return new Evidence(Verdict.CONFIRMED, 0.8, true,
                    "Injecting a NoSQL operator flipped a denied request (" + baselineStatus + ") into a "
                            + "success (" + injectedStatus + ") -- operator injection bypasses the query's intended "
                            + "constraint (authentication/authorisation bypass).",
                    "baseline=" + baselineStatus + " injected=" + injectedStatus);
        }
        return new Evidence(Verdict.REJECTED, 0.65, false,
                "The NoSQL operator payload produced neither a database error nor a status flip -- no "
                        + "operator injection demonstrated on this parameter.",
                "baseline=" + baselineStatus + " injected=" + injectedStatus);
    }
}
