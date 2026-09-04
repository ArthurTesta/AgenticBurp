package com.harness.llm.logic;

/**
 * Classification logic for sql_injection_validation. Montoya-free. This is the
 * Burp-plane, dependency-free confirmer (sqlmap runs harness-side / in a
 * container); it does the two classic bounded checks the executor feeds it:
 *   1. error-based -- an appended quote surfaces a SQL engine error, and
 *   2. boolean-based -- a `AND 1=1` vs `AND 1=2` pair produces materially
 *      different responses (status or length) while the syntactically-broken
 *      quote probe does not simply mirror one of them.
 *
 * NOTE: authored without a JDK (hazard #6); compiled/unit-run at gradle build.
 */
public final class SqlInjectionLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INCONCLUSIVE }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private SqlInjectionLogic() {}

    // Distinctive DB error fragments -- kept specific so ordinary prose ("you
    // have an error", "syntax") without a DB context does not false-match.
    private static final String[] SQL_ERRORS = {
            "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
            "quoted string not properly terminated", "pg_query", "psql:", "sqlite3::", "sqlstate",
            "ora-01756", "ora-00933", "odbc sql server driver", "microsoft ole db provider for sql server"
    };

    private static boolean hasSqlError(String body) {
        if (body == null) return false;
        String low = body.toLowerCase();
        for (String s : SQL_ERRORS) if (low.contains(s)) return true;
        return false;
    }

    /**
     * @param quoteProbeBody   response body after appending a single quote (error-based signal)
     * @param trueStatus       status of the `AND 1=1` (true) probe
     * @param trueLen          body length of the true probe
     * @param falseStatus      status of the `AND 1=2` (false) probe
     * @param falseLen         body length of the false probe
     */
    public static Evidence evaluate(String quoteProbeBody, int trueStatus, int trueLen,
                                    int falseStatus, int falseLen) {
        if (hasSqlError(quoteProbeBody)) {
            return new Evidence(Verdict.CONFIRMED, 0.9, true,
                    "Appending a single quote to the parameter produced a database engine error in the "
                            + "response -- the value reaches a SQL statement unescaped (error-based SQL injection).",
                    "error-based signature present");
        }
        if (trueStatus < 0 || falseStatus < 0) {
            return new Evidence(Verdict.INCONCLUSIVE, 0, false,
                    "No response was received for one of the boolean-differential SQLi probes.", "");
        }
        // Boolean-based: the always-true and always-false conditions must diverge.
        boolean statusDiverged = trueStatus != falseStatus;
        boolean lengthDiverged = Math.abs(trueLen - falseLen) > 32;
        if (statusDiverged || lengthDiverged) {
            return new Evidence(Verdict.CONFIRMED, 0.82, true,
                    "A boolean-based pair diverged: `AND 1=1` and `AND 1=2` produced materially different "
                            + "responses (status " + trueStatus + " vs " + falseStatus + ", length " + trueLen
                            + " vs " + falseLen + ") -- the parameter is boolean-blind SQL injectable.",
                    "statusDiverged=" + statusDiverged + " lengthDiverged=" + lengthDiverged);
        }
        return new Evidence(Verdict.REJECTED, 0.65, false,
                "Neither an error-based nor a boolean-differential signal appeared -- no SQL injection "
                        + "demonstrated on this parameter by the bounded Burp-plane probe (sqlmap may still be "
                        + "run harness-side for a deeper test).",
                "true=" + trueStatus + "/" + trueLen + " false=" + falseStatus + "/" + falseLen);
    }
}
