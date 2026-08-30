package com.harness.llm.logic;

/**
 * Classification logic for api_security_validation's mass-assignment
 * probe. Montoya-free.
 *
 * Directly implements the specialist agent's own suggested_test for
 * this finding class (see agents/api_security_agent.py's docstring):
 * "Resend a create/update request with an extra unexpected field (e.g.
 * 'role': 'admin') added to the JSON body and check whether the
 * response reflects it back as accepted." The probe adds a field the
 * ORIGINAL request never sent; if the mutated response reflects that
 * exact field/value back and the baseline (unmodified) response didn't
 * already show it, that's evidence the server blindly binds request
 * JSON onto an internal object without an allowlist of settable fields.
 *
 * Deliberately string-based, not a full JSON parse/serialize round
 * trip: injectField() only ever needs to insert one flat key before the
 * closing brace of an object-shaped body, and a full parser would need
 * to perfectly round-trip arbitrary real-world JSON (key ordering,
 * number formatting, unicode escaping) to avoid corrupting requests
 * this technique isn't even trying to test.
 */
public final class MassAssignmentLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INVALID }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private MassAssignmentLogic() {}

    /**
     * @return the body with `"fieldName":fieldValueJson` inserted before the final `}`,
     *         or null if the body isn't a plain JSON object ({...}).
     */
    public static String injectField(String originalBody, String fieldName, String fieldValueJson) {
        if (originalBody == null) return null;
        String trimmed = originalBody.trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return null;

        String withoutClosingBrace = trimmed.substring(0, trimmed.length() - 1);
        boolean emptyObject = withoutClosingBrace.trim().endsWith("{");
        String separator = emptyObject ? "" : ",";
        return withoutClosingBrace + separator + "\"" + fieldName + "\":" + fieldValueJson + "}";
    }

    public static Evidence evaluate(String fieldName, String fieldValueJson, boolean fieldAlreadyInRequestBody,
                                     String baselineResponseBody, String mutatedResponseBody) {
        if (fieldAlreadyInRequestBody) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "The field '" + fieldName + "' was already present in the original request body -- not a "
                            + "useful probe for blind mass assignment (the field is evidently already settable, "
                            + "intentionally or not, by the request's own author).",
                    "");
        }

        String keyNeedle = "\"" + fieldName + "\"";
        boolean mutatedReflects = mutatedResponseBody != null
                && mutatedResponseBody.contains(keyNeedle) && mutatedResponseBody.contains(fieldValueJson);
        boolean baselineAlreadyHadValue = baselineResponseBody != null
                && baselineResponseBody.contains(keyNeedle) && baselineResponseBody.contains(fieldValueJson);

        if (mutatedReflects && !baselineAlreadyHadValue) {
            return new Evidence(Verdict.CONFIRMED, 0.85, true,
                    "Adding an unrequested field ('" + fieldName + "': " + fieldValueJson + ") to the request "
                            + "body caused the response to reflect that exact field/value back, and the baseline "
                            + "(unmodified) response did not already show it -- consistent with the server blindly "
                            + "binding request JSON onto an internal object with no allowlist of settable fields "
                            + "(mass assignment / excessive data binding).",
                    "");
        }
        if (mutatedReflects) {
            return new Evidence(Verdict.SUPPORTED, 0.4, false,
                    "The mutated response reflects the injected field, but the baseline (unmodified) response "
                            + "already showed that same field/value -- this alone doesn't prove the injected "
                            + "value was newly accepted rather than already present.",
                    "");
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "The server did not reflect the injected field ('" + fieldName + "') back in its response -- "
                        + "no evidence of unvalidated mass assignment for this field.",
                "");
    }
}
