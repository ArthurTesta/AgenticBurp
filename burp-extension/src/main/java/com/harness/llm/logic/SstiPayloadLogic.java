package com.harness.llm.logic;

import java.util.List;

/**
 * Payload selection + classification logic for ssti_validation.
 * Montoya-free, mirrors XssPayloadLogic's Payload/Verdict/classify shape.
 *
 * Uses a fixed arithmetic expression (7*13=91) across several template
 * engines' syntax rather than a canary substitution: unlike XSS, where
 * the payload just needs to survive verbatim, an SSTI probe needs the
 * template engine to actually EVALUATE something, and arithmetic is the
 * simplest cross-engine-portable thing to evaluate and check. 91 is
 * deliberately not a round/common number (avoids coincidental
 * appearance in ordinary response content the way "100" or "42" might).
 * classify() additionally requires the result be ABSENT from the
 * baseline (pre-injection) response, guarding against exactly that
 * coincidence -- a real evaluation should only show up in the mutated
 * response, not something already present in ordinary page content.
 */
public final class SstiPayloadLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    public record Payload(String engineName, String template, String expectedResult) {}

    private static final String EXPECTED = "91"; // 7*13, chosen to avoid coincidental appearance

    public static final List<Payload> PAYLOADS = List.of(
            new Payload("Jinja2/Twig", "{{7*13}}", EXPECTED),
            new Payload("FreeMarker", "${7*13}", EXPECTED),
            new Payload("Velocity", "#set($sstiHarness=7*13)$sstiHarness", EXPECTED),
            new Payload("ERB (Ruby)", "<%=7*13%>", EXPECTED),
            new Payload("Smarty", "{7*13}", EXPECTED)
    );

    private SstiPayloadLogic() {}

    public static Payload nextPayload(List<String> triedTemplates) {
        for (Payload p : PAYLOADS) if (!triedTemplates.contains(p.template())) return p;
        return null;
    }

    /**
     * @param payload the payload that was sent
     * @param baselineBody the response body BEFORE injection (the original captured exchange)
     * @param mutatedBody the response body AFTER sending the payload
     */
    public static Evidence classify(Payload payload, String baselineBody, String mutatedBody) {
        if (mutatedBody == null) {
            return new Evidence(Verdict.REJECTED, 0.0, false, "No response body was received.", "");
        }
        boolean expectedInBaseline = baselineBody != null && baselineBody.contains(payload.expectedResult());
        boolean expectedInMutated = mutatedBody.contains(payload.expectedResult());
        boolean rawTemplateSurvived = mutatedBody.contains(payload.template());

        if (expectedInMutated && !expectedInBaseline && !rawTemplateSurvived) {
            return new Evidence(Verdict.CONFIRMED, 0.88, true,
                    "A " + payload.engineName() + "-style template expression (" + payload.template()
                            + ") was evaluated server-side: its arithmetic result (" + payload.expectedResult()
                            + ") appears in the response, the raw template syntax does not survive, and the "
                            + "result was absent from the baseline (pre-injection) response.",
                    "template=" + payload.template() + " expected=" + payload.expectedResult());
        }
        if (expectedInMutated && !expectedInBaseline) {
            return new Evidence(Verdict.SUPPORTED, 0.5, false,
                    "The expected evaluated result appeared (and was absent from the baseline), but the raw "
                            + "template text also survived in the response -- worth a manual check; this could "
                            + "indicate partial evaluation or be coincidental.",
                    "template=" + payload.template() + " expected=" + payload.expectedResult());
        }
        return new Evidence(Verdict.REJECTED, 0.72, false,
                "No evidence that the " + payload.engineName() + "-style template expression was evaluated.",
                "template=" + payload.template());
    }
}
