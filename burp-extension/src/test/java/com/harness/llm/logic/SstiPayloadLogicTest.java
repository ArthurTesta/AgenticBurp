package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static com.harness.llm.logic.SstiPayloadLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class SstiPayloadLogicTest {

    @Test
    @DisplayName("nextPayload cycles through untried payloads, ends at null")
    void nextPayloadCyclesAndExhausts() {
        List<String> tried = new ArrayList<>();
        int count = 0;
        Payload p;
        while ((p = nextPayload(tried)) != null) {
            assertFalse(tried.contains(p.template()));
            tried.add(p.template());
            count++;
            if (count > 10) fail("nextPayload did not terminate");
        }
        assertEquals(PAYLOADS.size(), count);
    }

    @Test
    @DisplayName("result present in mutated, absent from baseline, template gone -> confirmed")
    void evaluatedResultIsConfirmed() {
        Payload p = PAYLOADS.get(0); // Jinja2/Twig {{7*13}}
        Evidence e = classify(p, "<html>welcome</html>", "<html>result: 91</html>");
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("result present in mutated but raw template also survives -> supported, not confirmed")
    void resultWithSurvivingTemplateIsSupported() {
        Payload p = PAYLOADS.get(0);
        Evidence e = classify(p, "<html>welcome</html>", "<html>{{7*13}} = 91</html>");
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("result already present in baseline -> rejected, not proof of evaluation")
    void resultAlreadyInBaselineIsRejected() {
        Payload p = PAYLOADS.get(0);
        Evidence e = classify(p, "<html>count: 91</html>", "<html>count: 91</html>");
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("no result anywhere -> rejected")
    void noResultIsRejected() {
        Payload p = PAYLOADS.get(0);
        Evidence e = classify(p, "<html>welcome</html>", "<html>{{7*13}}</html>");
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("null mutated body -> rejected, not a crash")
    void nullMutatedBodyIsRejected() {
        Payload p = PAYLOADS.get(0);
        Evidence e = classify(p, "baseline", null);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("null baseline body is treated the same as an empty one, not a crash")
    void nullBaselineBodyDoesNotCrash() {
        Payload p = PAYLOADS.get(0);
        Evidence e = classify(p, null, "result: 91");
        assertEquals(Verdict.CONFIRMED, e.verdict());
    }

    @Test
    @DisplayName("all five engine payloads have the same expected arithmetic result")
    void allPayloadsShareExpectedResult() {
        for (Payload p : PAYLOADS) {
            assertEquals("91", p.expectedResult());
        }
    }
}
