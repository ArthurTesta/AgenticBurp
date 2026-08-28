package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.WorkflowReplayLogic.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Real JUnit 5 tests, discoverable by `gradle test`, written directly in
 * this format (see IdentityCompareLogicTest's history note for why the
 * project standardized on this rather than a plain-main() runner).
 */
public final class WorkflowReplayLogicTest {

    private static IdentityCompareLogic.Probe probe(int status) {
        return new IdentityCompareLogic.Probe(status, "");
    }

    @Test
    @DisplayName("negative quantity accepted, malformed rejected -> CONFIRMED (real Juice Shop ground truth shape)")
    void missingBoundsCheckIsConfirmed() {
        Evidence ev = evaluate("quantity", "3", "-500", probe(200), probe(200), probe(400));
        assertEquals(Verdict.CONFIRMED, ev.verdict, "expected CONFIRMED, got " + ev.verdict + " (" + ev.summary + ")");
        assertTrue(ev.confirmed, "confirmed flag must be true");
        assertTrue(ev.confidence > 0.8, "confidence should be high for a clean confirm, got " + ev.confidence);
    }

    @Test
    @DisplayName("boundary value rejected -> REJECTED, not confirmed")
    void enforcedBoundsCheckIsRejected() {
        Evidence ev = evaluate("quantity", "3", "-500", probe(200), probe(400), probe(400));
        assertEquals(Verdict.REJECTED, ev.verdict, "expected REJECTED, got " + ev.verdict);
        assertFalse(ev.confirmed, "an enforced bounds check must not be confirmed");
    }

    @Test
    @DisplayName("boundary AND malformed both accepted -> SUPPORTED only, generic lack of validation")
    void genericLackOfValidationIsNotConfirmed() {
        Evidence ev = evaluate("quantity", "3", "-500", probe(200), probe(200), probe(200));
        assertEquals(Verdict.SUPPORTED, ev.verdict, "expected SUPPORTED, got " + ev.verdict);
        assertFalse(ev.confirmed, "generic 'accepts everything' must not reach CONFIRMED -- it's a weaker, less specific signal");
    }

    @Test
    @DisplayName("missing malformed control caps verdict at SUPPORTED, never CONFIRMED")
    void missingMalformedControlCannotConfirm() {
        Evidence ev = evaluate("quantity", "3", "-500", probe(200), probe(200), null);
        assertEquals(Verdict.SUPPORTED, ev.verdict, "expected SUPPORTED, got " + ev.verdict);
        assertFalse(ev.confirmed, "without a negative control this must never reach CONFIRMED");
    }

    @Test
    @DisplayName("baseline itself fails -> INCONCLUSIVE, cannot establish comparison")
    void failedBaselineIsInconclusive() {
        Evidence ev = evaluate("quantity", "3", "-500", probe(500), probe(200), probe(400));
        assertEquals(Verdict.INCONCLUSIVE, ev.verdict, "expected INCONCLUSIVE, got " + ev.verdict);
        assertFalse(ev.confirmed);
    }

    @Test
    @DisplayName("value that isn't actually a boundary violation is rejected as INVALID input, not tested")
    void notAGenuineBoundaryIsInvalid() {
        // 3 -> 4 is not a boundary violation of a non-negative quantity.
        Evidence ev = evaluate("quantity", "3", "4", probe(200), probe(200), probe(400));
        assertEquals(Verdict.INVALID, ev.verdict, "expected INVALID, got " + ev.verdict);
        assertFalse(ev.confirmed);
    }

    @Test
    @DisplayName("extreme magnitude jump on an originally-negative-capable field still counts as a boundary violation")
    void extremeMagnitudeJumpIsGenuineBoundary() {
        assertTrue(WorkflowReplayLogic.isGenuineBoundaryViolation("5", "50000000"),
                "a 1000x+ magnitude jump should count as a boundary violation even without a sign flip");
        assertFalse(WorkflowReplayLogic.isGenuineBoundaryViolation("5", "6"),
                "a small in-range change must not count as a boundary violation");
    }

    @Test
    @DisplayName("non-numeric original or boundary value is rejected as INVALID, not silently coerced")
    void nonNumericValuesAreInvalid() {
        Evidence ev = evaluate("quantity", "not_a_number", "-500", probe(200), probe(200), probe(400));
        assertEquals(Verdict.INVALID, ev.verdict, "expected INVALID for unparseable original value, got " + ev.verdict);
    }

    @Test
    @DisplayName("numeric quantity-shaped params are recognized as boundary candidates; non-numeric ones are not")
    void candidateParamNamesAreCorrect() {
        for (String name : new String[]{"price", "amount", "quantity", "qty", "discount", "count", "total", "balance", "value", "PRICE"}) {
            assertTrue(WorkflowReplayLogic.isNumericBoundaryCandidateParam(name), name + " should be a boundary candidate");
        }
        for (String name : new String[]{"role", "is_admin", "admin", "status", "id", "email", null}) {
            assertFalse(WorkflowReplayLogic.isNumericBoundaryCandidateParam(name), name + " should NOT be a boundary candidate");
        }
    }
}
