package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.harness.llm.logic.RaceConditionLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class RaceConditionLogicTest {

    private static AttemptResult r(int status) { return new AttemptResult(status); }

    @Test
    @DisplayName("two of five succeed, rest rejected -> confirmed race condition")
    void partialSuccessIsConfirmed() {
        Evidence e = evaluate(List.of(r(200), r(200), r(409), r(409), r(409)));
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("exactly one success out of five -> correctly enforced, rejected")
    void singleSuccessIsRejected() {
        Evidence e = evaluate(List.of(r(200), r(409), r(409), r(409), r(409)));
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("zero successes out of five -> rejected (nothing to race)")
    void zeroSuccessesIsRejected() {
        Evidence e = evaluate(List.of(r(500), r(500), r(500), r(500), r(500)));
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("all five succeed -> supported but not confirmed, ambiguous with 'no limit at all'")
    void allSuccessIsSupportedNotConfirmed() {
        Evidence e = evaluate(List.of(r(200), r(201), r(200), r(200), r(200)));
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("single attempt succeeding alone (n=1) is not treated as the ambiguous all-succeed case")
    void singleAttemptSuccessIsNotAllSuccessCase() {
        Evidence e = evaluate(List.of(r(200)));
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("confirmed verdict carries higher confidence than the ambiguous all-success case")
    void confirmedHasHigherConfidenceThanAmbiguousAllSuccess() {
        Evidence confirmed = evaluate(List.of(r(200), r(200), r(409), r(409), r(409)));
        Evidence allSucceeded = evaluate(List.of(r(200), r(200), r(200), r(200), r(200)));
        assertTrue(confirmed.confidence() > allSucceeded.confidence());
    }
}
