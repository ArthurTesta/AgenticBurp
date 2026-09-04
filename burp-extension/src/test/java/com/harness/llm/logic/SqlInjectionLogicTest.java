package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.SqlInjectionLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class SqlInjectionLogicTest {

    @Test
    void errorBasedSignatureIsConfirmed() {
        Evidence ev = evaluate("You have an error in your SQL syntax near ''", 200, 100, 200, 100);
        assertEquals(Verdict.CONFIRMED, ev.verdict());
        assertTrue(ev.confirmed());
    }

    @Test
    void booleanStatusDivergenceIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, evaluate("ok", 200, 500, 404, 20).verdict());
    }

    @Test
    void booleanLengthDivergenceIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, evaluate("ok", 200, 5000, 200, 120).verdict());
    }

    @Test
    void noSignalIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate("ok", 200, 100, 200, 110).verdict());
    }

    @Test
    void missingProbeIsInconclusive() {
        assertEquals(Verdict.INCONCLUSIVE, evaluate("ok", -1, 0, 200, 100).verdict());
    }
}
