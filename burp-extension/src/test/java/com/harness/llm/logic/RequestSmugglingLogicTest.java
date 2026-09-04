package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.RequestSmugglingLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class RequestSmugglingLogicTest {

    @Test
    void probeErrorIsSupportedNotConfirmed() {
        Evidence ev = evaluate(200, -1, true);
        assertEquals(Verdict.SUPPORTED, ev.verdict());
        assertFalse(ev.confirmed());
    }

    @Test
    void cleanRejectionIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(200, 400, false).verdict());
        assertEquals(Verdict.REJECTED, evaluate(200, 501, false).verdict());
    }

    @Test
    void silentAcceptanceIsSupportedNeverConfirmed() {
        Evidence ev = evaluate(200, 200, false);
        assertEquals(Verdict.SUPPORTED, ev.verdict());
        assertFalse(ev.confirmed());
    }

    @Test
    void noProbeResponseIsInconclusive() {
        assertEquals(Verdict.INCONCLUSIVE, evaluate(200, -1, false).verdict());
    }
}
