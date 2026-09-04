package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.WebCachePoisoningLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class WebCachePoisoningLogicTest {

    private static final String MARK = "harness-cache-probe.example";

    @Test
    void reflectedAndCachedIsConfirmed() {
        Evidence ev = evaluate(MARK, true, false, "HIT", "12");
        assertEquals(Verdict.CONFIRMED, ev.verdict());
        assertTrue(ev.confirmed());
    }

    @Test
    void reflectedNoCacheIndicatorIsSupported() {
        assertEquals(Verdict.SUPPORTED, evaluate(MARK, true, false, null, null).verdict());
    }

    @Test
    void reflectedButFollowUpCarriedHeaderIsRejected() {
        // If the follow-up itself sent the header, reflection proves nothing.
        assertEquals(Verdict.REJECTED, evaluate(MARK, true, true, "HIT", "12").verdict());
    }

    @Test
    void notReflectedIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(MARK, false, false, "MISS", "0").verdict());
    }

    @Test
    void noMarkerIsInconclusive() {
        assertEquals(Verdict.INCONCLUSIVE, evaluate(null, true, false, "HIT", "12").verdict());
    }
}
