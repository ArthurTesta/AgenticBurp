package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static com.harness.llm.logic.CommandInjectionTimingLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class CommandInjectionTimingLogicTest {

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
    @DisplayName("render substitutes the duration into the template")
    void renderSubstitutesDuration() {
        Payload p = new Payload("Unix", "; sleep {N} ;");
        assertEquals("; sleep 6 ;", p.render(6));
    }

    @Test
    @DisplayName("delta tracking the requested difference, both clearly slower than baseline -> confirmed")
    void trackingDeltaIsConfirmed() {
        Payload p = PAYLOADS.get(0);
        // baseline=100ms, short(2s)=2100ms, long(6s)=6100ms -- delta=4000ms, expected=4000ms
        Evidence e = evaluate(p, 100, 2100, 6100);
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("delta approximately tracking within tolerance -> still confirmed")
    void approximateTrackingWithinToleranceIsConfirmed() {
        Payload p = PAYLOADS.get(0);
        // delta=3200ms vs expected 4000ms -- within the 0.5x-2.5x tolerance band
        Evidence e = evaluate(p, 100, 2300, 5500);
        assertEquals(Verdict.CONFIRMED, e.verdict());
    }

    @Test
    @DisplayName("both slower than baseline but delta doesn't track requested difference -> supported, not confirmed")
    void slowerButNotTrackingIsSupported() {
        Payload p = PAYLOADS.get(0);
        // both requests took ~5s regardless of requested duration -- generic slowness, not injection
        Evidence e = evaluate(p, 100, 5000, 5100);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("neither probe slower than baseline -> rejected")
    void noDelayAtAllIsRejected() {
        Payload p = PAYLOADS.get(0);
        Evidence e = evaluate(p, 100, 110, 120);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("only the long probe is slower, short probe is not -- fails the 'both slower' requirement")
    void onlyLongProbeSlowerIsNotConfirmed() {
        Payload p = PAYLOADS.get(0);
        Evidence e = evaluate(p, 100, 150, 6100);
        assertNotEquals(Verdict.CONFIRMED, e.verdict());
    }

    @Test
    @DisplayName("all payload templates contain the {N} placeholder")
    void allPayloadsHavePlaceholder() {
        for (Payload p : PAYLOADS) {
            assertTrue(p.template().contains("{N}"), "missing placeholder in: " + p.template());
        }
    }
}
