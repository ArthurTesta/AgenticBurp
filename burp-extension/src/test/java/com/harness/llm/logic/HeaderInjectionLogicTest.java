package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.HeaderInjectionLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class HeaderInjectionLogicTest {

    @Test
    @DisplayName("buildPayload appends CRLF-encoded marker header after the original value")
    void buildPayloadAppendsMarker() {
        String payload = buildPayload("https://example.com/next", "X-Test", "abc123");
        assertEquals("https://example.com/next%0d%0aX-Test: abc123", payload);
    }

    @Test
    @DisplayName("marker header appears with the exact expected value -> confirmed")
    void markerHeaderInjectedIsConfirmed() {
        Evidence e = evaluate("returnUrl", "X-Harness-Crlf-Test", "injected-12345", false, "injected-12345");
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("marker header absent from mutated response -> rejected")
    void markerHeaderAbsentIsRejected() {
        Evidence e = evaluate("returnUrl", "X-Harness-Crlf-Test", "injected-12345", false, null);
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("marker header present but with a different value -> rejected, not a real injection")
    void markerHeaderPresentWithWrongValueIsRejected() {
        Evidence e = evaluate("returnUrl", "X-Harness-Crlf-Test", "injected-12345", false, "something-else");
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("baseline already carries the marker header name -> invalid, can't use as a marker")
    void baselineAlreadyHasMarkerHeaderIsInvalid() {
        Evidence e = evaluate("returnUrl", "X-Harness-Crlf-Test", "injected-12345", true, "injected-12345");
        assertEquals(Verdict.INVALID, e.verdict());
        assertEquals(0.0, e.confidence());
    }
}
