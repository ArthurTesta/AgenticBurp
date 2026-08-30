package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.CspClickjackingLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class CspClickjackingLogicTest {

    @Test
    @DisplayName("non-HTML content type is invalid input, not a finding either way")
    void nonHtmlIsInvalid() {
        Evidence e = evaluate("application/json", null, null);
        assertEquals(Verdict.INVALID, e.verdict());
    }

    @Test
    @DisplayName("CSP frame-ancestors present -> rejected (protected)")
    void cspFrameAncestorsProtects() {
        Evidence e = evaluate("text/html", null, "default-src 'self'; frame-ancestors 'self'");
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("valid X-Frame-Options DENY -> rejected (protected)")
    void validXfoDenyProtects() {
        Evidence e = evaluate("text/html", "DENY", null);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("valid X-Frame-Options SAMEORIGIN (mixed case) -> rejected (protected)")
    void validXfoSameoriginCaseInsensitive() {
        Evidence e = evaluate("text/html", "sameOrigin", null);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("malformed X-Frame-Options value -> supported, not rejected")
    void malformedXfoIsSupported() {
        Evidence e = evaluate("text/html", "ALLOW-FROM https://example.com", null);
        assertEquals(Verdict.SUPPORTED, e.verdict());
    }

    @Test
    @DisplayName("neither CSP nor X-Frame-Options present on an HTML page -> supported")
    void missingBothIsSupported() {
        Evidence e = evaluate("text/html; charset=utf-8", null, null);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }
}
