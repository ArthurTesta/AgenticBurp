package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.OpenRedirectLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class OpenRedirectLogicTest {

    private static final String INJECTED = "https://harness-redirect-probe.example/proof";

    @Test
    @DisplayName("non-redirect status -> rejected")
    void nonRedirectStatusIsRejected() {
        Evidence e = evaluate(INJECTED, 200, null, "next");
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("redirect status with no Location header -> invalid input")
    void redirectWithNoLocationIsInvalid() {
        Evidence e = evaluate(INJECTED, 302, null, "next");
        assertEquals(Verdict.INVALID, e.verdict());
    }

    @Test
    @DisplayName("Location exactly matches injected URL -> confirmed")
    void exactMatchIsConfirmed() {
        Evidence e = evaluate(INJECTED, 302, INJECTED, "next");
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("exact match is case-insensitive")
    void exactMatchCaseInsensitive() {
        Evidence e = evaluate(INJECTED, 302, INJECTED.toUpperCase(), "next");
        assertEquals(Verdict.CONFIRMED, e.verdict());
    }

    @Test
    @DisplayName("Location references injected host but isn't an exact match -> supported")
    void hostReferencedButNotExactIsSupported() {
        Evidence e = evaluate(INJECTED, 302, "https://harness-redirect-probe.example/different-path", "next");
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("Location points somewhere unrelated -> rejected")
    void unrelatedLocationIsRejected() {
        Evidence e = evaluate(INJECTED, 302, "/login", "next");
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("redirect to the app's own domain, ignoring the injected param -> rejected")
    void redirectToOwnDomainIgnoringParamIsRejected() {
        Evidence e = evaluate(INJECTED, 302, "https://app.example.com/home", "next");
        assertEquals(Verdict.REJECTED, e.verdict());
    }
}
