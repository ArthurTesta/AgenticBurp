package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.CsrfLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class CsrfLogicTest {

    @Test
    @DisplayName("known CSRF token names are recognized case-insensitively")
    void tokenNamesRecognized() {
        assertTrue(looksLikeCsrfTokenName("csrf_token"));
        assertTrue(looksLikeCsrfTokenName("X-CSRF-Token"));
        assertTrue(looksLikeCsrfTokenName("csrfmiddlewaretoken"));
        assertTrue(looksLikeCsrfTokenName("authenticity_token"));
        assertTrue(looksLikeCsrfTokenName("__RequestVerificationToken"));
        assertFalse(looksLikeCsrfTokenName("quantity"));
        assertFalse(looksLikeCsrfTokenName(null));
    }

    @Test
    @DisplayName("safe methods are recognized")
    void safeMethodsRecognized() {
        assertTrue(isSafeMethod("GET"));
        assertTrue(isSafeMethod("head"));
        assertTrue(isSafeMethod("OPTIONS"));
        assertFalse(isSafeMethod("POST"));
        assertFalse(isSafeMethod("PUT"));
        assertFalse(isSafeMethod("DELETE"));
    }

    @Test
    @DisplayName("GET request -> invalid, CSRF not applicable")
    void safeMethodIsInvalid() {
        Evidence e = evaluate("GET", true, true, 200, 200);
        assertEquals(Verdict.INVALID, e.verdict());
    }

    @Test
    @DisplayName("non-cookie (Bearer token) auth -> rejected, not applicable the same way")
    void nonCookieAuthIsRejected() {
        Evidence e = evaluate("POST", false, false, 200, -1);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("token found, removal probe not run -> supported only, presence alone isn't proof")
    void tokenFoundButNotProbedIsSupported() {
        Evidence e = evaluate("POST", true, true, 200, -1);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("token found, request still succeeds after removal -> confirmed, token not enforced")
    void tokenRemovedButStillSucceedsIsConfirmed() {
        Evidence e = evaluate("POST", true, true, 200, 200);
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("token found, request correctly rejected after removal -> rejected, properly protected")
    void tokenRemovedAndRejectedIsRejected() {
        Evidence e = evaluate("POST", true, true, 200, 403);
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("no token found at all, cookie-authenticated state change -> supported, passive signal only")
    void noTokenFoundIsSupported() {
        Evidence e = evaluate("PUT", true, false, 200, -1);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("both original and mutated requests succeed within the 2xx range even at different codes -> still confirmed")
    void differentButBothSuccessfulStatusesStillConfirmed() {
        Evidence e = evaluate("POST", true, true, 200, 201);
        assertEquals(Verdict.CONFIRMED, e.verdict());
    }
}
