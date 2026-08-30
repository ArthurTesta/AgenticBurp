package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.harness.llm.logic.SsrfCallbackLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class SsrfCallbackLogicTest {

    @Test
    @DisplayName("interaction observed on one candidate -> CONFIRMED")
    void interactionIsConfirmed() {
        CallbackAttempt hit = new CallbackAttempt("profileImage", "abc123.oastify.com", List.of("HTTP"));
        CallbackAttempt miss = new CallbackAttempt("callback", "def456.oastify.com", List.of());
        Evidence ev = evaluate(List.of(miss, hit));
        assertEquals(Verdict.CONFIRMED, ev.verdict, "expected CONFIRMED, got " + ev.verdict + " (" + ev.summary + ")");
        assertTrue(ev.confirmed);
        assertTrue(ev.confidence > 0.85);
    }

    @Test
    @DisplayName("no interaction on any candidate -> INCONCLUSIVE, never claims a negative")
    void noInteractionIsInconclusiveNotRejected() {
        CallbackAttempt a = new CallbackAttempt("url", "abc.oastify.com", List.of());
        CallbackAttempt b = new CallbackAttempt("redirect", "def.oastify.com", List.of());
        Evidence ev = evaluate(List.of(a, b));
        assertEquals(Verdict.INCONCLUSIVE, ev.verdict, "expected INCONCLUSIVE, got " + ev.verdict);
        assertFalse(ev.confirmed, "absence of an interaction must never be reported as confirmed-safe");
    }

    @Test
    @DisplayName("no candidate parameters at all -> INVALID, nothing was tested")
    void noCandidatesIsInvalid() {
        Evidence ev = evaluate(List.of());
        assertEquals(Verdict.INVALID, ev.verdict);
        assertFalse(ev.confirmed);
    }

    @Test
    @DisplayName("classic SSRF-shaped param names are recognized")
    void classicParamNamesRecognized() {
        for (String name : new String[]{"url", "URL", "redirect", "next", "return_to", "callback",
                "webhook", "target", "endpoint", "fetch", "proxy", "dest", "destination", "uri", "link"}) {
            assertTrue(isCallbackCandidateParam(name), name + " should be recognized as a callback candidate");
        }
    }

    @Test
    @DisplayName("profileImage is recognized -- the real Juice Shop ground truth this session found, "
            + "which PathScorer's existing narrower list missed")
    void profileImageIsRecognized() {
        assertTrue(isCallbackCandidateParam("profileImage"));
        assertTrue(isCallbackCandidateParam("avatarUrl"));
        assertTrue(isCallbackCandidateParam("photo_url"));
        assertTrue(isCallbackCandidateParam("picture"));
    }

    @Test
    @DisplayName("unrelated parameter names are not flagged")
    void unrelatedNamesNotFlagged() {
        for (String name : new String[]{"quantity", "id", "page", "sort", "email", "password"}) {
            assertFalse(isCallbackCandidateParam(name), name + " should NOT be a callback candidate");
        }
    }

    @Test
    @DisplayName("null/blank name does not match and does not throw")
    void nullOrBlankIsSafe() {
        assertFalse(isCallbackCandidateParam(null));
        assertFalse(isCallbackCandidateParam(""));
        assertFalse(isCallbackCandidateParam("   "));
    }
}
