package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.SessionLifecycleLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class SessionLifecycleLogicTest {

    @Test
    @DisplayName("identical pre/post-login session ID is confirmed fixation")
    void identicalSessionIsFixationConfirmed() {
        Evidence ev = evaluateSessionFixation("abc123session", "abc123session");
        assertTrue(ev.verdict == Verdict.CONFIRMED, "expected CONFIRMED, got " + ev.verdict);
        assertTrue(ev.confirmed);
    }

    @Test
    @DisplayName("rotated session ID after login is rejected (correct behavior)")
    void rotatedSessionIsRejected() {
        Evidence ev = evaluateSessionFixation("abc123session", "xyz789different");
        assertTrue(ev.verdict == Verdict.REJECTED, "expected REJECTED, got " + ev.verdict);
        assertFalse(ev.confirmed);
    }

    @Test
    @DisplayName("missing pre-login session value is invalid, not a false negative")
    void missingPreLoginValueIsInvalid() {
        Evidence ev = evaluateSessionFixation(null, "xyz789");
        assertTrue(ev.verdict == Verdict.INVALID, "expected INVALID, got " + ev.verdict);
        assertFalse(ev.confirmed);
    }

    @Test
    @DisplayName("blank session values are treated the same as null")
    void blankSessionValueIsInvalid() {
        Evidence ev = evaluateSessionFixation("   ", "xyz789");
        assertTrue(ev.verdict == Verdict.INVALID, "expected INVALID for blank value, got " + ev.verdict);
    }

    @Test
    @DisplayName("old session reused after logout, matching pre-logout state, denied on anon -> confirmed")
    void sessionSurvivesLogoutIsConfirmed() {
        Probe preLogout = new Probe(200, "{\"account\":\"my private data\"}");
        Probe postLogoutReuse = new Probe(200, "{\"account\":\"my private data\"}");
        Probe anon = new Probe(401, "{\"error\":\"authentication required\"}");
        Evidence ev = evaluateLogoutInvalidation(preLogout, postLogoutReuse, anon);
        assertTrue(ev.verdict == Verdict.CONFIRMED, "expected CONFIRMED, got " + ev.verdict + " (" + ev.summary + ")");
        assertTrue(ev.confirmed);
        assertTrue(ev.confidence > 0.8, "expected high confidence, got " + ev.confidence);
    }

    @Test
    @DisplayName("old session rejected after logout (different status/body) -> rejected, invalidation works")
    void sessionInvalidatedIsRejected() {
        Probe preLogout = new Probe(200, "{\"account\":\"my private data\"}");
        Probe postLogoutReuse = new Probe(401, "{\"error\":\"session expired\"}");
        Probe anon = new Probe(401, "{\"error\":\"session expired\"}");
        Evidence ev = evaluateLogoutInvalidation(preLogout, postLogoutReuse, anon);
        assertTrue(ev.verdict == Verdict.REJECTED, "expected REJECTED, got " + ev.verdict);
        assertFalse(ev.confirmed);
    }

    @Test
    @DisplayName("matching pre-logout response but resource is actually public (anon matches too) -> inconclusive")
    void publicResourceIsNotConfirmedEvenIfSessionMatches() {
        Probe preLogout = new Probe(200, "<html>public page</html>");
        Probe postLogoutReuse = new Probe(200, "<html>public page</html>");
        Probe anon = new Probe(200, "<html>public page</html>"); // anon sees the same thing -> public
        Evidence ev = evaluateLogoutInvalidation(preLogout, postLogoutReuse, anon);
        assertTrue(ev.verdict == Verdict.INCONCLUSIVE, "expected INCONCLUSIVE for public resource, got " + ev.verdict);
        assertFalse(ev.confirmed, "a public resource must never be confirmed");
    }

    @Test
    @DisplayName("no anon baseline available caps verdict below CONFIRMED even if reuse matches pre-logout")
    void missingAnonBaselineCannotConfirm() {
        Probe preLogout = new Probe(200, "{\"account\":\"my private data\"}");
        Probe postLogoutReuse = new Probe(200, "{\"account\":\"my private data\"}");
        Evidence ev = evaluateLogoutInvalidation(preLogout, postLogoutReuse, null);
        assertTrue(ev.verdict != Verdict.CONFIRMED, "must never reach CONFIRMED without an anon baseline, got " + ev.verdict);
        assertFalse(ev.confirmed);
        assertTrue(ev.verdict == Verdict.INCONCLUSIVE, "expected INCONCLUSIVE as the capped tier, got " + ev.verdict);
    }

    @Test
    @DisplayName("missing probes are invalid input, not silently treated as a negative result")
    void missingProbesAreInvalid() {
        Evidence ev = evaluateLogoutInvalidation(null, new Probe(200, "x"), null);
        assertTrue(ev.verdict == Verdict.INVALID, "expected INVALID, got " + ev.verdict);
    }
}
