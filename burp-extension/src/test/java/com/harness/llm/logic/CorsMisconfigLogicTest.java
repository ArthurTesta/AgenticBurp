package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.CorsMisconfigLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class CorsMisconfigLogicTest {

    private static final String EVIL = "https://evil-harness-probe.example";

    @Test
    @DisplayName("no ACAO header at all -> rejected")
    void noAcaoIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(EVIL, null, null).verdict());
    }

    @Test
    @DisplayName("ACAO reflects injected origin exactly + credentials true -> confirmed, the dangerous combo")
    void reflectedOriginWithCredentialsIsConfirmed() {
        Evidence e = evaluate(EVIL, EVIL, "true");
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("ACAO reflects injected origin but no credentials -> supported, lower severity")
    void reflectedOriginWithoutCredentialsIsSupported() {
        Evidence e = evaluate(EVIL, EVIL, null);
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("ACAO reflection is case-insensitive")
    void reflectionCaseInsensitive() {
        Evidence e = evaluate(EVIL, EVIL.toUpperCase(), "TRUE");
        assertEquals(Verdict.CONFIRMED, e.verdict());
    }

    @Test
    @DisplayName("wildcard ACAO with credentials true -> supported (invalid combo, still a misconfig)")
    void wildcardWithCredentialsIsSupported() {
        Evidence e = evaluate(EVIL, "*", "true");
        assertEquals(Verdict.SUPPORTED, e.verdict());
    }

    @Test
    @DisplayName("wildcard ACAO without credentials is the safe, common case -> rejected")
    void wildcardWithoutCredentialsIsRejected() {
        Evidence e = evaluate(EVIL, "*", null);
        assertEquals(Verdict.REJECTED, e.verdict());
    }

    @Test
    @DisplayName("ACAO set to a fixed, legitimate origin (not reflecting ours) -> rejected")
    void fixedLegitimateOriginIsRejected() {
        Evidence e = evaluate(EVIL, "https://app.example.com", "true");
        assertEquals(Verdict.REJECTED, e.verdict());
    }
}
