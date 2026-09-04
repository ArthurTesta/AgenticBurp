package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.OAuthFlowLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class OAuthFlowLogicTest {

    private static final String ATTACKER = "https://harness-oauth-probe.example/cb";

    @Test
    void noRedirectUriParamIsInvalid() {
        assertEquals(Verdict.INVALID, evaluate(false, true, ATTACKER, -1, null).verdict());
    }

    @Test
    void honouredTamperedRedirectIsConfirmed() {
        Evidence ev = evaluate(true, true, ATTACKER, 302, ATTACKER + "?code=xyz");
        assertEquals(Verdict.CONFIRMED, ev.verdict());
        assertTrue(ev.confirmed());
    }

    @Test
    void notHonouredButMissingStateIsSupported() {
        assertEquals(Verdict.SUPPORTED, evaluate(true, false, ATTACKER, 302, "https://legit.example/cb").verdict());
    }

    @Test
    void notHonouredWithStateIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(true, true, ATTACKER, 400, null).verdict());
    }
}
