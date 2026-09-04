package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import java.util.List;

import static com.harness.llm.logic.CryptoTransportLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class CryptoTransportLogicTest {

    @Test
    void plaintextWithCredentialsIsConfirmed() {
        Evidence ev = evaluate(false, null, List.of("sid=abc"), true);
        assertEquals(Verdict.CONFIRMED, ev.verdict());
        assertTrue(ev.confirmed());
    }

    @Test
    void plaintextWithoutCredentialsIsSupported() {
        assertEquals(Verdict.SUPPORTED, evaluate(false, null, List.of(), false).verdict());
    }

    @Test
    void httpsMissingHstsIsSupported() {
        assertEquals(Verdict.SUPPORTED, evaluate(true, null, List.of(), false).verdict());
    }

    @Test
    void httpsCookieMissingSecureIsSupported() {
        assertEquals(Verdict.SUPPORTED, evaluate(true, "max-age=31536000", List.of("sid=abc; HttpOnly"), false).verdict());
    }

    @Test
    void httpsHardenedIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(true, "max-age=31536000", List.of("sid=abc; Secure; HttpOnly"), true).verdict());
    }
}
