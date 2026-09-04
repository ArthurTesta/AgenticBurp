package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.SubdomainTakeoverLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class SubdomainTakeoverLogicTest {

    @Test
    void knownFingerprintIsConfirmed() {
        Evidence ev = evaluate(404, "<html>There isn't a GitHub Pages site here.</html>");
        assertEquals(Verdict.CONFIRMED, ev.verdict());
        assertTrue(ev.confirmed());
    }

    @Test
    void s3FingerprintIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, evaluate(404, "<Error><Code>NoSuchBucket</Code></Error>").verdict());
    }

    @Test
    void plain404NoFingerprintIsSupported() {
        assertEquals(Verdict.SUPPORTED, evaluate(404, "generic not found page").verdict());
    }

    @Test
    void ok200NoFingerprintIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(200, "<html>welcome</html>").verdict());
    }

    @Test
    void nullBodyIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(200, null).verdict());
    }
}
