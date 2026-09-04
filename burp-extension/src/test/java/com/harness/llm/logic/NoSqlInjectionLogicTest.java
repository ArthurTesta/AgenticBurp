package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.NoSqlInjectionLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class NoSqlInjectionLogicTest {

    @Test
    void driverErrorSignatureIsConfirmed() {
        Evidence ev = evaluate(200, 500, "MongoError: unknown operator $ne");
        assertEquals(Verdict.CONFIRMED, ev.verdict());
        assertTrue(ev.confirmed());
    }

    @Test
    void deniedToAllowedFlipIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, evaluate(401, 200, "{\"ok\":true}").verdict());
    }

    @Test
    void noErrorNoFlipIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(200, 200, "{\"ok\":true}").verdict());
    }

    @Test
    void noResponseIsInconclusive() {
        assertEquals(Verdict.INCONCLUSIVE, evaluate(200, -1, null).verdict());
    }
}
