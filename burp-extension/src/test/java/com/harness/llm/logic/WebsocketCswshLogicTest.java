package com.harness.llm.logic;

import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.WebsocketCswshLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class WebsocketCswshLogicTest {

    @Test
    void notAWebsocketHandshakeIsInvalid() {
        assertEquals(Verdict.INVALID, evaluate(false, true, 101).verdict());
    }

    @Test
    void foreignOriginHandshakeAcceptedWithAuthIsConfirmed() {
        Evidence ev = evaluate(true, true, 101);
        assertEquals(Verdict.CONFIRMED, ev.verdict());
        assertTrue(ev.confirmed());
    }

    @Test
    void acceptedWithoutAuthIsSupported() {
        assertEquals(Verdict.SUPPORTED, evaluate(true, false, 101).verdict());
    }

    @Test
    void handshakeRejectedIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate(true, true, 403).verdict());
    }
}
