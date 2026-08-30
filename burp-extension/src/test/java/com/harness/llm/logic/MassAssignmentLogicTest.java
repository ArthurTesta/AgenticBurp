package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.MassAssignmentLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class MassAssignmentLogicTest {

    @Test
    @DisplayName("injectField adds the field before the closing brace of a non-empty object")
    void injectFieldNonEmptyObject() {
        String result = injectField("{\"name\":\"alice\"}", "role", "\"admin\"");
        assertEquals("{\"name\":\"alice\",\"role\":\"admin\"}", result);
    }

    @Test
    @DisplayName("injectField handles an empty object body without a stray leading comma")
    void injectFieldEmptyObject() {
        String result = injectField("{}", "role", "\"admin\"");
        assertEquals("{\"role\":\"admin\"}", result);
    }

    @Test
    @DisplayName("injectField returns null for a non-object body (array, plain text, empty)")
    void injectFieldRejectsNonObjectBodies() {
        assertNull(injectField("[1,2,3]", "role", "\"admin\""));
        assertNull(injectField("not json at all", "role", "\"admin\""));
        assertNull(injectField("", "role", "\"admin\""));
        assertNull(injectField(null, "role", "\"admin\""));
    }

    @Test
    @DisplayName("field already in the original request body -> invalid, not a useful probe")
    void fieldAlreadyPresentIsInvalid() {
        Evidence e = evaluate("role", "\"admin\"", true, "{}", "{\"role\":\"admin\"}");
        assertEquals(Verdict.INVALID, e.verdict());
    }

    @Test
    @DisplayName("injected field reflected back, absent from baseline -> confirmed mass assignment")
    void reflectedAndNewIsConfirmed() {
        Evidence e = evaluate("role", "\"admin\"", false,
                "{\"id\":1,\"name\":\"alice\"}", "{\"id\":1,\"name\":\"alice\",\"role\":\"admin\"}");
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("injected field absent from mutated response -> rejected")
    void notReflectedIsRejected() {
        Evidence e = evaluate("role", "\"admin\"", false,
                "{\"id\":1,\"name\":\"alice\"}", "{\"id\":1,\"name\":\"alice\"}");
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("field/value already present in baseline response too -> supported, not confirmed")
    void alreadyInBaselineIsSupportedNotConfirmed() {
        Evidence e = evaluate("role", "\"admin\"", false,
                "{\"id\":1,\"role\":\"admin\"}", "{\"id\":1,\"role\":\"admin\"}");
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }
}
