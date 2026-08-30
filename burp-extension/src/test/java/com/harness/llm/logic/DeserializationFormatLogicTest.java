package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.DeserializationFormatLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class DeserializationFormatLogicTest {

    @Test
    @DisplayName("empty or null body -> rejected")
    void emptyBodyIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate("").verdict());
        assertEquals(Verdict.REJECTED, evaluate(null).verdict());
    }

    @Test
    @DisplayName("plain JSON body -> rejected")
    void plainJsonIsRejected() {
        assertEquals(Verdict.REJECTED, evaluate("{\"username\": \"alice\", \"password\": \"x\"}").verdict());
    }

    @Test
    @DisplayName("base64 Java serialized object signature -> confirmed")
    void javaSerializedBase64IsConfirmed() {
        Evidence e = evaluate("data=rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAB");
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("PHP serialized array -> confirmed")
    void phpSerializedArrayIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, evaluate("data=a:2:{s:4:\"user\";s:5:\"alice\";}").verdict());
    }

    @Test
    @DisplayName("PHP serialized object -> confirmed")
    void phpSerializedObjectIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, evaluate("O:8:\"stdClass\":0:{}").verdict());
    }

    @Test
    @DisplayName("ASP.NET ViewState field name -> supported, not confirmed")
    void viewStateIsSupportedNotConfirmed() {
        Evidence e = evaluate("__VIEWSTATE=abc123&__EVENTVALIDATION=xyz");
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("ordinary text containing the letter sequences does not false-positive")
    void ordinaryTextDoesNotFalsePositive() {
        // "a:2:" pattern requires digit(s) then colon then optional quote --
        // ordinary prose shouldn't accidentally match this specific shape.
        Evidence e = evaluate("Please read section a2 of the manual for details.");
        assertEquals(Verdict.REJECTED, e.verdict());
    }
}
