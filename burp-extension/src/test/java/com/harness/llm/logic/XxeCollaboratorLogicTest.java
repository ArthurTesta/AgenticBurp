package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.harness.llm.logic.XxeCollaboratorLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class XxeCollaboratorLogicTest {

    @Test
    @DisplayName("Content-Type application/xml is XML-like even with a non-XML-looking body")
    void contentTypeXmlIsRecognized() {
        assertTrue(isXmlLike("application/xml", "whatever"));
        assertTrue(isXmlLike("text/xml; charset=utf-8", "whatever"));
    }

    @Test
    @DisplayName("body starting with an XML declaration is recognized regardless of Content-Type")
    void xmlDeclarationBodyIsRecognized() {
        assertTrue(isXmlLike("text/plain", "<?xml version=\"1.0\"?><foo>bar</foo>"));
    }

    @Test
    @DisplayName("body starting with a root element (no declaration) is recognized")
    void bareRootElementIsRecognized() {
        assertTrue(isXmlLike(null, "<foo><bar>baz</bar></foo>"));
    }

    @Test
    @DisplayName("JSON body with no XML Content-Type is not XML-like")
    void jsonBodyIsNotXml() {
        assertFalse(isXmlLike("application/json", "{\"foo\": \"bar\"}"));
    }

    @Test
    @DisplayName("empty or null body with no XML content-type is not XML-like")
    void emptyBodyIsNotXml() {
        assertFalse(isXmlLike("application/json", ""));
        assertFalse(isXmlLike(null, null));
    }

    @Test
    @DisplayName("buildPayload embeds the collaborator host in a SYSTEM entity URL")
    void payloadEmbedsCollaboratorHost() {
        String payload = buildPayload("abc123.collaborator.example");
        assertTrue(payload.contains("abc123.collaborator.example"));
        assertTrue(payload.contains("<!ENTITY xxe SYSTEM"));
        assertTrue(payload.contains("&xxe;"));
    }

    @Test
    @DisplayName("non-XML request -> invalid, not a finding either way")
    void nonXmlIsInvalid() {
        Evidence e = evaluate(false, List.of());
        assertEquals(Verdict.INVALID, e.verdict());
    }

    @Test
    @DisplayName("XML request with an observed interaction -> confirmed")
    void interactionObservedIsConfirmed() {
        Evidence e = evaluate(true, List.of("DNS"));
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("XML request with no interaction observed -> inconclusive, not proof of safety")
    void noInteractionIsInconclusive() {
        Evidence e = evaluate(true, List.of());
        assertEquals(Verdict.INCONCLUSIVE, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("null interaction list is treated the same as empty")
    void nullInteractionListIsInconclusive() {
        Evidence e = evaluate(true, null);
        assertEquals(Verdict.INCONCLUSIVE, e.verdict());
    }
}
