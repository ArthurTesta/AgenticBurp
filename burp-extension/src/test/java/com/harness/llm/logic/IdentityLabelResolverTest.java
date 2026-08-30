package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.harness.llm.logic.IdentityLabelResolver.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for IdentityLabelResolver -- the logic that lets
 * ValidationExecutor.identityCompare()'s picker show a registered
 * identity's name instead of a bare fingerprint, when one is known,
 * while falling back exactly to the prior unlabeled format otherwise.
 */
public final class IdentityLabelResolverTest {

    @Test
    @DisplayName("candidate with no registered session gets the plain fallback label")
    void noSessionFallsBackToPlainLabel() {
        String label = labelFor("GET", "https://example.com/api/orders/5", "a1b2c3d4",
                "fullfingerprintvalue", Map.of());
        assertEquals("GET https://example.com/api/orders/5 [a1b2c3d4]", label);
    }

    @Test
    @DisplayName("candidate with null sessions map (no harness reachable) also falls back safely")
    void nullSessionsMapFallsBackSafely() {
        String label = labelFor("GET", "https://example.com/x", "aaaa1111", "fp1", null);
        assertEquals("GET https://example.com/x [aaaa1111]", label);
    }

    @Test
    @DisplayName("candidate WITH a registered session shows the identity name and role")
    void matchedSessionShowsIdentityLabel() {
        Map<String, String> sessions = Map.of("fullfingerprintvalue", "Alice (admin)");
        String label = labelFor("GET", "https://example.com/api/orders/5", "a1b2c3d4",
                "fullfingerprintvalue", sessions);
        assertEquals("Alice (admin) -- GET https://example.com/api/orders/5 [a1b2c3d4]", label);
    }

    @Test
    @DisplayName("a session for a DIFFERENT fingerprint does not leak onto an unrelated candidate")
    void unrelatedSessionDoesNotApply() {
        Map<String, String> sessions = Map.of("some-other-fingerprint", "Bob (user)");
        String label = labelFor("GET", "https://example.com/x", "aaaa1111", "fp-not-in-map", sessions);
        assertEquals("GET https://example.com/x [aaaa1111]", label);
    }

    @Test
    @DisplayName("buildLookup formats name and role together")
    void buildLookupFormatsNameAndRole() {
        Map<String, String> lookup = buildLookup(List.of(
                new SessionEntry("fp1", "Alice", "admin"),
                new SessionEntry("fp2", "Bob", "user")
        ));
        assertEquals("Alice (admin)", lookup.get("fp1"));
        assertEquals("Bob (user)", lookup.get("fp2"));
    }

    @Test
    @DisplayName("buildLookup handles a missing/blank role without a dangling empty parenthesis")
    void buildLookupHandlesMissingRole() {
        Map<String, String> lookup = buildLookup(List.of(new SessionEntry("fp1", "Alice", "")));
        assertEquals("Alice", lookup.get("fp1"));
    }

    @Test
    @DisplayName("buildLookup falls back to a placeholder name rather than a blank label")
    void buildLookupHandlesMissingName() {
        Map<String, String> lookup = buildLookup(List.of(new SessionEntry("fp1", "", "admin")));
        assertEquals("(unnamed identity) (admin)", lookup.get("fp1"));
    }

    @Test
    @DisplayName("buildLookup skips entries with no exchange hash rather than crashing")
    void buildLookupSkipsEntriesWithoutFingerprint() {
        Map<String, String> lookup = buildLookup(List.of(
                new SessionEntry(null, "Alice", "admin"),
                new SessionEntry("", "Bob", "user"),
                new SessionEntry("fp3", "Carol", "user")
        ));
        assertEquals(1, lookup.size());
        assertEquals("Carol (user)", lookup.get("fp3"));
    }

    @Test
    @DisplayName("buildLookup with a null list returns an empty (not null) map")
    void buildLookupHandlesNullList() {
        Map<String, String> lookup = buildLookup(null);
        assertNotNull(lookup);
        assertTrue(lookup.isEmpty());
    }

    @Test
    @DisplayName("a corrective re-registration (same fingerprint, later entry) wins over the original")
    void laterEntryForSameFingerprintWins() {
        Map<String, String> lookup = buildLookup(List.of(
                new SessionEntry("fp1", "WrongIdentity", "user"),
                new SessionEntry("fp1", "CorrectIdentity", "admin")
        ));
        assertEquals("CorrectIdentity (admin)", lookup.get("fp1"));
    }

    @Test
    @DisplayName("end-to-end: buildLookup output plugs directly into labelFor")
    void buildLookupAndLabelForComposeCorrectly() {
        Map<String, String> lookup = buildLookup(List.of(new SessionEntry("thefingerprint", "Alice", "admin")));
        String label = labelFor("POST", "https://example.com/api/x", "thefi12", "thefingerprint", lookup);
        assertEquals("Alice (admin) -- POST https://example.com/api/x [thefi12]", label);
    }
}
