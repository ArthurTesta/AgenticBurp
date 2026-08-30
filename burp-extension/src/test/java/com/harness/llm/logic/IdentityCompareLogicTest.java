package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static com.harness.llm.logic.IdentityCompareLogic.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Real JUnit 5 tests, discoverable by `gradle test`.
 *
 * History: this file started as a plain-Java main()-method runner because
 * the sandbox these tests were originally written in had no Maven Central
 * access and couldn't pull JUnit. Once these were used in an environment
 * with real dependency resolution, Gradle's default `test` task correctly
 * reported "test sources present... did not discover any tests" -- there
 * were no @Test-annotated methods for it to find. Converted to standard
 * JUnit 5 Jupiter so `gradle test` actually runs these. Every assertion
 * and comment below is unchanged from the original; only the harness
 * (main()/run()/check() -> @Test/assertTrue/assertEquals) changed.
 */
public final class IdentityCompareLogicTest {

    @Test
    @DisplayName("public resource is not confirmed even though bodies match")
    void publicResourceIsNotConfirmed() {
        Probe source = new Probe(200, "<html>home page A</html>");
        Probe candidate = new Probe(200, "<html>home page B</html>");
        Probe attempt = new Probe(200, "<html>home page B</html>");
        Probe anon = new Probe(200, "<html>home page B</html>"); // anon sees the same thing -> public
        Evidence ev = evaluate("cross_identity_compare", true, source, candidate, attempt, anon);
        assertTrue(ev.verdict == Verdict.INCONCLUSIVE, "expected INCONCLUSIVE, got " + ev.verdict);
        assertFalse(ev.confirmed, "a public resource must never be confirmed");
    }

    @Test
    @DisplayName("genuine cross-identity access is confirmed")
    void genuineAccessIsConfirmed() {
        Probe source = new Probe(200, "{\"basket\":1,\"items\":[\"identity A's own item\"]}");
        Probe candidate = new Probe(200, "{\"basket\":4,\"items\":[\"identity B's private item\"]}");
        Probe attempt = new Probe(200, "{\"basket\":4,\"items\":[\"identity B's private item\"]}"); // A's session got B's data
        Probe anon = new Probe(401, "{\"error\":\"authentication required\"}");
        Evidence ev = evaluate("cross_identity_compare", true, source, candidate, attempt, anon);
        assertTrue(ev.verdict == Verdict.CONFIRMED, "expected CONFIRMED, got " + ev.verdict + " (" + ev.summary + ")");
        assertTrue(ev.confirmed, "confirmed flag must be true");
        assertTrue(ev.confidence > 0.85, "confidence should be high for a clean confirm, got " + ev.confidence);
    }

    @Test
    @DisplayName("correctly-denied attempt is rejected, not confirmed")
    void deniedAttemptIsRejected() {
        Probe source = new Probe(200, "{\"basket\":1,\"items\":[\"identity A's own item\"]}");
        Probe candidate = new Probe(200, "{\"basket\":4,\"items\":[\"identity B's private item\"]}");
        Probe attempt = new Probe(403, "{\"error\":\"forbidden\"}"); // access control worked correctly
        Probe anon = new Probe(403, "{\"error\":\"forbidden\"}");
        Evidence ev = evaluate("cross_identity_compare", true, source, candidate, attempt, anon);
        assertTrue(ev.verdict == Verdict.REJECTED, "expected REJECTED, got " + ev.verdict);
        assertFalse(ev.confirmed, "a correctly-denied attempt must not be confirmed");
    }

    @Test
    @DisplayName("missing anon baseline caps verdict at SUPPORTED, never CONFIRMED")
    void missingAnonBaselineCannotConfirm() {
        Probe source = new Probe(200, "{\"basket\":1,\"items\":[\"A's item\"]}");
        Probe candidate = new Probe(200, "{\"basket\":4,\"items\":[\"B's item\"]}");
        Probe attempt = new Probe(200, "{\"basket\":4,\"items\":[\"B's item\"]}");
        Evidence ev = evaluate("cross_identity_compare", true, source, candidate, attempt, null);
        assertTrue(ev.verdict != Verdict.CONFIRMED, "without an anon baseline this must never reach CONFIRMED, got " + ev.verdict);
        assertFalse(ev.confirmed, "confirmed must be false without an anon baseline");
        assertTrue(ev.verdict == Verdict.SUPPORTED, "expected SUPPORTED as the capped tier, got " + ev.verdict);
    }

    @Test
    @DisplayName("IDOR capability refuses to run when identifier did not change")
    void idorRequiresIdentifierChange() {
        Probe source = new Probe(200, "same");
        Probe candidate = new Probe(200, "same");
        Probe attempt = new Probe(200, "same");
        Probe anon = new Probe(403, "denied");
        Evidence ev = evaluate("cross_identity_compare", false, source, candidate, attempt, anon);
        assertTrue(ev.verdict == Verdict.INVALID, "IDOR without a changed identifier must be INVALID, got " + ev.verdict);
    }

    @Test
    @DisplayName("authorization_boundary_compare does not require identifierChanged")
    void boundaryCompareIgnoresIdentifierFlag() {
        Probe source = new Probe(200, "regular user's own view");
        Probe candidate = new Probe(200, "admin-only panel contents");
        Probe attempt = new Probe(200, "admin-only panel contents"); // same URL replayed with A's session
        Probe anon = new Probe(302, "redirect to login");
        Evidence ev = evaluate("authorization_boundary_compare", false, source, candidate, attempt, anon);
        assertTrue(ev.verdict == Verdict.CONFIRMED, "boundary compare should not require identifierChanged, got " + ev.verdict);
    }

    @Test
    @DisplayName("status code mismatch overrides coincidental body similarity")
    void statusMismatchPreventsConfirmation() {
        // Bodies coincidentally match (e.g. both near-empty), but status differs.
        Probe source = new Probe(200, "");
        Probe candidate = new Probe(200, "");
        Probe attempt = new Probe(500, ""); // server error, not real access
        Probe anon = new Probe(403, "denied");
        Evidence ev = evaluate("cross_identity_compare", true, source, candidate, attempt, anon);
        assertTrue(ev.verdict != Verdict.CONFIRMED, "differing status codes must prevent confirmation even with matching bodies");
    }

    @Test
    @DisplayName("trigram similarity: identical strings score 1.0")
    void similarityIdentical() {
        assertTrue(IdentityCompareLogic.similarity("abcdef", "abcdef") == 1.0, "identical strings must score 1.0");
    }

    @Test
    @DisplayName("trigram similarity: disjoint strings score 0.0")
    void similarityDisjoint() {
        double s = IdentityCompareLogic.similarity("aaaaaa", "zzzzzz");
        assertTrue(s == 0.0, "completely disjoint trigram sets must score 0.0, got " + s);
    }

    @Test
    @DisplayName("trigram similarity: near-identical strings score high")
    void similarityNearIdentical() {
        String a = "{\"user\":\"alice\",\"csrf\":\"AAAAAAAAAA\",\"balance\":100}";
        String b = "{\"user\":\"alice\",\"csrf\":\"BBBBBBBBBB\",\"balance\":100}";
        double s = IdentityCompareLogic.similarity(a, b);
        assertTrue(s >= MATCH_THRESHOLD, "a single differing token (csrf) should still score above threshold, got " + s);
    }

    @Test
    @DisplayName("trigram similarity: same-shape but different content scores low")
    void similarityDifferentContentSameShape() {
        // Two genuinely different resources that happen to share JSON
        // boilerplate must NOT score above threshold -- this is the
        // false-positive direction, checked alongside the false-negative
        // one above rather than assuming a lower threshold is free.
        String a = "{\"user\":\"alice\",\"csrf\":\"AAAAAAAAAA\",\"balance\":100}";
        String b = "{\"user\":\"carol\",\"csrf\":\"CCCCCCCCCC\",\"balance\":250}";
        double s = IdentityCompareLogic.similarity(a, b);
        assertTrue(s < MATCH_THRESHOLD, "genuinely different content must score below threshold, got " + s);
    }

    @Test
    @DisplayName("trigram similarity: realistic-length body survives one volatile token")
    void similarityRealisticLengthToken() {
        String big1 = "{\"basketId\":4,\"userId\":9,\"csrfToken\":\"AAAAAAAAAAAAAAAAAAAA\",\"items\":"
                + "[{\"id\":1,\"name\":\"Widget\",\"price\":19.99,\"qty\":2},{\"id\":2,\"name\":\"Gadget\","
                + "\"price\":9.99,\"qty\":1}],\"total\":49.97}";
        String big2 = big1.replace("AAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBB");
        double s = IdentityCompareLogic.similarity(big1, big2);
        assertTrue(s >= MATCH_THRESHOLD, "a realistic body with one differing token should score above threshold, got " + s);
    }

    @Test
    @DisplayName("url diff: single differing path segment is found")
    void urlDiffSinglePathSegment() {
        Optional<UrlIdentifierDiff.Diff> d = UrlIdentifierDiff.singleDifferingIdentifier(
                "https://shop.example/api/basket/1", "https://shop.example/api/basket/4");
        assertTrue(d.isPresent(), "expected a diff to be found");
        assertTrue(d.get().isPathDiff(), "expected a path diff");
        assertTrue(d.get().valueA.equals("1") && d.get().valueB.equals("4"), "expected values 1 and 4, got " + d.get().valueA + "/" + d.get().valueB);
    }

    @Test
    @DisplayName("url diff: single differing query value is found")
    void urlDiffSingleQueryValue() {
        Optional<UrlIdentifierDiff.Diff> d = UrlIdentifierDiff.singleDifferingIdentifier(
                "https://shop.example/api/order?order_id=100&fmt=json",
                "https://shop.example/api/order?order_id=104&fmt=json");
        assertTrue(d.isPresent(), "expected a diff to be found");
        assertTrue(!d.get().isPathDiff() && "order_id".equals(d.get().queryKey), "expected query diff on order_id");
    }

    @Test
    @DisplayName("url diff: refuses to guess when two tokens differ")
    void urlDiffRefusesMultipleDiffs() {
        Optional<UrlIdentifierDiff.Diff> d = UrlIdentifierDiff.singleDifferingIdentifier(
                "https://shop.example/api/basket/1/item/5", "https://shop.example/api/basket/4/item/9");
        assertTrue(d.isEmpty(), "two differing segments must not be auto-resolved, got " + d);
    }

    @Test
    @DisplayName("url diff: refuses when path shapes differ")
    void urlDiffRefusesDifferentShape() {
        Optional<UrlIdentifierDiff.Diff> d = UrlIdentifierDiff.singleDifferingIdentifier(
                "https://shop.example/api/basket/1", "https://shop.example/api/basket/4/extra");
        assertTrue(d.isEmpty(), "different path shapes must not be auto-resolved, got " + d);
    }
}
