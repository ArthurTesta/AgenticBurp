package com.harness.llm.surface;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real JUnit 5 tests, discoverable by `gradle test`.
 *
 * History: originally a plain-Java main()-method runner (no JUnit --
 * written in a sandbox with no Maven Central access). Converted once used
 * somewhere with real dependency resolution and Gradle's default `test`
 * task correctly reported zero discoverable tests. Every assertion and
 * comment is unchanged; only the harness changed.
 *
 * This file exists specifically because PathScorer.java originally failed
 * to compile with "illegal escape character" -- every rule ending in
 * "(/|\.|$)" had a single backslash in Java source, which is not a legal
 * Java string escape (Java requires "\\." to produce the one-character
 * regex escape "\."). That bug was caught by an actual javac invocation
 * during a real build attempt, not by review. This file exists so the
 * next regression -- including a *silent* one, where someone "fixes" the
 * escape but drops a backslash and turns a literal-dot match into an
 * any-character wildcard match -- gets caught the same way, automatically.
 */
public final class PathScorerTest {

    private final PathScorer scorer = new PathScorer();

    @Test
    @DisplayName("actuator endpoint is flagged misconfig")
    void actuatorIsFlaggedMisconfig() {
        var r = scorer.score("GET", "/actuator/health", List.of());
        assertTrue(r.score() > 0, "expected nonzero score, got " + r.score());
        assertEquals("misconfig", r.category());
    }

    @Test
    @DisplayName("exposed .git is flagged misconfig")
    void gitExposureIsFlaggedMisconfig() {
        var r = scorer.score("GET", "/.git/config", List.of());
        assertTrue(r.score() > 0, "expected nonzero score");
        assertEquals("misconfig", r.category());
    }

    // Found missing entirely during live testing against OWASP Juice
    // Shop: /ftp serves a real directory listing and had no matching
    // rule at all until this was added.
    @Test
    @DisplayName("ftp directory listing is flagged misconfig")
    void ftpListingIsFlaggedMisconfig() {
        var r = scorer.score("GET", "/ftp", List.of());
        assertTrue(r.score() > 0, "expected nonzero score, got " + r.score());
        assertEquals("misconfig", r.category());
    }

    @Test
    @DisplayName("numeric object id is flagged access_control")
    void numericObjectIdIsFlaggedAccessControl() {
        var r = scorer.score("GET", "/users/42", List.of());
        assertEquals("access_control", r.category());
    }

    @Test
    @DisplayName("admin path is flagged access_control")
    void adminPathIsFlaggedAccessControl() {
        var r = scorer.score("GET", "/admin/panel", List.of());
        assertEquals("access_control", r.category());
    }

    @Test
    @DisplayName("checkout is flagged business_logic")
    void checkoutIsFlaggedBusinessLogic() {
        var r = scorer.score("POST", "/checkout/confirm", List.of());
        assertEquals("business_logic", r.category());
    }

    @Test
    @DisplayName("chat endpoint is flagged ai_llm")
    void chatEndpointIsFlaggedAiLlm() {
        var r = scorer.score("POST", "/api/chat/completion", List.of());
        assertEquals("ai_llm", r.category());
    }

    @Test
    @DisplayName("benign listing path is not flagged")
    void benignListingPathIsNotFlagged() {
        var r = scorer.score("GET", "/products/list", List.of());
        assertTrue(r.score() == 0.0, "expected zero score for a benign path, got " + r.score());
    }

    @Test
    @DisplayName("profileImage param name is flagged ssrf -- the real Juice Shop ground truth found while "
            + "building controlled_callback_probe, which the original url|redirect|next|return_to|callback "
            + "list (exact-match only) silently missed")
    void profileImageParamIsFlaggedSsrf() {
        var r = scorer.score("PUT", "/rest/user/profile", List.of("profileImage"));
        assertEquals("ssrf", r.category(), "expected ssrf category, got " + r.category() + " (score=" + r.score() + ")");
        assertTrue(r.score() > 0, "expected nonzero score");
    }

    // The specific failure mode a hasty escape-fix could reintroduce: if
    // "\\." were accidentally left as an unescaped "." in the Java
    // source, the regex would match ANY character in that position, not
    // just a literal dot -- so "/adminX" would score identically to
    // "/admin.". This pins the literal-dot semantics down.
    @Test
    @DisplayName("literal-dot boundary matches a real dot")
    void literalDotBoundaryMatchesRealDot() {
        var r = scorer.score("GET", "/admin.", List.of());
        assertEquals("access_control", r.category());
    }

    @Test
    @DisplayName("literal-dot boundary does not match an arbitrary character")
    void literalDotBoundaryDoesNotMatchArbitraryCharacter() {
        var r = scorer.score("GET", "/adminX", List.of());
        assertTrue(r.score() == 0.0,
                "a wildcard-dot regression would make this match like '/admin.' does; got score=" + r.score());
    }
}
