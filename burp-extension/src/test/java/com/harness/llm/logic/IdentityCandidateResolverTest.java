package com.harness.llm.logic;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests for the candidate-selection seam extracted out of
 * ValidationExecutor.identityCompare() -- see that class's doc comment.
 * No Montoya runtime, no live Burp needed.
 *
 * Fakes are built with java.lang.reflect.Proxy rather than hand-written
 * classes implementing HttpRequest/HttpRequestResponse directly. Found
 * live, building this for real against the actual Montoya API (not just
 * dev-tools/stubs' deliberately simplified version): the real HttpRequest
 * interface has ~65 abstract methods, HttpRequestResponse has ~15 -- a
 * hand-written Fake implementing only the handful IdentityCandidateResolver
 * actually calls (url/method/headers/bodyToString/request/response) fails
 * to compile against the real jar ("is not abstract and does not override
 * abstract method ..."), and would need updating every time Montoya adds
 * another method regardless. A dynamic proxy satisfies the FULL interface
 * automatically (any unhandled method throws UnsupportedOperationException,
 * same intent as before) and needs zero changes if Montoya's API grows --
 * verified to work identically whether compiled against the real Montoya
 * API jar or dev-tools/stubs' simplified one, since Proxy only needs the
 * interface Class object, not a fixed method list.
 */
public final class IdentityCandidateResolverTest {

    @SuppressWarnings("unchecked")
    private static <T> T proxyFor(Class<T> iface, Map<String, Object> answers) {
        return (T) Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[]{iface}, (proxy, method, args) -> {
            switch (method.getName()) {
                case "equals": return proxy == args[0];
                case "hashCode": return System.identityHashCode(proxy);
                case "toString": return iface.getSimpleName() + "@" + System.identityHashCode(proxy);
                default:
                    if (answers.containsKey(method.getName())) return answers.get(method.getName());
                    throw new UnsupportedOperationException(method.getName());
            }
        });
    }

    private static HttpHeader fakeHeader(String name, String value) {
        return proxyFor(HttpHeader.class, Map.of("name", name, "value", value));
    }

    private static HttpRequest fakeRequest(String method, String url, List<HttpHeader> headers) {
        return proxyFor(HttpRequest.class, Map.of(
                "method", method, "url", url, "headers", headers, "bodyToString", ""));
    }

    private static HttpRequestResponse rr(String method, String url) {
        HttpRequest req = fakeRequest(method, url, List.of());
        return proxyFor(HttpRequestResponse.class, Map.of("request", req));
    }

    /** Same as rr(), but with a distinguishing header -- e.g. a different
     * identity's session cookie -- so its fingerprint differs from a
     * same-URL, no-header source (real captured traffic from two distinct
     * identities always differs at least by Cookie/Authorization; a bare
     * same-URL fixture with identical empty headers would otherwise
     * fingerprint-collide with the source and be wrongly excluded as
     * "the same request", masking the real pool-scan behavior). */
    private static HttpRequestResponse rrWithCookie(String method, String url, String cookieValue) {
        HttpRequest req = fakeRequest(method, url, List.of(fakeHeader("Cookie", cookieValue)));
        return proxyFor(HttpRequestResponse.class, Map.of("request", req));
    }

    @Test
    @DisplayName("explicit candidate + IDOR with a single differing identifier resolves with a diff")
    void explicitCandidate_idor_singleIdentifierDiff_resolvesWithDiff() {
        HttpRequestResponse source = rr("GET", "https://shop.example/api/basket/1");
        HttpRequestResponse explicit = rr("GET", "https://shop.example/api/basket/4");
        var res = IdentityCandidateResolver.resolve(source, Map.of(), true, explicit);
        assertEquals(IdentityCandidateResolver.Outcome.RESOLVED, res.outcome);
        assertTrue(explicit == res.candidate, "expected the exact explicit candidate object back");
        assertNotNull(res.diff);
        assertEquals("1", res.diff.valueA);
        assertEquals("4", res.diff.valueB);
    }

    @Test
    @DisplayName("explicit candidate + IDOR with no identifier diff resolves with a null diff (feeds INVALID downstream)")
    void explicitCandidate_idor_noDiff_resolvesWithNullDiff() {
        HttpRequestResponse source = rr("GET", "https://shop.example/api/basket/1");
        HttpRequestResponse explicit = rr("GET", "https://shop.example/api/basket/1/extra");
        var res = IdentityCandidateResolver.resolve(source, Map.of(), true, explicit);
        assertEquals(IdentityCandidateResolver.Outcome.RESOLVED, res.outcome);
        assertTrue(explicit == res.candidate, "expected the exact explicit candidate object back");
        assertNull(res.diff);
    }

    @Test
    @DisplayName("explicit candidate + authorization_boundary_compare never computes a diff")
    void explicitCandidate_authorizationBoundary_diffAlwaysNull() {
        HttpRequestResponse source = rr("GET", "https://shop.example/admin/panel");
        HttpRequestResponse explicit = rr("GET", "https://shop.example/admin/panel");
        var res = IdentityCandidateResolver.resolve(source, Map.of(), false, explicit);
        assertEquals(IdentityCandidateResolver.Outcome.RESOLVED, res.outcome);
        assertNull(res.diff);
    }

    @Test
    @DisplayName("no explicit candidate, empty pool -> NO_CANDIDATES")
    void noExplicitCandidate_emptyPool_returnsNoCandidates() {
        HttpRequestResponse source = rr("GET", "https://shop.example/api/basket/1");
        var res = IdentityCandidateResolver.resolve(source, Map.of(), true, null);
        assertEquals(IdentityCandidateResolver.Outcome.NO_CANDIDATES, res.outcome);
    }

    @Test
    @DisplayName("no explicit candidate, IDOR: pool scan finds identifier-diffing candidates")
    void noExplicitCandidate_idor_findsSingleIdentifierDiffCandidatesInPool() {
        HttpRequestResponse source = rr("GET", "https://shop.example/api/basket/1");
        HttpRequestResponse match = rr("GET", "https://shop.example/api/basket/4");
        Map<String, HttpRequestResponse> pool = new LinkedHashMap<>();
        pool.put("k1", match);
        var res = IdentityCandidateResolver.resolve(source, pool, true, null);
        assertEquals(IdentityCandidateResolver.Outcome.NEEDS_PICKER, res.outcome);
        assertEquals(1, res.pickerCandidates.size());
        assertTrue(match == res.pickerCandidates.get(0), "expected the exact matching pool object back");
        assertNotNull(res.pickerDiffs.get(0));
    }

    @Test
    @DisplayName("no explicit candidate, IDOR: entries without a single identifier diff are excluded")
    void noExplicitCandidate_idor_excludesEntriesWithoutASingleDiff() {
        HttpRequestResponse source = rr("GET", "https://shop.example/api/basket/1/item/5");
        HttpRequestResponse nonMatch = rr("GET", "https://shop.example/api/basket/4/item/9"); // two diffs
        Map<String, HttpRequestResponse> pool = new LinkedHashMap<>();
        pool.put("k1", nonMatch);
        var res = IdentityCandidateResolver.resolve(source, pool, true, null);
        assertEquals(IdentityCandidateResolver.Outcome.NO_CANDIDATES, res.outcome);
    }

    @Test
    @DisplayName("no explicit candidate, authorization_boundary_compare: pool scan finds same-URL candidates")
    void noExplicitCandidate_authorizationBoundary_findsSameUrlCandidatesInPool() {
        HttpRequestResponse source = rr("GET", "https://shop.example/admin/panel");
        // A different identity's session on the same URL -- a distinct
        // Cookie is what makes this genuinely a different captured
        // exchange rather than a fingerprint-identical duplicate of source.
        HttpRequestResponse match = rrWithCookie("GET", "https://shop.example/admin/panel", "session=identityB");
        HttpRequestResponse nonMatch = rr("GET", "https://shop.example/other/page");
        Map<String, HttpRequestResponse> pool = new LinkedHashMap<>();
        pool.put("k1", match);
        pool.put("k2", nonMatch);
        var res = IdentityCandidateResolver.resolve(source, pool, false, null);
        assertEquals(IdentityCandidateResolver.Outcome.NEEDS_PICKER, res.outcome);
        assertEquals(1, res.pickerCandidates.size());
        assertTrue(match == res.pickerCandidates.get(0), "expected the exact matching pool object back");
    }

    @Test
    @DisplayName("no explicit candidate: the source's own fingerprint is excluded from the pool scan")
    void noExplicitCandidate_excludesSourceItselfByFingerprint() {
        HttpRequestResponse source = rr("GET", "https://shop.example/admin/panel");
        // A different object with the SAME method/url/headers/body has the
        // same fingerprint as source, and must still be excluded.
        HttpRequestResponse sameFingerprintAsSource = rr("GET", "https://shop.example/admin/panel");
        Map<String, HttpRequestResponse> pool = new LinkedHashMap<>();
        pool.put("k1", sameFingerprintAsSource);
        var res = IdentityCandidateResolver.resolve(source, pool, false, null);
        assertEquals(IdentityCandidateResolver.Outcome.NO_CANDIDATES, res.outcome);
    }
}
