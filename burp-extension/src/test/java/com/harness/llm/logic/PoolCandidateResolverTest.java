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
 * Headless tests for the candidate-selection seam shared by
 * sessionFixationCompare and logoutInvalidationCompare -- see
 * PoolCandidateResolver's doc comment. Fakes built with
 * java.lang.reflect.Proxy for the same reason as
 * IdentityCandidateResolverTest: the real HttpRequest/HttpRequestResponse
 * interfaces are far larger than a hand-written class could practically
 * implement, and Proxy satisfies either the real Montoya API or
 * dev-tools/stubs' simplified version identically.
 */
public final class PoolCandidateResolverTest {

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

    private static HttpRequestResponse rr(String method, String url, List<HttpHeader> headers) {
        HttpRequest req = proxyFor(HttpRequest.class, Map.of(
                "method", method, "url", url, "headers", headers, "bodyToString", ""));
        return proxyFor(HttpRequestResponse.class, Map.of("request", req));
    }

    private static HttpRequestResponse rr(String method, String url) {
        return rr(method, url, List.of());
    }

    @Test
    @DisplayName("explicit candidate resolves immediately, filter never consulted")
    void explicitCandidate_resolvesWithoutFiltering() {
        HttpRequestResponse source = rr("GET", "https://shop.example/a");
        HttpRequestResponse explicit = rr("GET", "https://shop.example/b");
        var res = PoolCandidateResolver.resolve(source, Map.of(), rr -> {
            throw new AssertionError("filter must not be consulted when an explicit candidate is supplied");
        }, explicit);
        assertEquals(PoolCandidateResolver.Outcome.RESOLVED, res.outcome);
        assertTrue(explicit == res.candidate);
    }

    @Test
    @DisplayName("no explicit candidate, empty pool -> NO_CANDIDATES")
    void noExplicitCandidate_emptyPool_returnsNoCandidates() {
        HttpRequestResponse source = rr("GET", "https://shop.example/a");
        var res = PoolCandidateResolver.resolve(source, Map.of(), rr -> true, null);
        assertEquals(PoolCandidateResolver.Outcome.NO_CANDIDATES, res.outcome);
    }

    @Test
    @DisplayName("no explicit candidate: filter excludes non-matching pool entries")
    void noExplicitCandidate_filterExcludesNonMatching() {
        HttpRequestResponse source = rr("GET", "https://shop.example/a");
        HttpRequestResponse noCookie = rr("GET", "https://shop.example/b", List.of());
        HttpRequestResponse withCookie = rr("GET", "https://shop.example/c",
                List.of(proxyFor(HttpHeader.class, Map.of("name", "Set-Cookie", "value", "session=x"))));
        Map<String, HttpRequestResponse> pool = new LinkedHashMap<>();
        pool.put("k1", noCookie);
        pool.put("k2", withCookie);
        var res = PoolCandidateResolver.resolve(source, pool,
                rr -> rr.request().headers().stream().anyMatch(h -> h.name().equalsIgnoreCase("Set-Cookie")),
                null);
        assertEquals(PoolCandidateResolver.Outcome.NEEDS_PICKER, res.outcome);
        assertEquals(1, res.pickerCandidates.size());
        assertTrue(withCookie == res.pickerCandidates.get(0));
    }

    @Test
    @DisplayName("no explicit candidate: the source's own fingerprint is excluded from the pool scan")
    void noExplicitCandidate_excludesSourceItselfByFingerprint() {
        HttpRequestResponse source = rr("GET", "https://shop.example/a");
        // Same method/url/headers/body as source -> same fingerprint, must be excluded.
        HttpRequestResponse sameFingerprintAsSource = rr("GET", "https://shop.example/a");
        Map<String, HttpRequestResponse> pool = new LinkedHashMap<>();
        pool.put("k1", sameFingerprintAsSource);
        var res = PoolCandidateResolver.resolve(source, pool, rr -> true, null);
        assertEquals(PoolCandidateResolver.Outcome.NO_CANDIDATES, res.outcome);
    }

    @Test
    @DisplayName("no explicit candidate, accept-anything filter: all non-source pool entries are candidates")
    void noExplicitCandidate_acceptAnythingFilter_returnsAllOthers() {
        HttpRequestResponse source = rr("GET", "https://shop.example/a");
        HttpRequestResponse other1 = rr("GET", "https://shop.example/b");
        HttpRequestResponse other2 = rr("POST", "https://shop.example/c");
        Map<String, HttpRequestResponse> pool = new LinkedHashMap<>();
        pool.put("k1", other1);
        pool.put("k2", other2);
        var res = PoolCandidateResolver.resolve(source, pool, rr -> true, null);
        assertEquals(PoolCandidateResolver.Outcome.NEEDS_PICKER, res.outcome);
        assertEquals(2, res.pickerCandidates.size());
    }
}
