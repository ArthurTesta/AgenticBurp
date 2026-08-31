package com.harness.llm.logic;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Extracted from ValidationExecutor.exchangeFingerprint() so it can be
 * called from other Montoya-free classes in this package (e.g.
 * IdentityCandidateResolver) without pulling in the rest of
 * ValidationExecutor -- that class needs HarnessClient (which pulls in
 * Gson) to compile at all, which breaks the headless javac/RunTests
 * compilation this package's tests otherwise don't need (see
 * dev-tools/README.md). ValidationExecutor.exchangeFingerprint() now
 * delegates here; every one of its existing call sites is unchanged.
 *
 * Must match harness/planner.py's exchange_fingerprint() byte-for-byte --
 * see that function's own comment, and ValidationExecutor's original
 * comment on header-merge/sort-before-lowercase order, both preserved
 * here unchanged.
 */
public final class ExchangeFingerprint {

    private static final char UNIT_SEPARATOR = 0x1f;

    private ExchangeFingerprint() {}

    public static String compute(HttpRequestResponse rr) {
        try {
            var req = rr.request();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            StringBuilder m = new StringBuilder();
            m.append(req.method().toUpperCase()).append(UNIT_SEPARATOR).append(req.url()).append(UNIT_SEPARATOR);
            Map<String, String> merged = new LinkedHashMap<>();
            for (HttpHeader h : req.headers()) {
                merged.merge(h.name(), h.value(), (oldValue, newValue) -> oldValue + "\n" + newValue);
            }
            // Sort by the ORIGINAL-case key first, matching Python's
            // sorted(dict.items()) exactly -- then lowercase only for the
            // output string. Lowercasing before sorting would give a
            // different order whenever two header names' relative order
            // depends on case (e.g. "Content-Type" sorts before "accept"
            // by original case, but after it if both are lowercased
            // first) -- a real, if narrow, way these two sides could
            // still silently disagree even with merging fixed.
            merged.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(h -> m.append(h.getKey().toLowerCase(Locale.ROOT)).append(':').append(h.getValue()).append(UNIT_SEPARATOR));
            m.append(req.bodyToString());
            return HexFormat.of().formatHex(md.digest(m.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "";
        }
    }
}
