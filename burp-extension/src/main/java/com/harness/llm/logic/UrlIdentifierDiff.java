package com.harness.llm.logic;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Locates the single differing object identifier between two URLs that are
 * otherwise structurally identical -- e.g. {@code /basket/1} vs
 * {@code /basket/4}, or {@code ?order_id=100} vs {@code ?order_id=104}.
 *
 * This intentionally refuses to guess when more than one token differs,
 * or when the two URLs aren't the same shape (different host, different
 * path length, different query keys): a confident single-identifier swap
 * is the only case worth automating, and anything else risks silently
 * mutating the wrong thing.
 */
public final class UrlIdentifierDiff {

    private UrlIdentifierDiff() {}

    public static final class Diff {
        /** Index into the path segment list, or -1 if the diff is in the query string. */
        public final int pathSegmentIndex;
        /** Query key that differs, or null if the diff is a path segment. */
        public final String queryKey;
        public final String valueA;
        public final String valueB;

        Diff(int pathSegmentIndex, String queryKey, String valueA, String valueB) {
            this.pathSegmentIndex = pathSegmentIndex;
            this.queryKey = queryKey;
            this.valueA = valueA;
            this.valueB = valueB;
        }

        public boolean isPathDiff() { return queryKey == null; }
    }

    public static Optional<Diff> singleDifferingIdentifier(String urlA, String urlB) {
        try {
            URI a = URI.create(urlA);
            URI b = URI.create(urlB);
            if (!Objects.equals(a.getHost(), b.getHost())) return Optional.empty();
            if (!Objects.equals(a.getScheme(), b.getScheme())) return Optional.empty();

            List<String> pa = segments(a.getRawPath());
            List<String> pb = segments(b.getRawPath());
            if (pa.size() != pb.size()) return Optional.empty();

            Map<String, String> qa = query(a.getRawQuery());
            Map<String, String> qb = query(b.getRawQuery());
            if (!qa.keySet().equals(qb.keySet())) return Optional.empty();

            int diffCount = 0;
            int diffPathIdx = -1;
            String diffQueryKey = null;
            String va = null, vb = null;

            for (int i = 0; i < pa.size(); i++) {
                if (!pa.get(i).equals(pb.get(i))) {
                    diffCount++;
                    diffPathIdx = i;
                    va = pa.get(i);
                    vb = pb.get(i);
                }
            }
            for (String k : qa.keySet()) {
                String x = qa.get(k), y = qb.get(k);
                if (!Objects.equals(x, y)) {
                    diffCount++;
                    diffQueryKey = k;
                    va = x;
                    vb = y;
                }
            }

            if (diffCount != 1) return Optional.empty();
            return Optional.of(new Diff(diffQueryKey == null ? diffPathIdx : -1, diffQueryKey, va, vb));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static List<String> segments(String path) {
        List<String> out = new ArrayList<>();
        if (path == null) return out;
        for (String s : path.split("/")) if (!s.isEmpty()) out.add(s);
        return out;
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String kv : raw.split("&")) {
            int i = kv.indexOf('=');
            if (i < 0) out.put(kv, "");
            else out.put(kv.substring(0, i), kv.substring(i + 1));
        }
        return out;
    }
}
