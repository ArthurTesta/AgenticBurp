package com.harness.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;

/**
 * Pushes endpoints the harness discovered (via /crawl or /crawl-roles) into
 * Burp's own Target site map, so they show up in the native Target tab alongside
 * everything Burp saw itself -- not just in the harness panel.
 *
 * Adds each endpoint as an UNREQUESTED site-map entry (a request built from the
 * URL plus an empty response) via {@code api.siteMap().add(...)}. This
 * deliberately does NOT issue the request: the harness already crawled/probed
 * the surface server-side, so re-sending from Burp would only duplicate that
 * traffic. The entry still appears in Target and can then be selected, sent to
 * Repeater, or right-clicked into "Send to LLM Harness" like any other.
 */
public final class SiteMapImporter {

    private SiteMapImporter() {}

    /**
     * Adds every path in {@code paths} (resolved against {@code baseUrl}'s
     * origin) to the site map. Normalized {@code {id}} placeholders are filled
     * with "1" so the URL is valid. Returns how many entries were actually
     * added; malformed URLs are skipped rather than aborting the batch.
     */
    public static int importEndpoints(MontoyaApi api, String baseUrl, List<String> paths) {
        String origin = originOf(baseUrl);
        if (origin == null) return 0;
        int added = 0;
        for (String path : paths) {
            if (path == null || path.isBlank()) continue;
            String url = origin + normalizePath(path);
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                api.siteMap().add(HttpRequestResponse.httpRequestResponse(req, HttpResponse.httpResponse()));
                added++;
            } catch (Exception e) {
                api.logging().logToOutput("SiteMapImporter: skipped " + url + " (" + e.getMessage() + ")");
            }
        }
        api.logging().logToOutput("SiteMapImporter: added " + added + " endpoint(s) to the Target site map.");
        return added;
    }

    private static String normalizePath(String path) {
        String p = path.replace("{id}", "1");
        if (!p.startsWith("/")) p = "/" + p;
        return p;
    }

    /** scheme://host[:port] from a base URL, or null if it can't be parsed. */
    private static String originOf(String baseUrl) {
        try {
            java.net.URI u = java.net.URI.create(baseUrl.trim());
            if (u.getScheme() == null || u.getHost() == null) return null;
            StringBuilder sb = new StringBuilder(u.getScheme()).append("://").append(u.getHost());
            if (u.getPort() != -1) sb.append(':').append(u.getPort());
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
