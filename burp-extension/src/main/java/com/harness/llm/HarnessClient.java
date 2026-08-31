package com.harness.llm;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.harness.llm.model.AnalysisModels.AnalysisRequest;
import com.harness.llm.model.AnalysisModels.AnalysisResponse;
import com.harness.llm.model.AnalysisModels.ErrorBody;
import com.harness.llm.model.AnalysisModels.EstimateRequest;
import com.harness.llm.model.AnalysisModels.EstimateResponse;
import com.harness.llm.model.AnalysisModels.PrioritizeRequest;
import com.harness.llm.model.AnalysisModels.PrioritizeResponse;
import com.harness.llm.model.AnalysisModels.EffortStatus;
import com.harness.llm.model.AnalysisModels.IdentityInfo;
import com.harness.llm.model.AnalysisModels.SessionInfo;
import com.harness.llm.model.AnalysisModels.ValidationSubmission;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/**
 * Talks to the local harness server (harness/server.py). Loopback-only by
 * default -- this extension never talks to anything other than the
 * baseUrl the analyst configures, and that should always be localhost
 * unless the analyst has deliberately set up something else.
 */
public class HarnessClient {

    public static class HarnessException extends Exception {
        public HarnessException(String message) { super(message); }
        public HarnessException(String message, Throwable cause) { super(message, cause); }
    }

    private final Gson gson = new Gson();
    private final HttpClient httpClient;
    private volatile String baseUrl;
    private volatile int timeoutSeconds;
    // /analyze is the one endpoint that can involve many real, sequential
    // LLM round-trips -- every other endpoint here (/health, /estimate,
    // /effort, /identities, /sessions, /validation-results) is fast and
    // deterministic, no model call in the loop. Deliberately a separate
    // budget from timeoutSeconds: concurrency.max_parallel_agents (see
    // harness/config.yaml) trades dispatch throughput for staying within
    // a single GPU's VRAM, which means more total wall-clock time for a
    // dispatch involving several agents, not less -- a single shared
    // 120s budget across every endpoint was never going to survive real
    // inference once Ollama was actually reachable, and generously
    // covers even the coordinator's fail-open-to-all-36-agents fallback
    // (see orchestrator.py) at limited concurrency.
    private volatile int analysisTimeoutSeconds = 600;
    private volatile String bearerToken;

    public HarnessClient(String baseUrl, int timeoutSeconds) {
        this.baseUrl = baseUrl;
        this.timeoutSeconds = timeoutSeconds;
        this.bearerToken = System.getenv("HARNESS_BEARER_TOKEN");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                // Explicitly bypass any system/JVM-wide proxy. This client
                // only ever talks to a local harness process the user
                // configured directly in the URL field -- it should never
                // be subject to Burp's own upstream proxy settings, a
                // corporate/VPN proxy, or any other system-level proxy
                // configuration. Without this, java.net.http.HttpClient
                // falls back to ProxySelector.getDefault(), which DOES
                // route localhost traffic through a configured proxy
                // unless that proxy's own bypass list happens to exempt
                // localhost -- browsers bypass localhost by convention,
                // this client did not, which is why "reachable in Chrome,
                // unreachable in Burp" was possible at all.
                .proxy(HttpClient.Builder.NO_PROXY)
                // Force plain HTTP/1.1. HttpClient's default version
                // preference is HTTP_2, which makes it send a cleartext
                // upgrade attempt (Upgrade: h2c / HTTP2-Settings headers)
                // alongside every request even for plain http:// URLs.
                // Confirmed by direct reproduction against the real
                // harness server: the connection still negotiates down to
                // HTTP/1.1 either way, but uvicorn's request parser
                // silently drops the request BODY when those upgrade
                // headers are present -- Content-Length is correct on the
                // wire, the server just never reads it, and FastAPI/
                // Pydantic reports the body itself as missing (HTTP 422,
                // "loc":["body"], "msg":"Field required"). This local
                // server never needs or benefits from HTTP/2, so there's
                // no reason to ever attempt the upgrade.
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    public void setAnalysisTimeoutSeconds(int analysisTimeoutSeconds) {
        this.analysisTimeoutSeconds = analysisTimeoutSeconds;
    }

    public int getAnalysisTimeoutSeconds() {
        return analysisTimeoutSeconds;
    }

    private volatile String lastHealthCheckError = null;

    /** The exception message from the most recent healthCheck() failure,
     * or null if the last check succeeded or none has run yet. Exists so
     * the UI can show *why* a connection failed instead of just that it
     * did -- "Unreachable" alone gives the user nothing to act on. */
    public String getLastHealthCheckError() {
        return lastHealthCheckError;
    }

    public boolean healthCheck() {
        try {
            HttpRequest req = newRequestBuilder("/health", Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                lastHealthCheckError = null;
                return true;
            }
            lastHealthCheckError = "HTTP " + resp.statusCode() + ": " + resp.body();
            return false;
        } catch (Exception e) {
            lastHealthCheckError = e.getClass().getSimpleName()
                    + (e.getMessage() != null ? ": " + e.getMessage() : "");
            return false;
        }
    }

    /** Posts an independently observed validation result back to the control plane. */
    public void submitValidationResult(ValidationSubmission submission) throws HarnessException {
        String body = gson.toJson(submission);
        HttpRequest req = newRequestBuilder("/validation-results", Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new HarnessException("Harness validation result rejected (HTTP " + resp.statusCode() + "): " + resp.body());
            }
        } catch (IOException e) {
            throw new HarnessException("Could not post validation result: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HarnessException("Validation result submission interrupted", e);
        }
    }

    public void setBearerToken(String token) {
        this.bearerToken = (token == null || token.isBlank()) ? null : token.trim();
    }

    /**
     * Builds a request targeting `path` with auth applied correctly.
     *
     * Replaces the old pattern of `.headers(authHeaders())`, which threw
     * `IllegalArgumentException: wrong number, 0, of parameters` on
     * EVERY request whenever no bearer token was configured (the common
     * case) -- java.net.http.HttpRequest.Builder.headers(String...)
     * requires a non-empty, even-length array of name/value pairs, and
     * silently accepts nothing less; passing an empty array wasn't a
     * no-op, it was a guaranteed exception, thrown before the request
     * ever reached the network. This affected all 8 call sites in this
     * class equally -- healthCheck() just happened to be the one a user
     * noticed first, via a "Test Connection" button that made the
     * symptom visible.
     */
    private HttpRequest.Builder newRequestBuilder(String path, Duration timeout) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(timeout);
        if (bearerToken != null && !bearerToken.isBlank()) {
            builder.header("Authorization", "Bearer " + bearerToken);
        }
        return builder;
    }

    public AnalysisResponse analyze(AnalysisRequest request) throws HarnessException {
        String body = gson.toJson(request);
        HttpRequest req = newRequestBuilder("/analyze", Duration.ofSeconds(analysisTimeoutSeconds))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (HttpTimeoutException e) {
            throw new HarnessException(
                    "Analysis did not finish within " + analysisTimeoutSeconds + "s. This is a client-side "
                    + "wait budget, not necessarily a failure -- a dispatch involving several agents at limited "
                    + "concurrency (see config.yaml's concurrency.max_parallel_agents) with real LLM inference "
                    + "can genuinely take a while, and the harness may still be working or may have already "
                    + "finished server-side. Raise the analysis timeout in the Harness URL bar, or check the "
                    + "harness server's own logs/audit trail for whether this exchange actually completed.", e);
        } catch (IOException e) {
            throw new HarnessException(
                    "Could not reach harness at " + baseUrl +
                    ". Is `python server.py` running? (" + e.getMessage() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HarnessException("Request interrupted", e);
        }

        if (resp.statusCode() != 200) {
            String detail;
            try {
                ErrorBody err = gson.fromJson(resp.body(), ErrorBody.class);
                detail = (err != null && err.error != null) ? err.error : resp.body();
            } catch (Exception parseFail) {
                detail = resp.body();
            }
            throw new HarnessException("Harness returned HTTP " + resp.statusCode() + ": " + detail);
        }

        try {
            AnalysisResponse parsed = gson.fromJson(resp.body(), AnalysisResponse.class);
            if (parsed == null) {
                throw new HarnessException("Harness returned an empty/unparseable response body");
            }
            if (parsed.agent_reports == null) {
                parsed.agent_reports = List.of();
            }
            return parsed;
        } catch (Exception e) {
            throw new HarnessException("Failed to parse harness response: " + e.getMessage(), e);
        }
    }

    /**
     * Projects total token cost for running the full assessment across
     * `urls` -- see harness/effort.py::estimate_for_urls and server.py's
     * POST /estimate. Meant to be called once the analyst has spidered
     * the target (Attack Surface Map populated) and sent at least one
     * real exchange through analyze() already, so the projection is
     * calibrated against real token usage rather than the unmeasured
     * priors effort.py falls back to -- but it works either way; the
     * response's calibrated_from_real_calls field says which happened.
     */
    public EstimateResponse estimate(EstimateRequest request) throws HarnessException {
        String body = gson.toJson(request);
        HttpRequest req = newRequestBuilder("/estimate", Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new HarnessException("Could not reach harness at " + baseUrl + " for /estimate (" + e.getMessage() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HarnessException("Request interrupted", e);
        }
        if (resp.statusCode() != 200) {
            throw new HarnessException("Harness /estimate returned HTTP " + resp.statusCode() + ": " + resp.body());
        }
        EstimateResponse parsed = gson.fromJson(resp.body(), EstimateResponse.class);
        if (parsed == null) {
            throw new HarnessException("Harness /estimate returned an empty/unparseable response body");
        }
        return parsed;
    }

    /**
     * Structure-only (method/URL/param names, no bodies) LLM triage pass
     * for the Attack Surface Map tab -- see harness/surface_prioritizer.py
     * and server.py's POST /prioritize. The server batches `request.items`
     * into a handful of LLM calls internally; this is a single HTTP call
     * from this side regardless of how many items are in it. Uses a
     * longer timeout than the other short calls here (estimate/effort) --
     * this one genuinely runs LLM inference, potentially several batches
     * of it server-side, unlike those.
     */
    public PrioritizeResponse prioritize(PrioritizeRequest request) throws HarnessException {
        String body = gson.toJson(request);
        HttpRequest req = newRequestBuilder("/prioritize", Duration.ofSeconds(Math.max(timeoutSeconds, 120)))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new HarnessException("Could not reach harness at " + baseUrl + " for /prioritize (" + e.getMessage() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HarnessException("Request interrupted", e);
        }
        if (resp.statusCode() != 200) {
            throw new HarnessException("Harness /prioritize returned HTTP " + resp.statusCode() + ": " + resp.body());
        }
        PrioritizeResponse parsed = gson.fromJson(resp.body(), PrioritizeResponse.class);
        if (parsed == null) {
            throw new HarnessException("Harness /prioritize returned an empty/unparseable response body");
        }
        return parsed;
    }

    /** Current cumulative real spend against the configured budget -- see GET /effort. */
    public EffortStatus effortStatus() throws HarnessException {
        HttpRequest req = newRequestBuilder("/effort", Duration.ofSeconds(timeoutSeconds))
                .GET()
                .build();
        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new HarnessException("Could not reach harness at " + baseUrl + " for /effort (" + e.getMessage() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HarnessException("Request interrupted", e);
        }
        if (resp.statusCode() != 200) {
            throw new HarnessException("Harness /effort returned HTTP " + resp.statusCode() + ": " + resp.body());
        }
        EffortStatus parsed = gson.fromJson(resp.body(), EffortStatus.class);
        if (parsed == null) {
            throw new HarnessException("Harness /effort returned an empty/unparseable response body");
        }
        return parsed;
    }

    /**
     * All named identities registered via POST /identities -- see
     * identity.Identity. Used to populate the "which identity is this
     * session" picker when registering a new session, and to resolve
     * IdentityCompareLogic's picker labels alongside sessionsForHost().
     */
    public List<IdentityInfo> listIdentities() throws HarnessException {
        HttpRequest req = newRequestBuilder("/identities", Duration.ofSeconds(timeoutSeconds))
                .GET()
                .build();
        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new HarnessException("Could not reach harness at " + baseUrl + " for /identities (" + e.getMessage() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HarnessException("Request interrupted", e);
        }
        if (resp.statusCode() != 200) {
            throw new HarnessException("Harness /identities returned HTTP " + resp.statusCode() + ": " + resp.body());
        }
        List<IdentityInfo> parsed = gson.fromJson(resp.body(), new TypeToken<List<IdentityInfo>>() {}.getType());
        return parsed == null ? List.of() : parsed;
    }

    /**
     * All sessions registered for `host` -- see harness/store.py's
     * sessions_for_host(), which already JOINs the identity's name/role
     * in (see SessionInfo's field-shape note in AnalysisModels.java).
     * This is what lets identityCompare()'s picker show "Alice (admin)"
     * instead of a bare fingerprint for any candidate exchange that has
     * a registered session.
     */
    public List<SessionInfo> sessionsForHost(String host) throws HarnessException {
        String encodedHost = URLEncoder.encode(host, StandardCharsets.UTF_8);
        HttpRequest req = newRequestBuilder("/hosts/" + encodedHost + "/sessions", Duration.ofSeconds(timeoutSeconds))
                .GET()
                .build();
        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new HarnessException("Could not reach harness at " + baseUrl + " for /hosts/" + host + "/sessions (" + e.getMessage() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HarnessException("Request interrupted", e);
        }
        if (resp.statusCode() != 200) {
            throw new HarnessException("Harness /hosts/" + host + "/sessions returned HTTP " + resp.statusCode() + ": " + resp.body());
        }
        List<SessionInfo> parsed = gson.fromJson(resp.body(), new TypeToken<List<SessionInfo>>() {}.getType());
        return parsed == null ? List.of() : parsed;
    }

    /**
     * Registers a session linking `exchangeHash` (the same SHA-256
     * fingerprint ValidationExecutor.exchangeFingerprint() computes --
     * see IdentityCompareLogic's docstring for the verified match
     * between this and harness/planner.py::exchange_fingerprint()) to
     * an existing identity. This is the write side that makes
     * sessionsForHost() return anything at all -- without a caller of
     * this method, the read side above has nothing to read.
     */
    public SessionInfo createSession(String identityId, String host, String exchangeHash, String label) throws HarnessException {
        var payload = new java.util.HashMap<String, String>();
        payload.put("identity_id", identityId);
        payload.put("host", host);
        payload.put("exchange_hash", exchangeHash);
        payload.put("label", label == null ? "" : label);
        String body = gson.toJson(payload);
        HttpRequest req = newRequestBuilder("/sessions", Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new HarnessException("Could not reach harness at " + baseUrl + " for /sessions (" + e.getMessage() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HarnessException("Request interrupted", e);
        }
        if (resp.statusCode() != 200) {
            throw new HarnessException("Harness /sessions returned HTTP " + resp.statusCode() + ": " + resp.body());
        }
        // The server's POST /sessions response is a small subset of
        // SessionInfo's fields (id, identity_id, host, exchange_hash,
        // label -- no identity_name/identity_role, since it doesn't
        // re-join at creation time). Parse loosely; callers of
        // createSession don't need the joined fields back, only
        // confirmation the session was created.
        SessionInfo parsed = gson.fromJson(resp.body(), SessionInfo.class);
        if (parsed == null) {
            throw new HarnessException("Harness /sessions returned an empty/unparseable response body");
        }
        return parsed;
    }
}
