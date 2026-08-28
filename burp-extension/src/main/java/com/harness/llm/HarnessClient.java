package com.harness.llm;

import com.google.gson.Gson;
import com.harness.llm.model.AnalysisModels.AnalysisRequest;
import com.harness.llm.model.AnalysisModels.AnalysisResponse;
import com.harness.llm.model.AnalysisModels.ErrorBody;
import com.harness.llm.model.AnalysisModels.EstimateRequest;
import com.harness.llm.model.AnalysisModels.EstimateResponse;
import com.harness.llm.model.AnalysisModels.EffortStatus;
import com.harness.llm.model.AnalysisModels.ValidationSubmission;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
    private volatile String bearerToken;

    public HarnessClient(String baseUrl, int timeoutSeconds) {
        this.baseUrl = baseUrl;
        this.timeoutSeconds = timeoutSeconds;
        this.bearerToken = System.getenv("HARNESS_BEARER_TOKEN");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    public boolean healthCheck() {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/health"))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .headers(authHeaders())
                    .build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            return resp.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /** Posts an independently observed validation result back to the control plane. */
    public void submitValidationResult(ValidationSubmission submission) throws HarnessException {
        String body = gson.toJson(submission);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/validation-results"))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .headers(authHeaders())
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

    private String[] authHeaders() {
        return bearerToken == null || bearerToken.isBlank()
                ? new String[0]
                : new String[]{"Authorization", "Bearer " + bearerToken};
    }

    public AnalysisResponse analyze(AnalysisRequest request) throws HarnessException {
        String body = gson.toJson(request);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/analyze"))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .headers(authHeaders())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
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
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/estimate"))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .headers(authHeaders())
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

    /** Current cumulative real spend against the configured budget -- see GET /effort. */
    public EffortStatus effortStatus() throws HarnessException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/effort"))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .headers(authHeaders())
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
}
