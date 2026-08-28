package com.harness.llm.model;

import java.util.List;
import java.util.Map;

/**
 * Wire-format POJOs. Field names must match the JSON keys the Python
 * harness (models.py) actually produces/consumes -- these two files are
 * the narrow interface between the two halves of this system and have
 * to be kept in sync by hand, since there's no shared schema.
 */
public class AnalysisModels {

    public static class HttpExchange {
        public String url;
        public String method;
        public Map<String, String> request_headers;
        public String request_body;
        public Integer response_status; // nullable
        public Map<String, String> response_headers;
        public String response_body;
        public String analyst_note;
    }

    public static class AnalysisRequest {
        public HttpExchange exchange;
        public List<String> force_agents;
        public boolean attempt_rediscovery;
    }

    public static class Finding {
        public String vulnerability_class;
        public double confidence;
        public String severity;        // "info"|"low"|"medium"|"high"|"critical"
        public String owasp_category;  // nullable
        public String summary;
        public String evidence;
        public String suggested_test;
        public String basis;
        public Double original_confidence; // nullable
        public String review_verdict;      // nullable
        public String review_note;         // nullable
        public boolean confirmed;
    }

    public static class AgentReport {
        public String agent;
        public String model;
        public List<Finding> findings;
        public String raw_error; // nullable
    }

    public static class TestPlan {
        public String id;
        public String capability;
        public String finding_class;
        public String category; // nullable -- canonicalized category, see harness/categories.py
        public String source_exchange_url;
        public Map<String, String> mutation;
        public List<String> success_signals;
        public boolean requires_approval;
        public String execution_plane;
        public String rationale;
        public String source_exchange_hash;
        public String schema_version;
    }

    public static class ValidationSubmission {
        public String plan_id;
        public String status;
        public double confidence;
        public boolean confirmed;
        public String summary;
        public String evidence;
        public String executor;
        public String source_exchange_hash;
    }

    public static class AnalysisResponse {
        public String coordinator_model;
        public List<String> dispatched_agents;
        public List<AgentReport> agent_reports;
        public String summary;
        public Finding highest_confidence_finding; // nullable
        public int findings_reviewed;
        public int findings_rejected;
        public List<TestPlan> test_plans;
        public int effort_spent_tokens;
        public Integer effort_budget_remaining; // nullable -- null means no cap configured
        public String effort_budget_warning;    // "" when nothing to report
    }

    public static class UrlEstimateItem {
        public String url;
        public Double risk_score; // nullable, 0.0-1.0
        public String category;   // nullable
    }

    public static class EstimateRequest {
        public List<UrlEstimateItem> urls;
    }

    public static class EstimateResponse {
        public int urls_total;
        public int urls_scored;
        public int urls_unscored;
        public int urls_high_risk;
        public long estimated_total_tokens;
        public boolean calibrated_from_real_calls;
        public Map<String, Long> breakdown;
        public Map<String, Double> assumptions;
    }

    public static class EffortStatus {
        public String mode;
        public Integer total_tokens; // nullable
        public int spent_tokens;
        public Integer remaining_tokens; // nullable
        public boolean exhausted;
        public Map<String, Long> breakdown;
    }

    public static class ErrorBody {
        public String error;
    }
}
