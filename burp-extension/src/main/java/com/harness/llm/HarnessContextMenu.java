package com.harness.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Adds "Send to LLM Harness" / "Send to LLM Harness (choose agents)" to
 * Burp's right-click menu wherever a request/response is selected
 * (Proxy history, Repeater, Target site map, etc).
 */
public class HarnessContextMenu implements ContextMenuItemsProvider {

    private static final String[] AGENT_NAMES = {"sqli", "xss", "idor", "ssrf", "auth", "business_logic", "misconfig", "ai_llm", "rate_limit", "supply_chain"};

    private final MontoyaApi api;
    private final AnalysisRunner runner;

    public HarnessContextMenu(MontoyaApi api, AnalysisRunner runner) {
        this.api = api;
        this.runner = runner;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) {
            return List.of();
        }

        List<Component> items = new ArrayList<>();

        JMenuItem sendAll = new JMenuItem("Send to LLM Harness (auto-select agents)");
        sendAll.addActionListener(e -> selected.forEach(rr -> runner.submit(rr, List.of())));
        items.add(sendAll);

        JMenu chooseMenu = new JMenu("Send to LLM Harness (choose agents)");
        for (String agent : AGENT_NAMES) {
            JMenuItem item = new JMenuItem(agent);
            item.addActionListener(e -> selected.forEach(rr -> runner.submit(rr, List.of(agent))));
            chooseMenu.add(item);
        }
        items.add(chooseMenu);

        return items;
    }

    /**
     * Converts a Burp HttpRequestResponse into the plain HTTP exchange the
     * harness expects, submits it in the background, and routes the
     * result back to the UI. Kept separate from the menu provider so the
     * extension's main class can reuse it (e.g. for a future "auto-send
     * everything through Proxy" toggle) without duplicating this logic.
     */
    public static class AnalysisRunner {
        private final MontoyaApi api;
        private final HarnessClient client;
        private final java.util.function.BiConsumer<String, Object> onSuccess;
        private final java.util.function.BiConsumer<String, String> onFailure;
        private final java.util.function.BooleanSupplier attemptRediscoverySupplier;
        private ValidationExecutor validationExecutor;

        public AnalysisRunner(MontoyaApi api, HarnessClient client,
                               java.util.function.BiConsumer<String, Object> onSuccess,
                               java.util.function.BiConsumer<String, String> onFailure,
                               java.util.function.BooleanSupplier attemptRediscoverySupplier) {
            this.api = api;
            this.client = client;
            this.onSuccess = onSuccess;
            this.onFailure = onFailure;
            this.attemptRediscoverySupplier = attemptRediscoverySupplier;
        }

        public void setValidationExecutor(ValidationExecutor executor) {
            this.validationExecutor = executor;
        }

        public void submit(HttpRequestResponse rr, List<String> forceAgents) {
            if (validationExecutor != null) validationExecutor.registerExchange(rr);
            HttpRequest req = rr.request();
            HttpResponse resp = rr.response();
            String label = req.method() + " " + req.url();

            var exchange = new com.harness.llm.model.AnalysisModels.HttpExchange();
            exchange.url = req.url();
            exchange.method = req.method();
            exchange.request_headers = headersToMap(req.headers());
            exchange.request_body = req.bodyToString();
            exchange.response_status = resp != null ? (int) resp.statusCode() : null;
            exchange.response_headers = resp != null ? headersToMap(resp.headers()) : new HashMap<>();
            exchange.response_body = responseBodyForAnalysis(resp);
            exchange.analyst_note = "";

            var analysisReq = new com.harness.llm.model.AnalysisModels.AnalysisRequest();
            analysisReq.exchange = exchange;
            analysisReq.force_agents = forceAgents;
            analysisReq.attempt_rediscovery = attemptRediscoverySupplier.getAsBoolean();

            // Network call off the Swing/Burp event thread.
            new SwingWorker<Object, Void>() {
                String error;

                @Override
                protected Object doInBackground() {
                    try {
                        return client.analyze(analysisReq);
                    } catch (HarnessClient.HarnessException e) {
                        error = e.getMessage();
                        api.logging().logToError("LLM Harness analysis failed for " + label + ": " + error);
                        return null;
                    }
                }

                @Override
                protected void done() {
                    try {
                        Object result = get();
                        if (result != null) {
                            var analysis = (com.harness.llm.model.AnalysisModels.AnalysisResponse) result;
                            if (validationExecutor != null && analysis.test_plans != null) {
                                validationExecutor.registerSources(rr, analysis.test_plans);
                            }
                            onSuccess.accept(label, result);
                        } else {
                            onFailure.accept(label, error != null ? error : "Unknown error");
                        }
                    } catch (Exception e) {
                        onFailure.accept(label, e.getMessage());
                    }
                }
            }.execute();
        }

        private static Map<String, String> headersToMap(List<HttpHeader> headers) {
            Map<String, String> map = new java.util.LinkedHashMap<>();
            if (headers == null) return map;
            for (HttpHeader h : headers) {
                // The wire model is a string map, so preserve duplicate values by
                // joining them rather than silently dropping security-relevant
                // headers such as multiple Set-Cookie fields.
                map.merge(h.name(), h.value(), (oldValue, newValue) -> oldValue + "\n" + newValue);
            }
            return map;
        }

        private static String responseBodyForAnalysis(HttpResponse resp) {
            if (resp == null) return "";
            String contentType = resp.headers().stream()
                    .filter(h -> "Content-Type".equalsIgnoreCase(h.name()))
                    .map(HttpHeader::value)
                    .findFirst()
                    .orElse("")
                    .toLowerCase(java.util.Locale.ROOT);
            if (!contentType.isEmpty() && !isTextContentType(contentType)) {
                return "[non-text response body omitted: " + contentType + "]";
            }
            return resp.bodyToString();
        }

        private static boolean isTextContentType(String contentType) {
            return contentType.startsWith("text/")
                    || contentType.contains("json")
                    || contentType.contains("xml")
                    || contentType.contains("javascript")
                    || contentType.contains("ecmascript")
                    || contentType.contains("x-www-form-urlencoded")
                    || contentType.contains("graphql");
        }
    }
}
