package com.harness.llm;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import com.harness.llm.model.AnalysisModels.AnalysisResponse;
import com.harness.llm.ui.AttackSurfacePanel;
import com.harness.llm.ui.AttackSurfacePanel.SiteMapRow;
import com.harness.llm.ui.HarnessPanel;

import javax.swing.*;
import java.util.List;

public class LlmHarnessExtension implements BurpExtension {

    private HarnessClient client;
    private HarnessPanel panel;
    private HarnessContextMenu.AnalysisRunner runner;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("LLM Harness");

        client = new HarnessClient("http://localhost:8787", 120);

        panel = new HarnessPanel(() -> {
            client.setBaseUrl(panel.getBaseUrl());
            return client.healthCheck();
        });

        ValidationExecutor validationExecutor = new ValidationExecutor(api, client);

        runner = new HarnessContextMenu.AnalysisRunner(
                api,
                client,
                (label, result) -> SwingUtilities.invokeLater(() ->
                        panel.addSuccess(label, (AnalysisResponse) result)),
                (label, error) -> SwingUtilities.invokeLater(() ->
                        panel.addFailure(label, error)),
                () -> panel.getAttemptRediscovery()
        );
        runner.setValidationExecutor(validationExecutor);
        panel.setPlanExecutor(plan -> validationExecutor.execute(plan, (status, detail) ->
                api.logging().logToOutput("LLM Harness validation " + status + ": " + detail)));

        AttackSurfacePanel surfacePanel = new AttackSurfacePanel(
                () -> buildSiteMapRows(api),
                handle -> {
                    if (handle instanceof HttpRequestResponse rr) {
                        runner.submit(rr, List.of());
                    }
                },
                client);

        api.userInterface().registerSuiteTab("LLM Harness", panel);
        api.userInterface().registerSuiteTab("Attack Surface Map", surfacePanel);
        api.userInterface().registerContextMenuItemsProvider(
                new HarnessContextMenu(api, runner));

        api.logging().logToOutput(
                "LLM Harness extension loaded. Configure the harness URL in the " +
                "'LLM Harness' tab, click Test Connection. Right-click any request " +
                "in Proxy/Repeater/Target for 'Send to LLM Harness', or use the " +
                "'Attack Surface Map' tab to rank everything Burp has seen so far " +
                "before diving into individual requests.");
    }

    /**
     * Pulls everything in Burp's site map (populated by Proxy traffic,
     * Target crawling, Repeater, etc.) and reduces each entry to what the
     * local PathScorer needs, keeping the full HttpRequestResponse as an
     * opaque handle for the "send to harness" action.
     */
    private List<SiteMapRow> buildSiteMapRows(MontoyaApi api) {
        List<HttpRequestResponse> entries = api.siteMap().requestResponses();
        return entries.stream()
                .map(rr -> {
                    var req = rr.request();
                    List<String> paramNames;
                    try {
                        paramNames = req.parameters().stream()
                                .map(ParsedHttpParameter::name)
                                .toList();
                    } catch (Exception e) {
                        paramNames = List.of();
                    }
                    return new SiteMapRow(req.method(), req.url(), paramNames, rr);
                })
                .toList();
    }
}
