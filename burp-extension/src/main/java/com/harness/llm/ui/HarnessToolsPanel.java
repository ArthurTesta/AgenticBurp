package com.harness.llm.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.harness.llm.HarnessClient;
import com.harness.llm.model.AnalysisModels.ActivityEvent;
import com.harness.llm.model.AnalysisModels.ActivitySnapshot;
import com.harness.llm.model.AnalysisModels.HttpExchange;
import com.harness.llm.model.AnalysisModels.ModelsInfo;
import com.harness.llm.model.AnalysisModels.SelectModelRequest;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * "Harness Tools" suite tab -- the UI for the Session-3 server capabilities
 * that don't belong to the per-exchange analysis flow: model selection, runtime
 * settings, endpoint discovery (crawl), missing-auth probing, the active
 * (iterative) agent, the per-vulnerability retry loop, the budget-allocation
 * prioritizer, tool recommendations, the confidential-info scanner, and the
 * live agent-activity feed.
 *
 * Deliberately self-contained: it owns no analysis state and only talks to the
 * shared {@link HarnessClient}, so it can't destabilize the existing
 * AttackSurface/Harness panels. Every network call runs off the EDT (see
 * {@link #runAsync}); deep/dynamic responses are shown as pretty-printed JSON
 * rather than mirrored into bespoke widgets, which keeps this one panel able to
 * surface everything the server returns without a DTO per shape.
 */
public class HarnessToolsPanel extends JPanel {

    private final HarnessClient client;
    private final Gson pretty = new GsonBuilder().setPrettyPrinting().create();

    // Model dropdowns (populated from GET /models).
    private final JComboBox<String> coordinatorCombo = new JComboBox<>();
    private final JComboBox<String> agentCombo = new JComboBox<>();

    public HarnessToolsPanel(HarnessClient client) {
        this.client = client;
        setLayout(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Models & Settings", buildModelsTab());
        tabs.addTab("Discovery", buildDiscoveryTab());
        tabs.addTab("Active Testing", buildActiveTab());
        tabs.addTab("Budget", buildBudgetTab());
        tabs.addTab("Tools", buildToolsTab());
        tabs.addTab("Confidential Scan", buildConfidentialTab());
        tabs.addTab("Activity", buildActivityTab());
        add(tabs, BorderLayout.CENTER);
    }

    // ------------------------------------------------------------------
    // Shared helpers
    // ------------------------------------------------------------------

    private JTextArea outputArea() {
        JTextArea a = new JTextArea();
        a.setEditable(false);
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        return a;
    }

    /** Runs {@code call} off the EDT; renders the resulting JSON (or the error)
     * into {@code out}. Disables {@code trigger} while in flight so a slow call
     * can't be fired repeatedly. */
    private void runAsync(JButton trigger, JTextArea out, Callable<JsonObject> call) {
        if (trigger != null) trigger.setEnabled(false);
        out.setText("Running...");
        new SwingWorker<Object, Void>() {
            @Override protected Object doInBackground() {
                try {
                    return call.call();
                } catch (Exception e) {
                    return e;
                }
            }
            @Override protected void done() {
                try {
                    Object r = get();
                    if (r instanceof Exception e) {
                        out.setText("ERROR: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
                    } else {
                        out.setText(pretty.toJson(r));
                    }
                } catch (Exception e) {
                    out.setText("ERROR: " + e.getMessage());
                } finally {
                    if (trigger != null) trigger.setEnabled(true);
                    out.setCaretPosition(0);
                }
            }
        }.execute();
    }

    private HttpExchange exchangeFrom(String url, String method, String responseBody) {
        HttpExchange ex = new HttpExchange();
        ex.url = url.trim();
        ex.method = method == null || method.isBlank() ? "GET" : method.trim();
        ex.request_headers = new HashMap<>();
        ex.request_body = "";
        ex.response_status = 200;
        ex.response_headers = new HashMap<>();
        ex.response_body = responseBody == null ? "" : responseBody;
        ex.analyst_note = "";
        return ex;
    }

    private static JPanel labeled(String label, Component field) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        p.add(new JLabel(label));
        p.add(field);
        return p;
    }

    private static JPanel form(Component... rows) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        for (Component r : rows) {
            r.setAlignmentX(Component.LEFT_ALIGNMENT);
            p.add(r);
        }
        return p;
    }

    private JPanel withOutput(JComponent north, JTextArea out) {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.add(north, BorderLayout.NORTH);
        p.add(new JScrollPane(out), BorderLayout.CENTER);
        return p;
    }

    // ------------------------------------------------------------------
    // Models & Settings
    // ------------------------------------------------------------------

    private JComponent buildModelsTab() {
        JTextArea out = outputArea();

        JButton refresh = new JButton("Refresh models");
        refresh.addActionListener(e -> reloadModels(out));

        JButton applyModels = new JButton("Apply model selection");
        applyModels.addActionListener(e -> {
            SelectModelRequest req = new SelectModelRequest();
            Object coord = coordinatorCombo.getSelectedItem();
            Object agent = agentCombo.getSelectedItem();
            req.coordinator = coord == null ? "" : coord.toString();
            req.agent_model = agent == null ? "" : agent.toString();
            runAsync(applyModels, out, () -> client.selectModel(req));
        });

        JTextField throttleField = new JTextField("0", 6);
        JTextField retriesField = new JTextField("", 4);
        JTextField agentsField = new JTextField("", 4);
        JTextField perVulnField = new JTextField("", 8);
        JButton applySettings = new JButton("Apply settings");
        applySettings.addActionListener(e -> {
            Double rps = parseDoubleOrNull(throttleField.getText());
            Map<String, Object> retry = new HashMap<>();
            putIntIfPresent(retry, "max_retries", retriesField.getText());
            putIntIfPresent(retry, "max_agents", agentsField.getText());
            putIntIfPresent(retry, "max_tokens_per_vuln", perVulnField.getText());
            runAsync(applySettings, out, () -> client.updateSettings(rps, retry.isEmpty() ? null : retry));
        });
        JButton loadSettings = new JButton("Load current settings");
        loadSettings.addActionListener(e -> runAsync(loadSettings, out, client::getSettings));

        JComponent north = form(
                new JLabel("Model selection (the two dropdowns): coordinator/governor and agent model."),
                labeled("Coordinator model:", coordinatorCombo),
                labeled("Agent model (all agents):", agentCombo),
                buttonRow(refresh, applyModels),
                new JSeparator(),
                new JLabel("Runtime settings: throttle (req/s, 0 = unlimited) and default retry budget."),
                labeled("Throttle req/s:", throttleField),
                labeled("Retry budget -- max_retries:", retriesField),
                labeled("max_agents:", agentsField),
                labeled("max_tokens_per_vuln (0 = none):", perVulnField),
                buttonRow(loadSettings, applySettings));
        return withOutput(north, out);
    }

    private void reloadModels(JTextArea out) {
        new SwingWorker<Object, Void>() {
            @Override protected Object doInBackground() {
                try { return client.listModels(); } catch (Exception e) { return e; }
            }
            @Override protected void done() {
                try {
                    Object r = get();
                    if (r instanceof Exception e) {
                        out.setText("ERROR loading models: " + e.getMessage());
                        return;
                    }
                    ModelsInfo m = (ModelsInfo) r;
                    coordinatorCombo.removeAllItems();
                    agentCombo.removeAllItems();
                    List<String> all = m.all != null ? m.all : List.of();
                    for (String name : all) {
                        coordinatorCombo.addItem(name);
                        agentCombo.addItem(name);
                    }
                    if (m.coordinator_model != null) coordinatorCombo.setSelectedItem(m.coordinator_model);
                    out.setText(pretty.toJson(m));
                    out.setCaretPosition(0);
                } catch (Exception e) {
                    out.setText("ERROR: " + e.getMessage());
                }
            }
        }.execute();
    }

    // ------------------------------------------------------------------
    // Discovery (crawl + missing-auth)
    // ------------------------------------------------------------------

    private JComponent buildDiscoveryTab() {
        JTextArea out = outputArea();

        JTextField crawlUrl = new JTextField("http://localhost:3000/", 30);
        JTextField maxPages = new JTextField("40", 5);
        JButton crawlBtn = new JButton("Crawl");
        crawlBtn.addActionListener(e ->
                runAsync(crawlBtn, out, () -> client.crawl(crawlUrl.getText().trim(), null,
                        parseIntOr(maxPages.getText(), 40), 2)));

        JTextField maUrl = new JTextField("http://localhost:3000/", 30);
        JTextArea maPaths = new JTextArea(4, 30);
        maPaths.setBorder(BorderFactory.createTitledBorder("Paths to probe (one per line; blank -> use discover)"));
        JCheckBox discover = new JCheckBox("Discover endpoints first (crawl)");
        JButton probeBtn = new JButton("Probe missing auth");
        probeBtn.addActionListener(e -> {
            Map<String, Object> body = new HashMap<>();
            body.put("base_url", maUrl.getText().trim());
            List<String> paths = new ArrayList<>();
            for (String line : maPaths.getText().split("\\R")) {
                if (!line.isBlank()) paths.add(line.trim());
            }
            if (!paths.isEmpty()) body.put("paths", paths);
            body.put("discover", discover.isSelected());
            runAsync(probeBtn, out, () -> client.probeMissingAuth(body));
        });

        JComponent north = form(
                new JLabel("Crawl: mine the app's JS bundles for its real endpoint surface (POST /crawl)."),
                labeled("Base URL:", crawlUrl),
                labeled("Max pages:", maxPages),
                buttonRow(crawlBtn),
                new JSeparator(),
                new JLabel("Missing-auth probe: fire endpoints with credentials stripped, flag substantive 2xx."),
                labeled("Base URL:", maUrl),
                maPaths,
                buttonRow(discover, probeBtn));
        return withOutput(north, out);
    }

    // ------------------------------------------------------------------
    // Active testing (active-probe + retry-agents)
    // ------------------------------------------------------------------

    private JComponent buildActiveTab() {
        JTextArea out = outputArea();

        JTextField url = new JTextField("http://localhost:3000/rest/user/whoami", 30);
        JComboBox<String> method = new JComboBox<>(new String[]{"GET", "POST", "PUT", "PATCH", "DELETE"});
        JTextField hypothesis = new JTextField("IDOR on the id parameter", 30);
        JTextField specialty = new JTextField("idor", 12);
        JTextField stepBudget = new JTextField("20", 5);
        JButton probeBtn = new JButton("Run active probe");
        probeBtn.addActionListener(e -> {
            HttpExchange ex = exchangeFrom(url.getText(), (String) method.getSelectedItem(), "");
            runAsync(probeBtn, out, () -> client.activeProbe(ex, hypothesis.getText().trim(),
                    specialty.getText().trim(), "", parseIntOr(stepBudget.getText(), 20)));
        });

        JTextField retryClass = new JTextField("sqli", 12);
        JTextField retryCount = new JTextField("3", 4);
        JButton retryBtn = new JButton("Retry agents");
        retryBtn.addActionListener(e -> {
            HttpExchange ex = exchangeFrom(url.getText(), (String) method.getSelectedItem(), "");
            Map<String, Object> overrides = new HashMap<>();
            putIntIfPresent(overrides, "max_retries", retryCount.getText());
            runAsync(retryBtn, out, () -> client.retryAgents(ex, retryClass.getText().trim(),
                    overrides.isEmpty() ? null : overrides));
        });

        JComponent north = form(
                new JLabel("Active testing drives real adaptive traffic (server: iterative_agent.enabled + safety gate)."),
                labeled("URL:", url),
                labeled("Method:", method),
                new JLabel("Active probe (F4+F2): iterate, then validate/remember/pivot."),
                labeled("Hypothesis:", hypothesis),
                labeled("Specialty:", specialty),
                labeled("Step budget:", stepBudget),
                buttonRow(probeBtn),
                new JSeparator(),
                new JLabel("Retry loop (F5): re-run one agent up to N times, stop on a finding."),
                labeled("Agent class:", retryClass),
                labeled("Max retries:", retryCount),
                buttonRow(retryBtn));
        return withOutput(north, out);
    }

    // ------------------------------------------------------------------
    // Budget allocation
    // ------------------------------------------------------------------

    private JComponent buildBudgetTab() {
        JTextArea out = outputArea();
        JTextArea candidates = new JTextArea(6, 30);
        candidates.setText("critical sqli https://shop.test/rest/user/login\nlow xss https://shop.test/search");
        candidates.setBorder(BorderFactory.createTitledBorder(
                "Candidates -- one per line: <severity> <vulnerability_class> <url>"));
        JCheckBox useLlm = new JCheckBox("Use LLM (cloud model) to rank for this app");
        JButton planBtn = new JButton("Plan allocation");
        planBtn.addActionListener(e -> {
            List<Map<String, Object>> cands = new ArrayList<>();
            int i = 0;
            for (String line : candidates.getText().split("\\R")) {
                String[] parts = line.trim().split("\\s+", 3);
                if (parts.length < 3) continue;
                Map<String, Object> c = new HashMap<>();
                c.put("id", "c" + (i++));
                c.put("severity", parts[0]);
                c.put("vulnerability_class", parts[1]);
                c.put("url", parts[2]);
                cands.add(c);
            }
            runAsync(planBtn, out, () -> client.planAllocation(cands, useLlm.isSelected()));
        });
        JComponent north = form(
                new JLabel("F5 prioritizer: spread the remaining token budget across competing vulnerabilities."),
                candidates,
                buttonRow(useLlm, planBtn));
        return withOutput(north, out);
    }

    // ------------------------------------------------------------------
    // Tools
    // ------------------------------------------------------------------

    private JComponent buildToolsTab() {
        JTextArea out = outputArea();
        JTextField vc = new JTextField("sqli", 14);
        JTextField url = new JTextField("https://shop.test/item?id=1", 30);
        JButton recommend = new JButton("Recommend tools");
        recommend.addActionListener(e ->
                runAsync(recommend, out, () -> client.recommendTools(vc.getText().trim(), url.getText().trim())));
        JButton listAll = new JButton("List catalog");
        listAll.addActionListener(e -> runAsync(listAll, out, () -> client.tools("")));
        JComponent north = form(
                new JLabel("A3 tool catalog: which external tool to reach for, with a command templated to the URL."),
                labeled("Vulnerability class:", vc),
                labeled("Target URL:", url),
                buttonRow(recommend, listAll));
        return withOutput(north, out);
    }

    // ------------------------------------------------------------------
    // Confidential scan
    // ------------------------------------------------------------------

    private JComponent buildConfidentialTab() {
        JTextArea out = outputArea();
        JTextField url = new JTextField("https://shop.test/api/x", 30);
        JTextArea body = new JTextArea(8, 30);
        body.setBorder(BorderFactory.createTitledBorder("Response body to scan"));
        JButton scanBtn = new JButton("Scan response");
        scanBtn.addActionListener(e -> {
            HttpExchange ex = exchangeFrom(url.getText(), "GET", body.getText());
            runAsync(scanBtn, out, () -> client.scanConfidential(ex));
        });
        JComponent north = form(
                new JLabel("A4: deterministic secret/PII/internal-infra scan (values are redacted server-side)."),
                labeled("URL:", url),
                body,
                buttonRow(scanBtn));
        return withOutput(north, out);
    }

    // ------------------------------------------------------------------
    // Activity feed (live poll)
    // ------------------------------------------------------------------

    private long lastSeq = 0;
    private final AtomicBoolean polling = new AtomicBoolean(false);

    private JComponent buildActivityTab() {
        JTextArea out = outputArea();
        out.setLineWrap(false);
        JButton startBtn = new JButton("Start live view");
        JButton stopBtn = new JButton("Stop");
        stopBtn.setEnabled(false);
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> out.setText(""));

        // A Swing timer ticks on the EDT and launches a short background fetch;
        // an in-flight guard prevents overlapping polls from piling up.
        javax.swing.Timer timer = new javax.swing.Timer(1500, null);
        timer.addActionListener(e -> {
            if (!polling.compareAndSet(false, true)) return;
            long since = lastSeq;
            new SwingWorker<Object, Void>() {
                @Override protected Object doInBackground() {
                    try { return client.activitySince(since); } catch (Exception ex) { return ex; }
                }
                @Override protected void done() {
                    try {
                        Object r = get();
                        if (r instanceof ActivitySnapshot snap) {
                            if (snap.dropped > 0) {
                                out.append("... (" + snap.dropped + " events aged out of the buffer) ...\n");
                            }
                            if (snap.events != null) {
                                for (ActivityEvent ev : snap.events) {
                                    out.append(formatEvent(ev) + "\n");
                                }
                            }
                            lastSeq = Math.max(lastSeq, snap.latest_seq);
                            out.setCaretPosition(out.getDocument().getLength());
                        } else if (r instanceof Exception ex) {
                            out.append("[feed error] " + ex.getMessage() + "\n");
                        }
                    } catch (Exception ignore) {
                        // never let a rendering hiccup kill the timer
                    } finally {
                        polling.set(false);
                    }
                }
            }.execute();
        });

        startBtn.addActionListener(e -> {
            lastSeq = 0;
            timer.start();
            startBtn.setEnabled(false);
            stopBtn.setEnabled(true);
        });
        stopBtn.addActionListener(e -> {
            timer.stop();
            startBtn.setEnabled(true);
            stopBtn.setEnabled(false);
        });

        JComponent north = form(
                new JLabel("V1 live agent-activity feed: dispatch, iterative steps, and completions in real time."),
                buttonRow(startBtn, stopBtn, clearBtn));
        return withOutput(north, out);
    }

    private static String formatEvent(ActivityEvent ev) {
        String agent = ev.agent == null || ev.agent.isEmpty() ? "" : " {" + ev.agent + "}";
        return "#" + ev.seq + " [" + ev.kind + "]" + agent + " " + ev.message;
    }

    // ------------------------------------------------------------------
    // Small parsing/layout utilities
    // ------------------------------------------------------------------

    private static JPanel buttonRow(Component... buttons) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        for (Component b : buttons) p.add(b);
        return p;
    }

    private static Double parseDoubleOrNull(String s) {
        if (s == null || s.isBlank()) return null;
        try { return Double.parseDouble(s.trim()); } catch (NumberFormatException e) { return null; }
    }

    private static int parseIntOr(String s, int fallback) {
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return fallback; }
    }

    private static void putIntIfPresent(Map<String, Object> m, String key, String text) {
        if (text == null || text.isBlank()) return;
        try { m.put(key, Integer.parseInt(text.trim())); } catch (NumberFormatException ignore) { }
    }
}
