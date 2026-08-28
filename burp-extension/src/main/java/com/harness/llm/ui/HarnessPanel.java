package com.harness.llm.ui;

import com.harness.llm.HarnessClient;
import com.harness.llm.model.AnalysisModels.AgentReport;
import com.harness.llm.model.AnalysisModels.AnalysisResponse;
import com.harness.llm.model.AnalysisModels.Finding;
import com.harness.llm.model.AnalysisModels.TestPlan;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.function.Supplier;
import java.util.function.Consumer;

/**
 * The "LLM Harness" suite tab. Purely presentational: LlmHarnessExtension
 * owns the HarnessClient and pushes results in via addResult(). This class
 * doesn't make network calls itself, so it stays testable/reusable outside
 * a live Burp instance if needed.
 */
public class HarnessPanel extends JPanel {

    public record ResultEntry(String label, AnalysisResponse response, String error) {}

    private final DefaultListModel<ResultEntry> listModel = new DefaultListModel<>();
    private final JList<ResultEntry> resultList = new JList<>(listModel);
    private final JTextArea detailArea = new JTextArea();
    private final JTextField baseUrlField = new JTextField("http://localhost:8787", 24);
    private final JLabel statusLabel = new JLabel("Not connected");
    private final JCheckBox rediscoveryCheckbox = new JCheckBox("Attempt rediscovery of known vulnerabilities");
    private Consumer<TestPlan> planExecutor = plan -> {};

    public HarnessPanel(Supplier<Boolean> onTestConnection) {
        setLayout(new BorderLayout());

        // --- top bar: connection config ---
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topBar.add(new JLabel("Harness URL:"));
        topBar.add(baseUrlField);
        JButton testBtn = new JButton("Test Connection");
        testBtn.addActionListener(e -> {
            boolean ok = onTestConnection.get();
            statusLabel.setText(ok ? "Connected" : "Unreachable");
            statusLabel.setForeground(ok ? new Color(0, 128, 0) : Color.RED);
        });
        topBar.add(testBtn);
        topBar.add(statusLabel);
        JButton saveReportBtn = new JButton("Save Report");
        saveReportBtn.addActionListener(e -> saveReport());
        topBar.add(saveReportBtn);
        rediscoveryCheckbox.setToolTipText("When a known vulnerability is confirmed via the GitHub "
                + "Advisory Database, also spend an extra model call trying to independently corroborate "
                + "it against this specific exchange. Off by default -- a confirmed match doesn't need "
                + "re-deriving.");
        topBar.add(rediscoveryCheckbox);
        add(topBar, BorderLayout.NORTH);

        // --- main split: exchange list | detail view ---
        resultList.setCellRenderer(new ResultCellRenderer());
        resultList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showDetail(resultList.getSelectedValue());
        });
        JScrollPane listScroll = new JScrollPane(resultList);
        listScroll.setPreferredSize(new Dimension(320, 400));

        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, listScroll, detailScroll);
        split.setDividerLocation(320);
        add(split, BorderLayout.CENTER);

        // Proposed validation plans are intentionally analyst-triggered.
        // The button never appears as "confirm" because a plan is not evidence.
        JPanel planBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton executePlan = new JButton("Execute selected test plan");
        executePlan.setToolTipText("Runs only an approved, declarative validation plan; the LLM cannot supply an arbitrary command or URL.");
        executePlan.addActionListener(e -> {
            ResultEntry entry = resultList.getSelectedValue();
            if (entry == null || entry.response() == null || entry.response().test_plans == null || entry.response().test_plans.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Select an analysis result containing a proposed test plan.");
                return;
            }
            TestPlan selected = choosePlan(entry.response().test_plans);
            if (selected != null) {
                int answer = JOptionPane.showConfirmDialog(this,
                        "Execute capability '" + selected.capability + "' against the captured request?\n\n"
                                + "This may generate active traffic. The plan does not grant the LLM arbitrary request or shell access.",
                        "Approve Security Test", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (answer == JOptionPane.YES_OPTION) planExecutor.accept(selected);
            }
        });
        planBar.add(executePlan);
        add(planBar, BorderLayout.SOUTH);
    }

    public void setPlanExecutor(Consumer<TestPlan> executor) {
        this.planExecutor = executor == null ? plan -> {} : executor;
    }

    private TestPlan choosePlan(List<TestPlan> plans) {
        String[] labels = plans.stream().map(p -> p.capability + " [" + p.execution_plane + "]").toArray(String[]::new);
        int idx = JOptionPane.showOptionDialog(this, "Choose a proposed validation:", "Validation plan",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, labels, labels[0]);
        return idx >= 0 ? plans.get(idx) : null;
    }

    public String getBaseUrl() {
        return baseUrlField.getText().trim();
    }

    public boolean getAttemptRediscovery() {
        return rediscoveryCheckbox.isSelected();
    }

    /** Called from the Swing event thread by the extension after an analysis completes. */
    public void addSuccess(String label, AnalysisResponse response) {
        listModel.addElement(new ResultEntry(label, response, null));
        resultList.setSelectedIndex(listModel.size() - 1);
    }

    public void addFailure(String label, String error) {
        listModel.addElement(new ResultEntry(label, null, error));
        resultList.setSelectedIndex(listModel.size() - 1);
    }

    /**
     * Writes every result currently in the list to a single Markdown
     * report -- the baseline output format every comparable tool (Strix,
     * Xalgorix, PentAGI) produces and this extension previously lacked.
     * Rejected findings are already gone by the time results reach here
     * (the critique pass removes them before the extension ever sees
     * them), so nothing filtered-out shows up in the export.
     */
    private void saveReport() {
        if (listModel.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No results to export yet.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("llm-harness-report.md"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        StringBuilder sb = new StringBuilder();
        sb.append("# LLM Harness Report\n\n");
        sb.append("Generated ").append(java.time.Instant.now()).append("\n\n");

        int total = 0, critical = 0, high = 0;
        for (int i = 0; i < listModel.size(); i++) {
            ResultEntry e = listModel.get(i);
            if (e.error() != null) continue;
            for (AgentReport ar : e.response().agent_reports) {
                if (ar.findings == null) continue;
                for (Finding f : ar.findings) {
                    total++;
                    if ("critical".equals(f.severity)) critical++;
                    if ("high".equals(f.severity)) high++;
                }
            }
        }
        sb.append(String.format("**%d findings** (%d critical, %d high) across %d analyzed exchange(s).%n%n",
                total, critical, high, listModel.size()));

        for (int i = 0; i < listModel.size(); i++) {
            ResultEntry e = listModel.get(i);
            sb.append("## ").append(e.label()).append("\n\n");
            if (e.error() != null) {
                sb.append("**Error:** ").append(e.error()).append("\n\n");
                continue;
            }
            AnalysisResponse r = e.response();
            sb.append("_").append(r.summary).append("_\n\n");
            for (AgentReport ar : r.agent_reports) {
                if (ar.raw_error != null) {
                    sb.append("- **").append(ar.agent).append("**: error -- ").append(ar.raw_error).append('\n');
                    continue;
                }
                if (ar.findings == null || ar.findings.isEmpty()) continue;
                for (Finding f : ar.findings) {
                    sb.append(String.format("- **[%s] %s** (severity: %s, confidence: %.2f, confirmed: %s, basis: %s%s)%n",
                            ar.agent, f.vulnerability_class, f.severity, f.confidence, f.confirmed, f.basis,
                            f.owasp_category != null ? ", " + f.owasp_category : ""));
                    sb.append("  - Summary: ").append(f.summary).append('\n');
                    sb.append("  - Evidence: ").append(f.evidence).append('\n');
                    sb.append("  - Next step: ").append(f.suggested_test).append('\n');
                    sb.append("  - Verification status: ").append(f.confirmed ? "CONFIRMED" : "HYPOTHESIS / NOT CONFIRMED")
                      .append('\n');
                    if (f.review_verdict != null) {
                        sb.append("  - Reviewed: ").append(f.review_verdict)
                          .append(" -- ").append(f.review_note).append('\n');
                    }
                }
            }
            sb.append('\n');
        }

        try (java.io.FileWriter w = new java.io.FileWriter(chooser.getSelectedFile())) {
            w.write(sb.toString());
            JOptionPane.showMessageDialog(this, "Report saved to " + chooser.getSelectedFile());
        } catch (java.io.IOException ex) {
            JOptionPane.showMessageDialog(this, "Failed to save report: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showDetail(ResultEntry entry) {
        if (entry == null) {
            detailArea.setText("");
            return;
        }
        if (entry.error() != null) {
            detailArea.setText("ERROR\n=====\n" + entry.error());
            return;
        }
        AnalysisResponse r = entry.response();
        StringBuilder sb = new StringBuilder();
        sb.append("Coordinator model: ").append(r.coordinator_model).append('\n');
        sb.append("Dispatched agents: ").append(String.join(", ", r.dispatched_agents)).append('\n');
        sb.append('\n').append(r.summary).append("\n\n");
        sb.append("================\n");

        List<AgentReport> reports = r.agent_reports;
        if (reports == null || reports.isEmpty()) {
            sb.append("(no agent reports)\n");
        }
        for (AgentReport ar : reports) {
            sb.append("\n[").append(ar.agent).append("] model=").append(ar.model).append('\n');
            if (ar.raw_error != null) {
                sb.append("  ERROR: ").append(ar.raw_error).append('\n');
                continue;
            }
            if (ar.findings == null || ar.findings.isEmpty()) {
                sb.append("  (no findings)\n");
                continue;
            }
            for (Finding f : ar.findings) {
                sb.append(String.format("  - [%s] severity=%s confidence=%.2f basis=%s%s%n",
                        f.vulnerability_class, f.severity, f.confidence, f.basis,
                        f.owasp_category != null ? " owasp=" + f.owasp_category : ""));
                sb.append("    summary: ").append(f.summary).append('\n');
                sb.append("    evidence: ").append(f.evidence).append('\n');
                sb.append("    next step: ").append(f.suggested_test).append('\n');
                if (f.review_verdict != null) {
                    sb.append(String.format("    reviewed: %s (was %.2f -> %.2f) -- %s%n",
                            f.review_verdict,
                            f.original_confidence != null ? f.original_confidence : f.confidence,
                            f.confidence, f.review_note));
                }
            }
        }
        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    private static class ResultCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                        boolean isSelected, boolean cellHasFocus) {
            JLabel label = (JLabel) super.getListCellRendererComponent(
                    list, value, index, isSelected, cellHasFocus);
            if (value instanceof ResultEntry entry) {
                if (entry.error() != null) {
                    label.setText("\u26A0 " + entry.label());
                    if (!isSelected) label.setForeground(Color.RED);
                } else {
                    int n = entry.response().agent_reports.stream()
                            .mapToInt(ar -> ar.findings == null ? 0 : ar.findings.size())
                            .sum();
                    label.setText(String.format("[%d] %s", n, entry.label()));
                }
            }
            return label;
        }
    }
}
