package com.harness.llm.ui;

import com.harness.llm.HarnessClient;
import com.harness.llm.model.AnalysisModels.EstimateRequest;
import com.harness.llm.model.AnalysisModels.EstimateResponse;
import com.harness.llm.model.AnalysisModels.UrlEstimateItem;
import com.harness.llm.surface.PathScorer;
import com.harness.llm.surface.PathScorer.ScoredPath;
import com.harness.llm.surface.PathScorer.Tier;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * "Attack Surface Map" tab: scores every request Burp has seen (Proxy
 * history / Target site map, supplied by the extension via the
 * siteMapSupplier) with the local, no-network-call PathScorer, and shows
 * them sorted highest-score-first so the analyst can see where to spend
 * limited attention before running any agent at all.
 *
 * This tab intentionally does NOT call the LLM harness to build the map
 * itself -- scoring hundreds of endpoints through an LLM would be slow
 * and mostly redundant with cheap pattern matching. The harness is one
 * right-click away ("Send to LLM Harness") once the analyst has picked
 * promising candidates off this list.
 */
public class AttackSurfacePanel extends JPanel {

    /**
     * @param handle opaque back-reference to the originating Burp
     *               HttpRequestResponse, so "send to harness" can recover
     *               the full request/response after the analyst picks a
     *               row off the ranked list (the map itself only needs
     *               method/url/params, not the full bodies).
     */
    public record SiteMapRow(String method, String url, List<String> paramNames, Object handle) {}

    private final PathScorer scorer = new PathScorer();
    private final ScoredTableModel tableModel = new ScoredTableModel();
    private final JTable table = new JTable(tableModel);
    private final JLabel countLabel = new JLabel("No scan run yet");
    private final JComboBox<String> tierFilter =
            new JComboBox<>(new String[]{"All tiers", "CRITICAL", "HIGH", "MEDIUM", "LOW"});
    private List<SiteMapRow> sourceRows = List.of();
    private List<ScoredPath> lastScored = List.of();
    private final HarnessClient client;

    public AttackSurfacePanel(Supplier<List<SiteMapRow>> siteMapSupplier,
                               Consumer<Object> onSendToHarness,
                               HarnessClient client) {
        this.client = client;
        setLayout(new BorderLayout());

        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton scanBtn = new JButton("Scan Site Map");
        scanBtn.addActionListener(e -> runScan(siteMapSupplier));
        topBar.add(scanBtn);
        topBar.add(new JLabel("Filter:"));
        tierFilter.addActionListener(e -> applyTierFilter());
        topBar.add(tierFilter);
        topBar.add(countLabel);
        add(topBar, BorderLayout.NORTH);

        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoCreateRowSorter(false);
        TableRowSorter<ScoredTableModel> sorter = new TableRowSorter<>(tableModel);
        // Default sort: highest score first, so the "most promising"
        // parts of the map are simply the top rows -- no separate
        // visualization needed for that to read as a ranked map.
        sorter.setSortKeys(List.of(new javax.swing.RowSorter.SortKey(
                1, javax.swing.SortOrder.DESCENDING)));
        table.setRowSorter(sorter);
        table.getColumnModel().getColumn(0).setPreferredWidth(80);  // tier
        table.getColumnModel().getColumn(1).setPreferredWidth(60);  // score
        table.getColumnModel().getColumn(2).setPreferredWidth(110); // category
        table.getColumnModel().getColumn(3).setPreferredWidth(60);  // method
        table.getColumnModel().getColumn(4).setPreferredWidth(320); // url
        table.getColumnModel().getColumn(5).setPreferredWidth(320); // reasons
        table.setDefaultRenderer(Object.class, new TierRowRenderer());

        JScrollPane scroll = new JScrollPane(table);
        add(scroll, BorderLayout.CENTER);

        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton estimateBtn = new JButton("Estimate Assessment Cost");
        estimateBtn.setToolTipText("Projects total token spend for running the full harness across every "
                + "scanned URL, using PathScorer's tier as a risk prior. Calibrates against real usage once "
                + "at least one exchange has actually been sent through the harness this session.");
        estimateBtn.addActionListener(e -> runEstimate());
        bottomBar.add(estimateBtn);
        JButton sendBtn = new JButton("Send selected to LLM Harness");
        sendBtn.addActionListener(e -> {
            int[] viewRows = table.getSelectedRows();
            for (int viewRow : viewRows) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                if (modelRow >= 0 && modelRow < sourceRows.size()) {
                    onSendToHarness.accept(sourceRows.get(modelRow).handle());
                }
            }
        });
        bottomBar.add(sendBtn);
        add(bottomBar, BorderLayout.SOUTH);
    }

    /**
     * Calls the harness's POST /estimate (see HarnessClient.estimate,
     * harness/effort.py) using every currently-scanned row's PathScorer
     * score as its risk_score -- exactly the "estimator available upon
     * request once spidering and first walkthrough done" flow: "Scan
     * Site Map" is the spidering-review step, this button is the
     * on-request estimate. Blocks the EDT briefly like the existing
     * "Test Connection" button in HarnessPanel does -- this is a single
     * local HTTP call with no LLM inference in the loop (see server.py's
     * /estimate handler), so it's fast; if that stops being true this
     * should move to a SwingWorker like plan execution does.
     */
    private void runEstimate() {
        if (lastScored.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Run \"Scan Site Map\" first -- nothing to estimate yet.",
                    "Estimate Assessment Cost", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        List<UrlEstimateItem> items = new ArrayList<>();
        for (ScoredPath s : lastScored) {
            UrlEstimateItem item = new UrlEstimateItem();
            item.url = s.url();
            item.risk_score = s.score();
            item.category = "none".equals(s.category()) ? null : s.category();
            items.add(item);
        }
        EstimateRequest req = new EstimateRequest();
        req.urls = items;

        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        try {
            EstimateResponse resp = client.estimate(req);
            String calibration = resp.calibrated_from_real_calls
                    ? "calibrated from real token usage observed this session"
                    : "based on unmeasured priors -- send at least one exchange through the harness first for a calibrated number";
            String message = String.format(Locale.ROOT,
                    "%d URLs (%d high-risk, %d unscored)%n" +
                    "Estimated total: ~%,d tokens (%s)%n%n" +
                    "Breakdown:%n" +
                    "  routing:            %,d%n" +
                    "  agent dispatch:     %,d%n" +
                    "  critique:           %,d%n" +
                    "  validation retries: %,d%n" +
                    "  escalation:         %,d",
                    resp.urls_total, resp.urls_high_risk, resp.urls_unscored,
                    resp.estimated_total_tokens, calibration,
                    resp.breakdown.getOrDefault("routing", 0L),
                    resp.breakdown.getOrDefault("agent_dispatch", 0L),
                    resp.breakdown.getOrDefault("critique", 0L),
                    resp.breakdown.getOrDefault("validation_retries", 0L),
                    resp.breakdown.getOrDefault("escalation", 0L));
            JOptionPane.showMessageDialog(this, message, "Estimate Assessment Cost", JOptionPane.INFORMATION_MESSAGE);
        } catch (HarnessClient.HarnessException ex) {
            JOptionPane.showMessageDialog(this, "Could not get an estimate: " + ex.getMessage(),
                    "Estimate Assessment Cost", JOptionPane.ERROR_MESSAGE);
        } finally {
            setCursor(Cursor.getDefaultCursor());
        }
    }

    private void runScan(Supplier<List<SiteMapRow>> siteMapSupplier) {
        List<SiteMapRow> rows = siteMapSupplier.get();
        this.sourceRows = rows;
        List<ScoredPath> scored = rows.stream()
                .map(r -> scorer.score(r.method(), r.url(), r.paramNames()))
                .toList();
        this.lastScored = scored;
        tableModel.setData(scored);
        long critical = scored.stream().filter(s -> s.tier() == Tier.CRITICAL).count();
        long high = scored.stream().filter(s -> s.tier() == Tier.HIGH).count();
        countLabel.setText(String.format(
                "%d endpoints scanned  |  %d critical, %d high", scored.size(), critical, high));
    }

    private void applyTierFilter() {
        String selected = (String) tierFilter.getSelectedItem();
        @SuppressWarnings("unchecked")
        TableRowSorter<ScoredTableModel> sorter = (TableRowSorter<ScoredTableModel>) table.getRowSorter();
        if (selected == null || selected.equals("All tiers")) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(javax.swing.RowFilter.regexFilter("^" + selected + "$", 0));
        }
    }

    private static class ScoredTableModel extends AbstractTableModel {
        private final String[] columns = {"Tier", "Score", "Category", "Method", "URL", "Why it's interesting"};
        private List<ScoredPath> data = List.of();

        void setData(List<ScoredPath> data) {
            this.data = data;
            fireTableDataChanged();
        }

        ScoredPath rowAt(int modelRow) {
            return data.get(modelRow);
        }

        @Override
        public int getRowCount() { return data.size(); }

        @Override
        public int getColumnCount() { return columns.length; }

        @Override
        public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col) {
            ScoredPath s = data.get(row);
            return switch (col) {
                case 0 -> s.tier().name();
                case 1 -> String.format("%.2f", s.score());
                case 2 -> s.category();
                case 3 -> s.method();
                case 4 -> s.url();
                case 5 -> String.join("; ", s.reasons());
                default -> "";
            };
        }
    }

    private static class TierRowRenderer extends javax.swing.table.DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                         boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            if (!isSelected) {
                String tier = (String) table.getModel().getValueAt(table.convertRowIndexToModel(row), 0);
                c.setBackground(switch (tier) {
                    case "CRITICAL" -> new Color(255, 205, 210);
                    case "HIGH" -> new Color(255, 236, 179);
                    case "MEDIUM" -> new Color(255, 249, 196);
                    default -> Color.WHITE;
                });
            }
            return c;
        }
    }
}
