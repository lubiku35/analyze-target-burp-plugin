package com.analyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Redaction;
import com.analyzer.engine.AnalysisEngine;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;
import com.analyzer.persistence.StateStore;
import com.analyzer.report.HtmlReportWriter;
import com.analyzer.traffic.HttpTrafficLog;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Root component for the Analyze Target suite tab. Tabs: Target | Findings | HTTP traffic | About.
 *
 * Workflow: right-click → "Send to Analyze Target" calls {@link #loadTarget} (no run).
 * User switches to the Target tab and clicks Run; findings stream into the Findings tab and
 * every plugin-sent request appears in HTTP traffic.
 */
public class AnalyzerTab extends JPanel {
    private final MontoyaApi api;
    private final AnalysisEngine engine;
    private final Palette palette;
    private final FindingsTableModel model = new FindingsTableModel();
    private final FindingDetailPanel detailPanel;
    private final TargetPanel targetPanel;
    private final SummaryPanel summaryPanel;
    private final JTabbedPane outer;
    private final JLabel statusLabel = new JLabel(" ");
    private final JProgressBar progressBar = new JProgressBar();
    private final JTable table;
    private final int findingsTabIndex;
    private final int targetTabIndex;
    private final StateStore stateStore;
    private HttpRequest currentTargetRequest;   // for SummaryPanel context on completion

    public AnalyzerTab(MontoyaApi api, AnalysisEngine engine, HttpTrafficLog trafficLog) {
        super(new BorderLayout());
        this.api = api;
        this.engine = engine;
        this.palette = Palette.detect(api);
        setBackground(palette.background);
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        this.detailPanel = new FindingDetailPanel(api, palette);
        this.targetPanel = new TargetPanel(api, palette, this::startAnalysis);
        this.summaryPanel = new SummaryPanel(api, palette);
        this.stateStore = new StateStore(api);

        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.setRowHeight(24);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        table.getTableHeader().setReorderingAllowed(false);

        SeverityBadgeRenderer.ZebraRenderer zebra = new SeverityBadgeRenderer.ZebraRenderer(palette);
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(zebra);
        }
        table.getColumnModel().getColumn(2).setCellRenderer(new SeverityBadgeRenderer(palette));

        TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(model);
        sorter.setComparator(2, (a, b) -> {
            Severity sa = Severity.valueOf(((String) a).toUpperCase());
            Severity sb = Severity.valueOf(((String) b).toUpperCase());
            return Integer.compare(sa.ordinal(), sb.ordinal());
        });
        table.setRowSorter(sorter);
        sizeColumns();

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                detailPanel.showFinding(null);
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            detailPanel.showFinding(model.getFinding(modelRow));
        });

        // ---- Findings pane ----
        JPanel findingsPane = new JPanel(new BorderLayout());
        findingsPane.setOpaque(false);
        findingsPane.add(buildFindingsToolbar(), BorderLayout.NORTH);

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createLineBorder(palette.border));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailPanel);
        split.setResizeWeight(0.45);
        split.setDividerLocation(320);
        // Make the divider thicker so the resize-cursor target is easy to grab; one-touch arrows give
        // users a single-click way to collapse either pane.
        split.setDividerSize(8);
        split.setOneTouchExpandable(true);
        split.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
        findingsPane.add(split, BorderLayout.CENTER);

        // Status bar
        JPanel status = new JPanel(new BorderLayout());
        status.setOpaque(false);
        status.setBorder(BorderFactory.createEmptyBorder(6, 4, 0, 4));
        statusLabel.setForeground(palette.mutedForeground);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        statusLabel.setText("Idle. Right-click any request → Extensions → Send to Analyze Target.");
        status.add(statusLabel, BorderLayout.WEST);

        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(220, 16));
        progressBar.setVisible(false);
        status.add(progressBar, BorderLayout.EAST);

        findingsPane.add(status, BorderLayout.SOUTH);

        // ---- Outer tab container: Target | Findings | HTTP traffic | About ----
        outer = new JTabbedPane();
        outer.addTab("Target", targetPanel);
        targetTabIndex = 0;
        outer.addTab("Summary", summaryPanel);
        outer.addTab("Findings", findingsPane);
        findingsTabIndex = 2;
        outer.addTab("HTTP traffic", new HttpTrafficTab(api, trafficLog, palette));
        outer.addTab("About", buildAboutPanel());
        api.userInterface().applyThemeToComponent(outer);

        add(outer, BorderLayout.CENTER);

        // Restore any state from the current Burp project (no-op if there's nothing or if the
        // project is in memory only).
        restorePersistedState();
    }

    private void restorePersistedState() {
        try {
            StateStore.Restored r = stateStore.restore();
            if (r.target() != null) {
                this.currentTargetRequest = r.target();
                targetPanel.loadTarget(r.target(), r.targetResponse());
            }
            if (!r.findings().isEmpty()) {
                for (Finding f : r.findings()) model.addFinding(f);
                summaryPanel.updateSummary(r.target(), r.findings());
                setStatus("Restored " + r.findings().size() + " finding(s) from the saved Burp project.");
            }
        } catch (Exception e) {
            api.logging().logToError("[analyze-target] state restore failed: " + e);
        }
    }

    private void sizeColumns() {
        int[] widths = {40, 80, 90, 90, 140, 380, 360};
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            TableColumn col = table.getColumnModel().getColumn(i);
            col.setPreferredWidth(widths[i]);
        }
    }

    private JToolBar buildFindingsToolbar() {
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        bar.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        bar.setOpaque(false);

        JLabel title = new JLabel("Findings");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        title.setForeground(palette.accent);
        title.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 12));
        bar.add(title);

        JButton clearBtn = new JButton("Clear findings");
        clearBtn.addActionListener(this::onClearFindings);
        bar.add(clearBtn);
        bar.add(Box.createHorizontalStrut(8));

        JButton exportBtn = new JButton("Export HTML report…");
        exportBtn.addActionListener(this::onExport);
        bar.add(exportBtn);

        bar.add(Box.createHorizontalGlue());

        JCheckBox redactBox = new JCheckBox("Redact auth headers", Redaction.enabled());
        redactBox.setToolTipText(
                "<html>When enabled, Authorization, Cookie, Set-Cookie, X-Api-Key and similar headers<br>"
                        + "are replaced with &lt;redacted&gt; in finding snippets and exported reports.<br>"
                        + "Recommended for client deliverables.</html>");
        redactBox.setOpaque(false);
        redactBox.setForeground(palette.foreground);
        redactBox.addActionListener(e -> Redaction.setEnabled(redactBox.isSelected()));
        bar.add(redactBox);

        return bar;
    }

    private JPanel buildAboutPanel() {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(palette.background);
        wrapper.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        javax.swing.JTextPane pane = new javax.swing.JTextPane();
        pane.setContentType("text/html");
        pane.setEditable(false);
        pane.setOpaque(true);
        pane.setBackground(palette.background);
        pane.setForeground(palette.foreground);
        pane.setBorder(BorderFactory.createEmptyBorder(20, 24, 20, 24));
        // Read-only — keep the default arrow cursor so users don't see an I-beam edge.
        pane.setCursor(java.awt.Cursor.getDefaultCursor());
        pane.addHyperlinkListener(e -> {
            if (e.getEventType() == javax.swing.event.HyperlinkEvent.EventType.ACTIVATED && e.getURL() != null) {
                try {
                    if (java.awt.Desktop.isDesktopSupported()) {
                        java.awt.Desktop.getDesktop().browse(java.net.URI.create(e.getURL().toString()));
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[analyze-target] failed to open link: " + ex);
                }
            }
        });

        String fg     = toHex(palette.foreground);
        String mut    = toHex(palette.mutedForeground);
        String acc    = toHex(palette.accent);
        String bg     = toHex(palette.background);
        String card   = toHex(palette.panelBackground);
        String border = toHex(palette.border);

        String html = "<html><head><style>"
                + "body{font-family:-apple-system,'SF Pro Text','Segoe UI',sans-serif;font-size:13px;"
                + "color:" + fg + ";background:" + bg + ";margin:0;padding:0;}"
                + "h1{color:" + acc + ";font-size:22px;margin:0 0 4px 0;}"
                + "h3{color:" + acc + ";font-size:11px;text-transform:uppercase;letter-spacing:0.6px;"
                + "margin:0 0 8px 0;font-weight:700;}"
                + ".tag{color:" + mut + ";font-size:12px;margin-bottom:18px;}"
                + ".card{background:" + card + ";border:1px solid " + border + ";"
                + "padding:14px 16px;margin-bottom:12px;}"
                + ".muted{color:" + mut + ";}"
                + "a{color:" + acc + ";text-decoration:none;}"
                + "a:hover{text-decoration:underline;}"
                + "ol{margin:4px 0 0 18px;padding:0;}"
                + "li{margin:4px 0;}"
                + "</style></head><body>"
                + "<h1>Analyze Target</h1>"
                + "<div class='tag'>Burp Suite extension for one-click reconnaissance and reporting.</div>"

                + "<div class='card'>"
                + "<h3>Author</h3>"
                + "<div><b>lubiku35</b> &nbsp;·&nbsp; "
                + "<a href='https://github.com/lubiku35'>github.com/lubiku35</a></div>"
                + "<div class='muted' style='margin-top:6px;'>"
                + "Plugin hosted at <a href='https://github.com/lubiku35'>github.com/lubiku35</a>. "
                + "Pull requests and ideas are welcome."
                + "</div>"
                + "</div>"

                + "<div class='card'>"
                + "<h3>How to use</h3>"
                + "<ol>"
                + "<li>Right-click a request in Proxy / Repeater / Target → Extensions → "
                + "<b>Send to Analyze Target</b>.</li>"
                + "<li>Switch to the <b>Target</b> tab to review (and optionally edit) the loaded "
                + "request.</li>"
                + "<li>Click <b>Run analysis</b>. Findings stream into the <b>Findings</b> tab; the "
                + "<b>Summary</b> tab synthesises everything once the run completes.</li>"
                + "<li>All plugin-generated traffic shows up under <b>HTTP traffic</b> for review.</li>"
                + "<li><b>Export HTML report…</b> on the Findings tab saves a client deliverable.</li>"
                + "</ol>"
                + "</div>"

                + "<div class='card'>"
                + "<h3>References</h3>"
                + "<div>"
                + "<a href='https://owasp.org/www-project-web-security-testing-guide/'>OWASP Web Security Testing Guide</a> · "
                + "<a href='https://cheatsheetseries.owasp.org/'>OWASP Cheat Sheet Series</a> · "
                + "<a href='https://owasp.org/www-project-secure-headers/'>OWASP Secure Headers Project</a> · "
                + "<a href='https://portswigger.net/web-security'>PortSwigger Web Security Academy</a>"
                + "</div>"
                + "</div>"

                + "</body></html>";
        pane.setText(html);
        pane.setCaretPosition(0);

        javax.swing.JScrollPane scroll = new javax.swing.JScrollPane(pane,
                javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(palette.background);
        wrapper.add(scroll, BorderLayout.CENTER);
        return wrapper;
    }

    private static String toHex(java.awt.Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    // ============================================================================================
    // Public API for the context menu and engine
    // ============================================================================================

    /** Called from the right-click context menu. Loads the request - does not run. */
    public void loadTarget(HttpRequest req, HttpResponse resp) {
        targetPanel.loadTarget(req, resp);
        this.currentTargetRequest = req;
        stateStore.saveTarget(req, resp);
        setStatus("Loaded target. Switch to the Target tab and click Run analysis.");
        // Switch to the Target tab so the user immediately sees what's loaded.
        SwingUtilities.invokeLater(() -> outer.setSelectedIndex(targetTabIndex));
    }

    public void addFinding(Finding f) {
        model.addFinding(f);
    }

    public void setStatus(String text) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(text));
    }

    // ============================================================================================
    // Internals
    // ============================================================================================

    private void startAnalysis(HttpRequest req, HttpResponse resp) {
        boolean passiveOnly = targetPanel.isPassiveOnly();
        this.currentTargetRequest = req;
        // Fresh run: clear prior results (including any findings restored from the saved project)
        // so re-running — or running after a restore — never stacks duplicates on top of the last run.
        model.clear();
        detailPanel.showFinding(null);
        summaryPanel.clear();
        setStatus("Analyzing " + req.url() + (passiveOnly ? " (passive only)" : "") + " - running checks…");
        // Auto-switch to Findings so the user sees results coming in.
        SwingUtilities.invokeLater(() -> {
            outer.setSelectedIndex(findingsTabIndex);
            progressBar.setVisible(true);
            progressBar.setIndeterminate(true);
            progressBar.setString("starting…");
        });

        engine.analyze(req, resp, passiveOnly,
                this::addFinding,
                this::setProgress,
                () -> {
                    setStatus("Analysis complete for " + req.url() + ".");
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setIndeterminate(false);
                        if (progressBar.getMaximum() > 0) progressBar.setValue(progressBar.getMaximum());
                        progressBar.setString("complete");
                    });
                    targetPanel.onAnalysisComplete();
                    // Refresh the Summary panel with everything we just collected.
                    List<Finding> snapshot = model.snapshot();
                    summaryPanel.updateSummary(req, snapshot);
                    // Persist findings so they survive a Burp restart (within a saved project).
                    stateStore.saveFindings(snapshot);
                });
    }

    private void setProgress(AnalysisEngine.Progress p) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setVisible(true);
            progressBar.setIndeterminate(false);
            progressBar.setMaximum(p.total());
            progressBar.setValue(p.completed());
            progressBar.setString(p.completed() + " / " + p.total() + " checks");
        });
    }

    private void onClearFindings(ActionEvent e) {
        model.clear();
        detailPanel.showFinding(null);
        summaryPanel.clear();
        stateStore.saveFindings(List.of());
        setStatus("Findings cleared.");
    }

    private void onExport(ActionEvent e) {
        if (model.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "No findings to export yet.",
                    "Analyze Target", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("analyze-target-report.html"));
        chooser.setFileFilter(new FileNameExtensionFilter("HTML report (*.html)", "html"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File target = chooser.getSelectedFile();
        if (!target.getName().toLowerCase().endsWith(".html")) {
            target = new File(target.getParentFile(), target.getName() + ".html");
        }
        try {
            String html = HtmlReportWriter.render(model.snapshot());
            Files.writeString(Path.of(target.toURI()), html);
            setStatus("Report exported: " + target.getAbsolutePath());
            api.logging().logToOutput("[analyze-target] report written to " + target);
        } catch (IOException ex) {
            api.logging().logToError("[analyze-target] failed to write report: " + ex);
            JOptionPane.showMessageDialog(this, "Failed to write report: " + ex.getMessage(),
                    "Analyze Target", JOptionPane.ERROR_MESSAGE);
        }
    }
}
