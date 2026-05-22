package com.analyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Redaction;
import com.analyzer.engine.AnalysisEngine;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;
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
    private final JTabbedPane outer;
    private final JLabel statusLabel = new JLabel(" ");
    private final JProgressBar progressBar = new JProgressBar();
    private final JTable table;
    private final int findingsTabIndex;
    private final int targetTabIndex;

    public AnalyzerTab(MontoyaApi api, AnalysisEngine engine, HttpTrafficLog trafficLog) {
        super(new BorderLayout());
        this.api = api;
        this.engine = engine;
        this.palette = Palette.detect(api);
        setBackground(palette.background);
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        this.detailPanel = new FindingDetailPanel(api, palette);
        this.targetPanel = new TargetPanel(api, palette, this::startAnalysis);

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
        outer.addTab("Findings", findingsPane);
        findingsTabIndex = 1;
        outer.addTab("HTTP traffic", new HttpTrafficTab(api, trafficLog, palette));
        outer.addTab("About", buildAboutPanel());
        api.userInterface().applyThemeToComponent(outer);

        add(outer, BorderLayout.CENTER);
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
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createEmptyBorder(24, 32, 24, 32));
        p.setBackground(palette.panelBackground);

        JLabel title = new JLabel("Analyze Target");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));
        title.setForeground(palette.accent);
        p.add(title);
        p.add(Box.createVerticalStrut(8));
        p.add(line("Burp Suite extension for one-click reconnaissance and reporting.", palette.mutedForeground));
        p.add(Box.createVerticalStrut(16));
        p.add(line("How to use:", palette.foreground));
        p.add(line("  1. Right-click a request in Proxy / Repeater / Target → Extensions → Send to Analyze Target.", palette.foreground));
        p.add(line("  2. Switch to the Target tab to review (and optionally edit) the loaded request.", palette.foreground));
        p.add(line("  3. Click Run analysis. Findings stream into the Findings tab.", palette.foreground));
        p.add(line("  4. All plugin-generated traffic shows up under HTTP traffic for review.", palette.foreground));
        p.add(line("  5. Export HTML report… on the Findings tab saves a client deliverable.", palette.foreground));
        p.add(Box.createVerticalStrut(16));
        p.add(line("References: OWASP WSTG, PortSwigger Web Security Academy, OWASP Secure Headers Project.",
                palette.mutedForeground));
        return p;
    }

    private JLabel line(String text, java.awt.Color color) {
        JLabel l = new JLabel(text);
        l.setForeground(color);
        l.setAlignmentX(LEFT_ALIGNMENT);
        return l;
    }

    // ============================================================================================
    // Public API for the context menu and engine
    // ============================================================================================

    /** Called from the right-click context menu. Loads the request - does not run. */
    public void loadTarget(HttpRequest req, HttpResponse resp) {
        targetPanel.loadTarget(req, resp);
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
