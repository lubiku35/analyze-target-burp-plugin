package com.analyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.analyzer.traffic.HttpTrafficEntry;
import com.analyzer.traffic.HttpTrafficLog;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Font;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * "HTTP traffic" tab - a Burp-history-style table of every HTTP request the plugin sent
 * during analysis. Click a row to see the underlying request/response in Burp's native editors.
 */
public class HttpTrafficTab extends JPanel {
    private final MontoyaApi api;
    private final Palette palette;
    private final TrafficTableModel model = new TrafficTableModel();
    private final JTable table;
    private final HttpRequestEditor reqEditor;
    private final HttpResponseEditor respEditor;
    private final JLabel statusLabel = new JLabel(" ");
    private final HttpTrafficLog log;

    public HttpTrafficTab(MontoyaApi api, HttpTrafficLog log, Palette palette) {
        super(new BorderLayout());
        this.api = api;
        this.log = log;
        this.palette = palette;
        setBackground(palette.background);

        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.setRowHeight(22);
        table.setShowGrid(false);
        table.setIntercellSpacing(new java.awt.Dimension(0, 0));
        table.getTableHeader().setReorderingAllowed(false);

        SeverityBadgeRenderer.ZebraRenderer zebra = new SeverityBadgeRenderer.ZebraRenderer(palette);
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(zebra);
        }

        TableRowSorter<TrafficTableModel> sorter = new TableRowSorter<>(model);
        sorter.setSortsOnUpdates(true);
        table.setRowSorter(sorter);
        sizeColumns();

        reqEditor  = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        respEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            HttpTrafficEntry entry = null;
            if (viewRow >= 0) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                entry = model.get(modelRow);
            }
            showEntry(entry);
        });

        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.addTab("Request", reqEditor.uiComponent());
        detailTabs.addTab("Response", respEditor.uiComponent());
        api.userInterface().applyThemeToComponent(detailTabs);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detailTabs);
        split.setResizeWeight(0.55);
        split.setDividerLocation(320);
        split.setDividerSize(8);
        split.setOneTouchExpandable(true);
        split.setBorder(BorderFactory.createEmptyBorder());

        // Toolbar with Clear button for the traffic log (independent from Findings clear)
        javax.swing.JToolBar trafficToolbar = new javax.swing.JToolBar();
        trafficToolbar.setFloatable(false);
        trafficToolbar.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        trafficToolbar.setOpaque(false);
        JLabel title = new JLabel("HTTP traffic");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        title.setForeground(palette.accent);
        title.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 12));
        trafficToolbar.add(title);
        javax.swing.JButton clearBtn = new javax.swing.JButton("Clear traffic");
        clearBtn.setToolTipText("Discard all recorded requests. Findings keep their attached request/response.");
        clearBtn.addActionListener(e -> log.clear());
        trafficToolbar.add(clearBtn);

        add(trafficToolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setBorder(BorderFactory.createEmptyBorder(4, 12, 6, 12));
        bottom.setOpaque(false);
        statusLabel.setForeground(palette.mutedForeground);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        bottom.add(statusLabel, BorderLayout.WEST);
        add(bottom, BorderLayout.SOUTH);

        log.addListener(entry -> SwingUtilities.invokeLater(() -> {
            model.add(entry);
            statusLabel.setText(model.getRowCount() + " request(s) recorded");
        }));
        log.addClearListener(() -> SwingUtilities.invokeLater(() -> {
            model.clear();
            statusLabel.setText("0 requests recorded");
            showEntry(null);
        }));
        statusLabel.setText("0 requests recorded");
    }

    private void sizeColumns() {
        int[] widths = {48, 110, 130, 60, 60, 70, 80, 360};
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            TableColumn col = table.getColumnModel().getColumn(i);
            col.setPreferredWidth(widths[i]);
        }
    }

    private void showEntry(HttpTrafficEntry entry) {
        if (entry == null) {
            reqEditor.setRequest(null);
            respEditor.setResponse(null);
            return;
        }
        try {
            HttpRequest r = entry.request();
            if (r != null) reqEditor.setRequest(r); else reqEditor.setRequest(null);
        } catch (Exception ignored) {
            reqEditor.setRequest(null);
        }
        try {
            HttpResponse resp = entry.response();
            if (resp != null) {
                respEditor.setResponse(resp);
            } else if (entry.errored()) {
                // Synthetic 599 (non-standard "network error") so Burp's editor parses it cleanly.
                respEditor.setResponse(HttpResponse.httpResponse(
                        ByteArray.byteArray("HTTP/1.1 599 Plugin Error\r\n\r\n" + entry.error())));
            } else {
                respEditor.setResponse(null);
            }
        } catch (Exception ignored) {
            respEditor.setResponse(null);
        }
    }

    // -- model -----------------------------------------------------------------

    private static final class TrafficTableModel extends AbstractTableModel {
        private static final String[] COLUMNS =
                {"#", "Time", "Check", "Method", "Status", "Length", "Time (ms)", "URL"};
        private static final DateTimeFormatter T_FMT =
                DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());
        private final List<HttpTrafficEntry> rows = new ArrayList<>();

        void add(HttpTrafficEntry e) {
            rows.add(e);
            fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
        }

        void clear() {
            int n = rows.size();
            if (n == 0) return;
            rows.clear();
            fireTableRowsDeleted(0, n - 1);
        }

        HttpTrafficEntry get(int row) {
            return row >= 0 && row < rows.size() ? rows.get(row) : null;
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int c) { return COLUMNS[c]; }
        @Override public Class<?> getColumnClass(int c) {
            return switch (c) {
                case 0, 4, 5, 6 -> Integer.class;
                default -> String.class;
            };
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            HttpTrafficEntry e = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> (int) e.sequence();
                case 1 -> T_FMT.format(e.timestamp());
                case 2 -> e.checkId();
                case 3 -> e.method();
                case 4 -> e.statusCode() < 0 ? -1 : e.statusCode();
                case 5 -> e.responseLength();
                case 6 -> (int) e.durationMillis();
                case 7 -> e.url();
                default -> "";
            };
        }
    }
}
