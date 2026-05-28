package com.analyzer.ui;

import com.analyzer.model.Finding;

import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Findings table model. All mutations and reads must happen on the EDT - addFinding/clear
 * schedule their work via SwingUtilities.invokeLater. Worker threads call addFinding directly.
 *
 * <p>Identical findings are de-duplicated by a content signature, so a check that emits the same
 * finding twice — or a restore that overlaps a fresh run — can never produce duplicate rows.</p>
 */
public class FindingsTableModel extends AbstractTableModel {
    private static final String[] COLUMNS = {"#", "Time", "Severity", "Confidence", "Category", "Title", "URL"};
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final List<Finding> rows = new ArrayList<>();
    private final Set<String> signatures = new HashSet<>();

    public void addFinding(Finding f) {
        if (f == null) return;
        SwingUtilities.invokeLater(() -> {
            if (!signatures.add(signature(f))) return; // exact duplicate — skip
            rows.add(f);
            int idx = rows.size() - 1;
            fireTableRowsInserted(idx, idx);
        });
    }

    /** Content signature used to suppress duplicate rows. Findings that differ in any displayed
     *  field or in their evidence remain distinct. */
    private static String signature(Finding f) {
        return f.checkId() + "|#|" + f.severity() + "|#|" + f.title()
                + "|#|" + f.url() + "|#|" + f.evidence();
    }

    public void clear() {
        SwingUtilities.invokeLater(() -> {
            signatures.clear();
            int size = rows.size();
            if (size == 0) return;
            rows.clear();
            fireTableRowsDeleted(0, size - 1);
        });
    }

    public List<Finding> snapshot() {
        return new ArrayList<>(rows);
    }

    public Finding getFinding(int row) {
        if (row < 0 || row >= rows.size()) return null;
        return rows.get(row);
    }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int column) { return COLUMNS[column]; }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnIndex == 0 ? Integer.class : String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Finding f = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> rowIndex + 1;
            case 1 -> TIME_FMT.format(f.detectedAt());
            case 2 -> f.severity().label();
            case 3 -> f.confidence().label();
            case 4 -> f.checkId().contains(".")
                    ? f.checkId().substring(0, f.checkId().indexOf('.'))
                    : f.checkId();
            case 5 -> f.title();
            case 6 -> f.url();
            default -> "";
        };
    }
}
