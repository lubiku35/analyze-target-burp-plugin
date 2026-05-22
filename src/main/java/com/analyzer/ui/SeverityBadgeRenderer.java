package com.analyzer.ui;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;

/**
 * Pill-style severity cell. Background is the severity bucket colour from the Palette;
 * foreground matches that bucket; text is centred and slightly inset.
 */
public class SeverityBadgeRenderer extends DefaultTableCellRenderer {
    private final Palette palette;

    public SeverityBadgeRenderer(Palette palette) {
        this.palette = palette;
        setHorizontalAlignment(SwingConstants.CENTER);
        setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int column) {
        JLabel label = (JLabel) super.getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column);
        String text = value == null ? "" : value.toString();
        label.setText(text);
        if (isSelected) {
            label.setBackground(palette.rowSelectedBg);
            label.setForeground(palette.rowSelectedFg);
        } else {
            label.setBackground(palette.severityBg(text));
            label.setForeground(palette.severityFg(text));
        }
        label.setOpaque(true);
        return label;
    }

    /** Zebra-striping cell renderer for the rest of the table. */
    public static class ZebraRenderer extends DefaultTableCellRenderer {
        private final Palette palette;
        public ZebraRenderer(Palette palette) { this.palette = palette; }
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            // Match Swing's default alignment: numbers right-aligned, text left-aligned
            try {
                Class<?> cc = table.getColumnClass(column);
                setHorizontalAlignment(Number.class.isAssignableFrom(cc) ? RIGHT : LEFT);
            } catch (Exception ignored) {
                setHorizontalAlignment(LEFT);
            }
            if (isSelected) {
                c.setBackground(palette.rowSelectedBg);
                c.setForeground(palette.rowSelectedFg);
            } else {
                c.setBackground(row % 2 == 0 ? palette.rowEven : palette.rowOdd);
                c.setForeground(palette.foreground);
            }
            return c;
        }

        public Color background(int row) {
            return row % 2 == 0 ? palette.rowEven : palette.rowOdd;
        }
    }
}
