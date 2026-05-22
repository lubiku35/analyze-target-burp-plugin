package com.analyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.analyzer.model.Finding;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.event.HyperlinkEvent;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.net.URI;

/**
 * Right-hand pane on the Findings tab. Shows the selected finding's metadata, description,
 * remediation, evidence, and the raw request/response — using Burp's native editors when
 * available, falling back to plain text otherwise.
 */
public class FindingDetailPanel extends JPanel {
    private final MontoyaApi api;
    private final Palette palette;

    private final JLabel titleLabel = new JLabel(" ");
    private final JLabel metaLabel = new JLabel(" ");
    private final JTextPane descriptionPane = new JTextPane();
    private final JTextPane remediationPane = new JTextPane();
    private final JTextArea evidenceArea = new JTextArea();
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextPane referencesPane = new JTextPane();

    public FindingDetailPanel(MontoyaApi api, Palette palette) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.palette = palette;
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        setBackground(palette.panelBackground);

        // Header
        JPanel header = new JPanel(new GridBagLayout());
        header.setOpaque(false);
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = 0; c.weightx = 1.0; c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL; c.insets = new Insets(0, 0, 4, 0);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 15f));
        titleLabel.setForeground(palette.foreground);
        header.add(titleLabel, c);
        c.gridy = 1;
        metaLabel.setForeground(palette.mutedForeground);
        metaLabel.setFont(metaLabel.getFont().deriveFont(Font.PLAIN, 11f));
        header.add(metaLabel, c);
        add(header, BorderLayout.NORTH);

        // Tabs
        styleTextPane(descriptionPane);
        styleTextPane(remediationPane);
        descriptionPane.setContentType("text/plain");
        remediationPane.setContentType("text/plain");

        evidenceArea.setEditable(false);
        evidenceArea.setLineWrap(false);
        evidenceArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        evidenceArea.setBackground(palette.panelBackground);
        evidenceArea.setForeground(palette.foreground);

        styleTextPane(referencesPane);
        referencesPane.setContentType("text/html");
        referencesPane.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                try {
                    if (Desktop.isDesktopSupported() && e.getURL() != null) {
                        Desktop.getDesktop().browse(URI.create(e.getURL().toString()));
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[analyze-target] failed to open link: " + ex);
                }
            }
        });

        // Use Burp's native request/response editors. They render exactly like Repeater.
        this.requestEditor  = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Description", wrapScroll(descriptionPane));
        tabs.addTab("Remediation", wrapScroll(remediationPane));
        tabs.addTab("Evidence",    wrapScroll(evidenceArea));
        tabs.addTab("Request",     requestEditor.uiComponent());
        tabs.addTab("Response",    responseEditor.uiComponent());
        tabs.addTab("References",  wrapScroll(referencesPane));
        api.userInterface().applyThemeToComponent(tabs);

        add(tabs, BorderLayout.CENTER);
        showFinding(null);
    }

    private void styleTextPane(JTextPane p) {
        p.setEditable(false);
        p.setBackground(palette.panelBackground);
        p.setForeground(palette.foreground);
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
    }

    private static JScrollPane wrapScroll(java.awt.Component c) {
        JScrollPane sp = new JScrollPane(c,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.setPreferredSize(new Dimension(400, 200));
        return sp;
    }

    public void showFinding(Finding f) {
        if (f == null) {
            titleLabel.setText("Select a finding to view details");
            metaLabel.setText(" ");
            descriptionPane.setText("");
            remediationPane.setText("");
            evidenceArea.setText("");
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            referencesPane.setText("");
            return;
        }
        titleLabel.setText(f.title());
        metaLabel.setText(String.format("%s · %s · %s · %s",
                f.severity().label(), f.confidence().label(), f.checkId(), f.url()));
        descriptionPane.setText(f.description());
        descriptionPane.setCaretPosition(0);
        remediationPane.setText(f.remediation());
        remediationPane.setCaretPosition(0);
        evidenceArea.setText(f.evidence());
        evidenceArea.setCaretPosition(0);

        // Prefer the original Montoya HttpRequest/HttpResponse refs — Burp's editor renders them
        // in full, with proper highlighting and parser awareness. Only fall back to re-parsing the
        // textual snippet when the finding didn't attach the live objects.
        if (f.httpRequest() != null) {
            try {
                requestEditor.setRequest(f.httpRequest());
            } catch (Exception ignored) {
                requestEditor.setRequest(null);
            }
        } else if (!f.requestSnippet().isEmpty()) {
            try {
                requestEditor.setRequest(burp.api.montoya.http.message.requests.HttpRequest
                        .httpRequest(ByteArray.byteArray(f.requestSnippet())));
            } catch (Exception ignored) {
                requestEditor.setRequest(null);
            }
        } else {
            requestEditor.setRequest(null);
        }

        if (f.httpResponse() != null) {
            try {
                responseEditor.setResponse(f.httpResponse());
            } catch (Exception ignored) {
                responseEditor.setResponse(null);
            }
        } else if (!f.responseSnippet().isEmpty()) {
            try {
                responseEditor.setResponse(burp.api.montoya.http.message.responses.HttpResponse
                        .httpResponse(ByteArray.byteArray(f.responseSnippet())));
            } catch (Exception ignored) {
                responseEditor.setResponse(null);
            }
        } else {
            responseEditor.setResponse(null);
        }

        StringBuilder refs = new StringBuilder(
                "<html><head><style>body{font-family:sans-serif;font-size:12px;color:")
                .append(toHex(palette.foreground)).append(";background:")
                .append(toHex(palette.panelBackground)).append(";} a{color:")
                .append(toHex(palette.accent)).append(";}</style></head><body><ul>");
        if (f.references().isEmpty()) refs.append("<li><em>(no references)</em></li>");
        for (String r : f.references()) {
            String safe = safeHttpUrl(r);
            if (safe != null) {
                refs.append("<li><a href='").append(escape(safe)).append("'>")
                        .append(escape(r)).append("</a></li>");
            } else {
                refs.append("<li>").append(escape(r)).append("</li>");
            }
        }
        refs.append("</ul></body></html>");
        referencesPane.setText(refs.toString());
        referencesPane.setCaretPosition(0);
    }

    private static String toHex(java.awt.Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static String safeHttpUrl(String url) {
        if (url == null) return null;
        String trimmed = url.trim();
        try {
            java.net.URI u = java.net.URI.create(trimmed);
            String scheme = u.getScheme();
            if (scheme != null && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                return trimmed;
            }
        } catch (IllegalArgumentException ignored) {
        }
        return null;
    }
}
