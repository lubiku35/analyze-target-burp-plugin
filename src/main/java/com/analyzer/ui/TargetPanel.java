package com.analyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.util.function.BiConsumer;

/**
 * "Target" sub-tab - the loaded request/response, with a Run button. Right-click → Send to Analyze
 * Target loads here but does not run; the user clicks Run when ready.
 *
 * The request editor is editable so the user can tweak the request (add a header, change a parameter)
 * before analysing - the engine receives whatever is in the editor at the moment Run is pressed.
 */
public class TargetPanel extends JPanel {
    private final MontoyaApi api;
    private final Palette palette;

    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JLabel targetLabel = new JLabel(" ");
    private final JButton runBtn = new JButton("Run analysis");
    private final JButton resetBtn = new JButton("Reset to last loaded");
    private final JButton clearBtn = new JButton("Clear target");
    private final JCheckBox passiveOnlyBox = new JCheckBox("Passive only");

    private HttpRequest originallyLoadedRequest;       // for the Reset button
    private HttpResponse loadedResponse;
    private final BiConsumer<HttpRequest, HttpResponse> onRun;

    public TargetPanel(MontoyaApi api, Palette palette, BiConsumer<HttpRequest, HttpResponse> onRun) {
        super(new BorderLayout());
        this.api = api;
        this.palette = palette;
        this.onRun = onRun;

        setBackground(palette.background);
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Editable request editor + read-only response editor (for context)
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.addTab("Request (editable)", requestEditor.uiComponent());
        editorTabs.addTab("Response (read-only)", responseEditor.uiComponent());
        api.userInterface().applyThemeToComponent(editorTabs);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildHeader(), editorTabs);
        split.setResizeWeight(0.0);
        split.setDividerLocation(80);
        split.setDividerSize(8);
        split.setBorder(BorderFactory.createEmptyBorder());

        add(split, BorderLayout.CENTER);
        refreshControls();
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout(8, 4));
        header.setOpaque(false);
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));

        JLabel title = new JLabel("Target");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        title.setForeground(palette.accent);
        header.add(title, BorderLayout.WEST);

        targetLabel.setForeground(palette.mutedForeground);
        targetLabel.setFont(targetLabel.getFont().deriveFont(Font.PLAIN, 12f));
        targetLabel.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));
        header.add(targetLabel, BorderLayout.CENTER);

        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        bar.setOpaque(false);
        bar.add(runBtn);
        bar.add(Box.createHorizontalStrut(4));
        bar.add(resetBtn);
        bar.add(Box.createHorizontalStrut(4));
        bar.add(clearBtn);
        bar.add(Box.createHorizontalStrut(12));
        passiveOnlyBox.setOpaque(false);
        passiveOnlyBox.setForeground(palette.foreground);
        passiveOnlyBox.setToolTipText(
                "<html>Run only read-only checks that never send extra HTTP traffic.<br>"
                        + "Skips active probes (CORS, host-header, HTTP methods, sensitive paths),<br>"
                        + "the TLS connection, and follow-up fetches (JS grep, robots/sitemap).<br>"
                        + "Safe to use against production without an engagement scope.</html>");
        bar.add(passiveOnlyBox);

        runBtn.addActionListener(e -> doRun());
        resetBtn.addActionListener(e -> resetEditor());
        clearBtn.addActionListener(e -> clear());

        header.add(bar, BorderLayout.EAST);
        header.setPreferredSize(new Dimension(800, 64));
        return header;
    }

    /** Load (but do not run) a new target. Called from the right-click context menu. */
    public void loadTarget(HttpRequest req, HttpResponse resp) {
        SwingUtilities.invokeLater(() -> {
            this.originallyLoadedRequest = req;
            this.loadedResponse = resp;
            requestEditor.setRequest(req);
            responseEditor.setResponse(resp);
            refreshControls();
        });
    }

    public void clear() {
        SwingUtilities.invokeLater(() -> {
            originallyLoadedRequest = null;
            loadedResponse = null;
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            refreshControls();
        });
    }

    private void resetEditor() {
        if (originallyLoadedRequest == null) return;
        requestEditor.setRequest(originallyLoadedRequest);
    }

    /** Disable Run unless a request is loaded. */
    private void refreshControls() {
        boolean has = originallyLoadedRequest != null;
        runBtn.setEnabled(has);
        resetBtn.setEnabled(has);
        clearBtn.setEnabled(has);
        if (has) {
            String url = originallyLoadedRequest.url();
            String method = originallyLoadedRequest.method();
            targetLabel.setText("Loaded: " + method + " " + url
                    + (loadedResponse != null ? "  (HTTP " + loadedResponse.statusCode() + ")" : "  (no response)"));
        } else {
            targetLabel.setText("No target loaded. Right-click any request → Extensions → Send to Analyze Target.");
        }
    }

    private void doRun() {
        HttpRequest current = requestEditor.getRequest();
        if (current == null) {
            api.logging().logToError("[analyze-target] cannot run: editor returned null request");
            return;
        }
        runBtn.setEnabled(false);
        onRun.accept(current, loadedResponse);
    }

    /** True if the user asked to run read-only checks only (no extra traffic). */
    public boolean isPassiveOnly() {
        return passiveOnlyBox.isSelected();
    }

    /** Re-enable the Run button when the engine signals completion. */
    public void onAnalysisComplete() {
        SwingUtilities.invokeLater(() -> runBtn.setEnabled(originallyLoadedRequest != null));
    }
}
