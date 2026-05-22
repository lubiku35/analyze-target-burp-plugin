package com.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.analyzer.ui.AnalyzerTab;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Adds a "Send to Analyze Target" entry under Extensions in the right-click menu. Clicking it
 * loads the selected request into the Target tab — it does NOT auto-run. The user clicks
 * "Run analysis" on the Target tab when ready.
 */
public class AnalyzeContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final AnalyzerTab tab;

    public AnalyzeContextMenuProvider(MontoyaApi api, AnalyzerTab tab) {
        this.api = api;
        this.tab = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Optional<HttpRequestResponse> selected = pickRequestResponse(event);
        if (selected.isEmpty()) return Collections.emptyList();

        HttpRequestResponse rr = selected.get();
        JMenuItem item = new JMenuItem("Send to Analyze Target");
        item.addActionListener(e -> loadIntoTab(rr));
        return List.of(item);
    }

    private Optional<HttpRequestResponse> pickRequestResponse(ContextMenuEvent event) {
        List<HttpRequestResponse> list = event.selectedRequestResponses();
        if (!list.isEmpty()) return Optional.of(list.get(0));
        return event.messageEditorRequestResponse()
                .map(mer -> mer.requestResponse());
    }

    private void loadIntoTab(HttpRequestResponse rr) {
        HttpRequest req = rr.request();
        HttpResponse resp = rr.response(); // may be null
        if (req == null) {
            api.logging().logToError("[analyze-target] no request available on selection.");
            return;
        }
        api.logging().logToOutput("[analyze-target] loaded target: " + req.url());
        tab.loadTarget(req, resp);
    }
}
