package com.analyzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.analyzer.engine.AnalysisEngine;
import com.analyzer.traffic.HttpTrafficLog;
import com.analyzer.ui.AnalyzerTab;

/**
 * Entry point. Burp instantiates this class via ServiceLoader
 * (META-INF/services/burp.api.montoya.BurpExtension) and invokes initialize(MontoyaApi) once.
 */
public class AnalyzeTargetExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Analyze Target");
        api.logging().logToOutput("[analyze-target] loading…");

        HttpTrafficLog trafficLog = new HttpTrafficLog();
        AnalysisEngine engine = new AnalysisEngine(api, trafficLog);
        AnalyzerTab tab = new AnalyzerTab(api, engine, trafficLog);

        api.userInterface().registerSuiteTab("Analyze Target", tab);
        api.userInterface().registerContextMenuItemsProvider(
                new AnalyzeContextMenuProvider(api, tab));

        api.logging().logToOutput("[analyze-target] ready ("
                + engine.checks().size() + " checks). Right-click any request → Extensions → Send to Analyze Target.");
    }
}
