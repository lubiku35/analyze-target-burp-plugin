package com.analyzer.persistence;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Saves and restores the loaded target + findings between Burp project sessions.
 *
 * Backed by {@code api.persistence().extensionData()}, which is bound to the current Burp project:
 *   - With a saved project, state survives Burp restarts.
 *   - With a temporary project, state lives in memory only (Burp's documented behaviour).
 *
 * The traffic log is intentionally <em>not</em> persisted — it can be large and is meaningful
 * only within a single run.
 *
 * Schema is versioned via {@code state.version} so future changes can migrate gracefully.
 */
public final class StateStore {
    private static final int SCHEMA_VERSION = 1;

    private static final String KEY_VERSION       = "state.version";
    private static final String KEY_TARGET_REQ    = "target.request";
    private static final String KEY_TARGET_RESP   = "target.response";
    private static final String KEY_FINDING_PREFIX = "finding.";

    private final MontoyaApi api;
    private final PersistedObject root;

    public StateStore(MontoyaApi api) {
        this.api = api;
        this.root = api.persistence().extensionData();
    }

    // ---- Saving ------------------------------------------------------------

    public synchronized void saveTarget(HttpRequest req, HttpResponse resp) {
        try {
            root.setInteger(KEY_VERSION, SCHEMA_VERSION);
            if (req != null) {
                root.setHttpRequest(KEY_TARGET_REQ, req);
            } else {
                root.deleteHttpRequest(KEY_TARGET_REQ);
            }
            if (resp != null) {
                root.setHttpResponse(KEY_TARGET_RESP, resp);
            } else {
                root.deleteHttpResponse(KEY_TARGET_RESP);
            }
        } catch (Throwable t) {
            api.logging().logToError("[analyze-target] saveTarget failed: " + t);
        }
    }

    public synchronized void saveFindings(List<Finding> findings) {
        try {
            root.setInteger(KEY_VERSION, SCHEMA_VERSION);
            // Drop any previously-stored findings before re-writing — keys are positional.
            for (String key : new ArrayList<>(root.childObjectKeys())) {
                if (key.startsWith(KEY_FINDING_PREFIX)) {
                    root.deleteChildObject(key);
                }
            }
            int i = 0;
            for (Finding f : findings) {
                PersistedObject child = PersistedObject.persistedObject();
                writeFinding(child, f);
                root.setChildObject(KEY_FINDING_PREFIX + i, child);
                i++;
            }
        } catch (Throwable t) {
            api.logging().logToError("[analyze-target] saveFindings failed: " + t);
        }
    }

    private static void writeFinding(PersistedObject o, Finding f) {
        o.setString("checkId",     f.checkId());
        o.setString("title",       f.title());
        o.setString("severity",    f.severity().name());
        o.setString("confidence",  f.confidence().name());
        o.setString("url",         f.url());
        o.setString("description", f.description());
        o.setString("remediation", f.remediation());
        o.setString("evidence",    f.evidence());
        o.setString("references",  String.join("\n", f.references()));
        o.setString("requestSnippet",  f.requestSnippet());
        o.setString("responseSnippet", f.responseSnippet());
        o.setString("detectedAt", f.detectedAt().toString());
        if (f.httpRequest()  != null) o.setHttpRequest("request",   f.httpRequest());
        if (f.httpResponse() != null) o.setHttpResponse("response", f.httpResponse());
    }

    // ---- Loading -----------------------------------------------------------

    public record Restored(HttpRequest target, HttpResponse targetResponse, List<Finding> findings) {}

    public synchronized Restored restore() {
        Restored empty = new Restored(null, null, List.of());
        try {
            Integer version = root.getInteger(KEY_VERSION);
            if (version == null) return empty;     // first run on this project — nothing saved yet
            if (version != SCHEMA_VERSION) {
                api.logging().logToOutput("[analyze-target] persisted state has schema v" + version
                        + " (expected " + SCHEMA_VERSION + ") — ignoring.");
                return empty;
            }
            HttpRequest req  = safeGetHttpRequest(KEY_TARGET_REQ);
            HttpResponse rsp = safeGetHttpResponse(KEY_TARGET_RESP);
            List<Finding> findings = readFindings();
            api.logging().logToOutput("[analyze-target] restored " + findings.size()
                    + " finding(s) and " + (req == null ? "no" : "a") + " loaded target from project storage.");
            return new Restored(req, rsp, findings);
        } catch (Throwable t) {
            api.logging().logToError("[analyze-target] restore failed: " + t);
            return empty;
        }
    }

    private List<Finding> readFindings() {
        List<Finding> out = new ArrayList<>();
        Set<String> keys = root.childObjectKeys();
        // Sort by trailing integer so order matches the save order.
        List<String> sorted = new ArrayList<>();
        for (String k : keys) if (k.startsWith(KEY_FINDING_PREFIX)) sorted.add(k);
        sorted.sort((a, b) -> {
            try {
                return Integer.compare(
                        Integer.parseInt(a.substring(KEY_FINDING_PREFIX.length())),
                        Integer.parseInt(b.substring(KEY_FINDING_PREFIX.length())));
            } catch (NumberFormatException e) {
                return a.compareTo(b);
            }
        });
        for (String key : sorted) {
            PersistedObject child = root.getChildObject(key);
            if (child == null) continue;
            try {
                out.add(readFinding(child));
            } catch (Exception e) {
                api.logging().logToError("[analyze-target] failed to read persisted finding " + key + ": " + e);
            }
        }
        return out;
    }

    private static Finding readFinding(PersistedObject o) {
        Finding.Builder b = Finding.builder()
                .checkId(nullToEmpty(o.getString("checkId")))
                .title(nullToEmpty(o.getString("title")))
                .severity(parseSeverity(o.getString("severity")))
                .confidence(parseConfidence(o.getString("confidence")))
                .url(nullToEmpty(o.getString("url")))
                .description(nullToEmpty(o.getString("description")))
                .remediation(nullToEmpty(o.getString("remediation")))
                .evidence(nullToEmpty(o.getString("evidence")))
                .references(splitLines(o.getString("references")))
                .requestSnippet(nullToEmpty(o.getString("requestSnippet")))
                .responseSnippet(nullToEmpty(o.getString("responseSnippet")));
        String iso = o.getString("detectedAt");
        if (iso != null) {
            try { b.detectedAt(Instant.parse(iso)); } catch (Exception ignored) {}
        }
        HttpRequest  req  = safeGetHttpRequestFrom(o, "request");
        HttpResponse resp = safeGetHttpResponseFrom(o, "response");
        if (req  != null) b.request(req);
        if (resp != null) b.response(resp);
        return b.build();
    }

    // ---- Helpers -----------------------------------------------------------

    public synchronized void clear() {
        try {
            for (String key : new ArrayList<>(root.childObjectKeys())) {
                if (key.startsWith(KEY_FINDING_PREFIX)) root.deleteChildObject(key);
            }
            root.deleteHttpRequest(KEY_TARGET_REQ);
            root.deleteHttpResponse(KEY_TARGET_RESP);
            // Keep KEY_VERSION so we know the slot is initialised.
        } catch (Throwable t) {
            api.logging().logToError("[analyze-target] clear failed: " + t);
        }
    }

    private HttpRequest safeGetHttpRequest(String key) {
        try { return root.getHttpRequest(key); } catch (Exception e) { return null; }
    }
    private HttpResponse safeGetHttpResponse(String key) {
        try { return root.getHttpResponse(key); } catch (Exception e) { return null; }
    }
    private static HttpRequest safeGetHttpRequestFrom(PersistedObject o, String key) {
        try { return o.getHttpRequest(key); } catch (Exception e) { return null; }
    }
    private static HttpResponse safeGetHttpResponseFrom(PersistedObject o, String key) {
        try { return o.getHttpResponse(key); } catch (Exception e) { return null; }
    }

    private static String nullToEmpty(String s) { return s == null ? "" : s; }

    private static List<String> splitLines(String s) {
        if (s == null || s.isEmpty()) return List.of();
        return Arrays.asList(s.split("\\n"));
    }

    private static Severity parseSeverity(String s) {
        try { return Severity.valueOf(s); } catch (Exception e) { return Severity.INFO; }
    }
    private static Confidence parseConfidence(String s) {
        try { return Confidence.valueOf(s); } catch (Exception e) { return Confidence.TENTATIVE; }
    }
}
