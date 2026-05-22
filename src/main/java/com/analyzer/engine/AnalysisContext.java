package com.analyzer.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.traffic.HttpTrafficEntry;
import com.analyzer.traffic.HttpTrafficLog;

import java.time.Instant;
import java.util.Objects;

/**
 * Per-check execution context: seed request/response, the Montoya API, and a logging wrapper
 * around HTTP send so the UI's "HTTP traffic" tab can show every probe.
 *
 * Checks should prefer {@link #sendRequest(HttpRequest)} over {@code api().http().sendRequest(...)};
 * direct calls bypass traffic logging.
 */
public final class AnalysisContext {
    private final MontoyaApi api;
    private final HttpRequest seedRequest;
    private final HttpResponse seedResponse;
    private final String checkId;
    private final HttpTrafficLog trafficLog;

    public AnalysisContext(MontoyaApi api,
                           HttpRequest seedRequest,
                           HttpResponse seedResponse,
                           String checkId,
                           HttpTrafficLog trafficLog) {
        this.api = Objects.requireNonNull(api, "api");
        this.seedRequest = Objects.requireNonNull(seedRequest, "seedRequest");
        this.seedResponse = seedResponse;
        this.checkId = checkId == null ? "unknown" : checkId;
        this.trafficLog = Objects.requireNonNull(trafficLog, "trafficLog");
    }

    public MontoyaApi api() { return api; }
    public HttpRequest seedRequest() { return seedRequest; }
    public HttpResponse seedResponse() { return seedResponse; }
    public String checkId() { return checkId; }
    public String targetUrl() { return seedRequest.url(); }

    /**
     * Send a request through Burp's HTTP stack and record it in the traffic log.
     * Returns null on error (already logged).
     */
    public HttpResponse sendRequest(HttpRequest request) {
        long seq = trafficLog.nextSequence();
        Instant start = Instant.now();
        long t0 = System.nanoTime();
        try {
            HttpRequestResponse rr = api.http().sendRequest(request);
            long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
            HttpResponse response = rr == null ? null : rr.response();
            int status = response == null ? -1 : response.statusCode();
            int length = response == null ? -1 : safeLength(response);
            trafficLog.add(new HttpTrafficEntry(
                    seq, start, checkId, request.method(), request.url(),
                    status, length, elapsedMs, request, response, null));
            return response;
        } catch (Exception e) {
            long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
            trafficLog.add(new HttpTrafficEntry(
                    seq, start, checkId, request.method(), request.url(),
                    -1, -1, elapsedMs, request, null, e.getClass().getSimpleName() + ": " + e.getMessage()));
            api.logging().logToError("[analyze-target] " + checkId + " send failed: " + e);
            return null;
        }
    }

    private static int safeLength(HttpResponse response) {
        try {
            return response.body().length();
        } catch (Exception e) {
            return -1;
        }
    }
}
