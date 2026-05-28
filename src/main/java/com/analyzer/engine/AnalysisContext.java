package com.analyzer.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.traffic.HttpTrafficEntry;
import com.analyzer.traffic.HttpTrafficLog;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Per-check execution context: seed request/response, the Montoya API, and a logging wrapper
 * around HTTP send so the UI's "HTTP traffic" tab can show every probe.
 *
 * Checks should prefer {@link #sendRequest(HttpRequest)} over {@code api().http().sendRequest(...)};
 * direct calls bypass traffic logging.
 *
 * <p>For plain idempotent GET fetches of shared resources (linked JavaScript, common probe paths)
 * checks should use {@link #cachedGet(HttpRequest)} instead. A single {@code responseCache} instance
 * is shared across every check in one run, so two checks that reference the same URL — e.g. the
 * JavaScript-grep and link-extraction crawlers both pulling the same {@code <script src>} — only
 * pay for one network round-trip. Fewer requests means faster runs and a quieter footprint on the
 * target.</p>
 */
public final class AnalysisContext {
    /** How long a check will wait on an in-flight cached fetch started by another check. */
    private static final long CACHE_WAIT_SECONDS = 65;

    private final MontoyaApi api;
    private final HttpRequest seedRequest;
    private final HttpResponse seedResponse;
    private final String checkId;
    private final HttpTrafficLog trafficLog;
    private final ConcurrentHashMap<String, CompletableFuture<HttpResponse>> responseCache;

    public AnalysisContext(MontoyaApi api,
                           HttpRequest seedRequest,
                           HttpResponse seedResponse,
                           String checkId,
                           HttpTrafficLog trafficLog) {
        this(api, seedRequest, seedResponse, checkId, trafficLog, new ConcurrentHashMap<>());
    }

    public AnalysisContext(MontoyaApi api,
                           HttpRequest seedRequest,
                           HttpResponse seedResponse,
                           String checkId,
                           HttpTrafficLog trafficLog,
                           ConcurrentHashMap<String, CompletableFuture<HttpResponse>> responseCache) {
        this.api = Objects.requireNonNull(api, "api");
        this.seedRequest = Objects.requireNonNull(seedRequest, "seedRequest");
        this.seedResponse = seedResponse;
        this.checkId = checkId == null ? "unknown" : checkId;
        this.trafficLog = Objects.requireNonNull(trafficLog, "trafficLog");
        this.responseCache = responseCache == null ? new ConcurrentHashMap<>() : responseCache;
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

    /**
     * Fetch a resource through the shared per-run cache. Only plain {@code GET} requests are
     * cached (keyed on the full URL); any other method falls straight through to
     * {@link #sendRequest(HttpRequest)} so header-mutating active probes — host-header injection,
     * CORS origin reflection, etc. — are never served a stale or wrong-variant response.
     *
     * <p>If another check is already fetching the same URL, this waits for that result instead of
     * issuing a duplicate request. On any wait failure it falls back to a direct fetch, so a stalled
     * in-flight request can never wedge a caller.</p>
     */
    public HttpResponse cachedGet(HttpRequest request) {
        if (request == null) return null;
        String method = request.method();
        if (method == null || !method.equalsIgnoreCase("GET")) {
            return sendRequest(request);
        }
        String key = request.url();
        CompletableFuture<HttpResponse> mine = new CompletableFuture<>();
        CompletableFuture<HttpResponse> inFlight = responseCache.putIfAbsent(key, mine);
        if (inFlight != null) {
            try {
                return inFlight.get(CACHE_WAIT_SECONDS, TimeUnit.SECONDS);
            } catch (Exception e) {
                return sendRequest(request);
            }
        }
        HttpResponse resp = sendRequest(request);
        mine.complete(resp);
        return resp;
    }

    private static int safeLength(HttpResponse response) {
        try {
            return response.body().length();
        } catch (Exception e) {
            return -1;
        }
    }
}
