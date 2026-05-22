package com.analyzer.traffic;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.Instant;

/**
 * One HTTP round-trip recorded during an analysis run. We keep the original Montoya
 * request/response handles so the UI can show them in Burp's native editors instead of plain text.
 */
public record HttpTrafficEntry(
        long sequence,
        Instant timestamp,
        String checkId,
        String method,
        String url,
        int statusCode,         // -1 if the request errored
        int responseLength,     // -1 if no response
        long durationMillis,
        HttpRequest request,
        HttpResponse response,  // null on error
        String error            // null on success
) {
    public boolean errored() { return error != null; }
}
