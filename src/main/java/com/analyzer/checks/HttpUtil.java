package com.analyzer.checks;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;

/** Tiny helpers shared across checks. */
public final class HttpUtil {
    private HttpUtil() {}

    public static String headerValue(HttpResponse resp, String name) {
        if (resp == null) return null;
        for (HttpHeader h : resp.headers()) {
            if (h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    public static List<String> headerValues(HttpResponse resp, String name) {
        List<String> out = new ArrayList<>();
        if (resp == null) return out;
        for (HttpHeader h : resp.headers()) {
            if (h.name().equalsIgnoreCase(name)) out.add(h.value());
        }
        return out;
    }

    public static String headerValue(HttpRequest req, String name) {
        if (req == null) return null;
        for (HttpHeader h : req.headers()) {
            if (h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    /**
     * Truncate long text for display in evidence lines (not for request/response bodies — those
     * are preserved in full via {@link #requestSnippet}/{@link #responseSnippet}).
     */
    public static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "… [truncated " + (s.length() - max) + " bytes]";
    }

    /**
     * Full request as an HTTP/1.1-style snippet. No truncation; the entire body is included.
     * Sensitive headers are replaced with {@code <redacted>} when the global Redaction toggle is on.
     */
    public static String requestSnippet(HttpRequest req) {
        if (req == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append(req.method()).append(' ').append(req.path()).append(" HTTP/1.1\n");
        for (HttpHeader h : req.headers()) {
            String value = Redaction.isSensitive(h.name()) ? "<redacted>" : h.value();
            sb.append(h.name()).append(": ").append(value).append('\n');
        }
        String body = req.bodyToString();
        if (body != null && !body.isEmpty()) {
            sb.append('\n').append(body);
        }
        return sb.toString();
    }

    /**
     * Full response as an HTTP/1.1-style snippet. No truncation; the entire body is included.
     * Sensitive headers are redacted when the global Redaction toggle is on.
     */
    public static String responseSnippet(HttpResponse resp) {
        if (resp == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(resp.statusCode()).append(' ').append(resp.reasonPhrase()).append('\n');
        for (HttpHeader h : resp.headers()) {
            String value = Redaction.isSensitive(h.name()) ? "<redacted>" : h.value();
            sb.append(h.name()).append(": ").append(value).append('\n');
        }
        sb.append('\n');
        String body = resp.bodyToString();
        if (body != null) sb.append(body);
        return sb.toString();
    }

    /**
     * Back-compat overload: ignores the body-cap parameter and returns the full response.
     * Existing call sites that passed `0` (headers-only) still work but now also include the body —
     * since callers typically build the finding via {@code .response(resp)} which also auto-populates
     * the snippet, the explicit overload mainly survives for stray imports.
     * @deprecated use {@link #responseSnippet(HttpResponse)} or attach the response via
     *             {@code Finding.Builder.response(resp)}.
     */
    @Deprecated
    public static String responseSnippet(HttpResponse resp, int ignoredBodyMax) {
        return responseSnippet(resp);
    }

    /** Headers-only variant — useful for checks whose evidence is in the headers, not the body. */
    public static String responseHeadersOnly(HttpResponse resp) {
        if (resp == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(resp.statusCode()).append(' ').append(resp.reasonPhrase()).append('\n');
        for (HttpHeader h : resp.headers()) {
            String value = Redaction.isSensitive(h.name()) ? "<redacted>" : h.value();
            sb.append(h.name()).append(": ").append(value).append('\n');
        }
        return sb.toString();
    }
}
