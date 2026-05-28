package com.analyzer.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.HttpUtil;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * A single security finding produced by a check.
 *
 * Immutable once built. Holds two parallel representations of the underlying request/response:
 *   - Montoya {@link HttpRequest} / {@link HttpResponse} refs, used by the UI to render full
 *     content in Burp's native editors (no parsing, no truncation).
 *   - Textual snippets, used by the HTML report and as a fallback.
 */
public final class Finding {
    private final String checkId;
    private final String title;
    private final Severity severity;
    private final Confidence confidence;
    private final String url;
    private final String description;
    private final String remediation;
    private final String evidence;
    private final List<String> references;
    private final String requestSnippet;
    private final String responseSnippet;
    private final HttpRequest httpRequest;     // nullable
    private final HttpResponse httpResponse;   // nullable
    private final Instant detectedAt;

    private Finding(Builder b) {
        this.checkId = Objects.requireNonNull(b.checkId, "checkId");
        this.title = Objects.requireNonNull(b.title, "title");
        this.confidence = b.confidence == null ? Confidence.FIRM : b.confidence;
        // Confidence cap: a TENTATIVE finding is an unconfirmed lead, not a demonstrated issue, so it
        // can never outrank LOW no matter what severity the check requested. Keeps the table honest —
        // "possible secret in JS", "reflected parameter", "serialized blob present" are leads to chase,
        // not HIGH/MEDIUM findings until manually confirmed.
        Severity requested = Objects.requireNonNull(b.severity, "severity");
        this.severity = (this.confidence == Confidence.TENTATIVE
                && requested.ordinal() < Severity.LOW.ordinal())
                ? Severity.LOW
                : requested;
        this.url = b.url == null ? "" : b.url;
        this.description = b.description == null ? "" : b.description;
        this.remediation = b.remediation == null ? "" : b.remediation;
        this.evidence = b.evidence == null ? "" : b.evidence;
        this.references = b.references == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(new ArrayList<>(b.references));
        this.requestSnippet = b.requestSnippet == null ? "" : b.requestSnippet;
        this.responseSnippet = b.responseSnippet == null ? "" : b.responseSnippet;
        this.httpRequest = b.httpRequest;
        this.httpResponse = b.httpResponse;
        this.detectedAt = b.detectedAt == null ? Instant.now() : b.detectedAt;
    }

    public String checkId() { return checkId; }
    public String title() { return title; }
    public Severity severity() { return severity; }
    public Confidence confidence() { return confidence; }
    public String url() { return url; }
    public String description() { return description; }
    public String remediation() { return remediation; }
    public String evidence() { return evidence; }
    public List<String> references() { return references; }
    public String requestSnippet() { return requestSnippet; }
    public String responseSnippet() { return responseSnippet; }
    public HttpRequest httpRequest() { return httpRequest; }
    public HttpResponse httpResponse() { return httpResponse; }
    public Instant detectedAt() { return detectedAt; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String checkId;
        private String title;
        private Severity severity;
        private Confidence confidence;
        private String url;
        private String description;
        private String remediation;
        private String evidence;
        private List<String> references;
        private String requestSnippet;
        private String responseSnippet;
        private HttpRequest httpRequest;
        private HttpResponse httpResponse;
        private Instant detectedAt;

        public Builder checkId(String v) { this.checkId = v; return this; }
        public Builder title(String v) { this.title = v; return this; }
        public Builder severity(Severity v) { this.severity = v; return this; }
        public Builder confidence(Confidence v) { this.confidence = v; return this; }
        public Builder url(String v) { this.url = v; return this; }
        public Builder description(String v) { this.description = v; return this; }
        public Builder remediation(String v) { this.remediation = v; return this; }
        public Builder evidence(String v) { this.evidence = v; return this; }
        public Builder references(List<String> v) { this.references = v; return this; }
        public Builder requestSnippet(String v) { this.requestSnippet = v; return this; }
        public Builder responseSnippet(String v) { this.responseSnippet = v; return this; }
        public Builder detectedAt(Instant v) { this.detectedAt = v; return this; }

        /**
         * Attach the originating HTTP request: stores the Montoya ref AND auto-populates
         * the textual request snippet (full content, redaction applied).
         */
        public Builder request(HttpRequest req) {
            this.httpRequest = req;
            if (req != null) this.requestSnippet = HttpUtil.requestSnippet(req);
            return this;
        }

        /**
         * Attach the response: stores the Montoya ref AND auto-populates the textual
         * response snippet (full content, redaction applied).
         */
        public Builder response(HttpResponse resp) {
            this.httpResponse = resp;
            if (resp != null) this.responseSnippet = HttpUtil.responseSnippet(resp);
            return this;
        }

        public Finding build() {
            return new Finding(this);
        }
    }
}
