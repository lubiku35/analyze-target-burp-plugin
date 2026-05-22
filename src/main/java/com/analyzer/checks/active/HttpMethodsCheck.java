package com.analyzer.checks.active;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Enumerates HTTP methods on the target path: OPTIONS to read Allow:, then targeted PUT/DELETE/TRACE
 * probes and X-HTTP-Method-Override smuggling.
 */
public class HttpMethodsCheck implements Check {
    private static final String ID = "http-methods";
    private static final List<String> RISKY_METHODS = Arrays.asList("TRACE", "PUT", "DELETE", "CONNECT", "PATCH");

    @Override public String id() { return ID; }
    @Override public String category() { return "HTTP methods"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest seed = ctx.seedRequest();
        if (seed == null) return out;

        // OPTIONS probe
        try {
            HttpRequest options = seed.withMethod("OPTIONS");
            HttpResponse resp = ctx.sendRequest(options);
            if (resp != null) {
                String allow = HttpUtil.headerValue(resp, "Allow");
                String acam  = HttpUtil.headerValue(resp, "Access-Control-Allow-Methods");
                if (allow != null || acam != null) {
                    String reported = (allow != null ? "Allow: " + allow : "")
                            + (allow != null && acam != null ? "\n" : "")
                            + (acam != null ? "Access-Control-Allow-Methods: " + acam : "");
                    boolean risky = RISKY_METHODS.stream().anyMatch(m ->
                            (allow != null && allow.toUpperCase().contains(m)) ||
                                    (acam != null && acam.toUpperCase().contains(m)));
                    out.add(Finding.builder()
                            .checkId(ID + ".options-allow")
                            .title("OPTIONS reports allowed methods" + (risky ? " (including risky)" : ""))
                            .severity(risky ? Severity.LOW : Severity.INFO)
                            .confidence(Confidence.CERTAIN)
                            .url(ctx.targetUrl())
                            .description("Server advertised allowed methods on OPTIONS. " +
                                    (risky ? "List includes one of TRACE/PUT/DELETE/CONNECT/PATCH — verify each is intentionally exposed."
                                            : "Informational — confirm each is intentionally exposed."))
                            .remediation("Disable methods the application does not need at the web server / framework layer. "
                                    + "Prefer explicit per-route method allow-lists over global enablement.")
                            .evidence(reported)
                            .request(options)
                            .response(resp)
                            .build());
                }
            }
        } catch (Exception e) {
            ctx.api().logging().logToError("[analyze-target] OPTIONS probe failed: " + e);
        }

        // TRACE probe
        try {
            HttpRequest trace = seed.withMethod("TRACE");
            HttpResponse resp = ctx.sendRequest(trace);
            if (resp != null && resp.statusCode() < 400) {
                String body = resp.bodyToString();
                if (body != null && body.toUpperCase().startsWith("TRACE")) {
                    out.add(Finding.builder()
                            .checkId(ID + ".trace-enabled")
                            .title("HTTP TRACE method is enabled")
                            .severity(Severity.LOW)
                            .confidence(Confidence.CERTAIN)
                            .url(ctx.targetUrl())
                            .description("Server echoes TRACE requests, enabling Cross-Site Tracing (XST) under specific browser conditions "
                                    + "and revealing intermediate proxies.")
                            .remediation("Disable TRACE at the web server level (`TraceEnable Off` on Apache, equivalent on nginx/IIS).")
                            .evidence(HttpUtil.truncate(body, 400))
                            .request(trace)
                            .response(resp)
                            .build());
                }
            }
        } catch (Exception e) {
            ctx.api().logging().logToError("[analyze-target] TRACE probe failed: " + e);
        }

        // X-HTTP-Method-Override smuggling: try GET that pretends to be DELETE
        try {
            HttpRequest override = seed.withMethod("GET").withAddedHeader("X-HTTP-Method-Override", "DELETE");
            HttpResponse baseline = ctx.seedResponse();
            HttpResponse overResp = ctx.sendRequest(override);
            if (baseline != null && overResp != null && baseline.statusCode() != overResp.statusCode()) {
                out.add(Finding.builder()
                        .checkId(ID + ".method-override")
                        .title("X-HTTP-Method-Override appears honoured (status differs from baseline)")
                        .severity(Severity.MEDIUM)
                        .confidence(Confidence.TENTATIVE)
                        .url(ctx.targetUrl())
                        .description("Sending `X-HTTP-Method-Override: DELETE` on a GET produced status " + overResp.statusCode()
                                + " vs baseline " + baseline.statusCode()
                                + ". The framework may be honouring the override, which can bypass method-based access controls.")
                        .remediation("Disable X-HTTP-Method-Override support unless explicitly needed. If needed, require the same auth "
                                + "and CSRF protection as the underlying method.")
                        .evidence("Baseline status: " + baseline.statusCode()
                                + " | Override status: " + overResp.statusCode())
                        .request(override)
                        .response(overResp)
                        .build());
            }
        } catch (Exception e) {
            ctx.api().logging().logToError("[analyze-target] method-override probe failed: " + e);
        }

        return out;
    }
}
