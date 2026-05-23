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
 * Enumerates HTTP methods on the target path: actively sends each verb (HEAD/POST/PUT/DELETE/PATCH/
 * CONNECT plus an unknown method) and records the status, reads the OPTIONS Allow: list, probes TRACE
 * for Cross-Site Tracing, and tests X-HTTP-Method-Override smuggling.
 */
public class HttpMethodsCheck implements Check {
    private static final String ID = "http-methods";
    private static final List<String> RISKY_METHODS = Arrays.asList("TRACE", "PUT", "DELETE", "CONNECT", "PATCH");
    /** Methods actively sent to the target path to observe how the server responds. */
    private static final List<String> ENUMERATED_METHODS =
            Arrays.asList("HEAD", "POST", "PUT", "DELETE", "PATCH", "CONNECT");
    /** Write / tunnelling verbs that warrant a finding when the server accepts them. */
    private static final List<String> DANGEROUS_METHODS =
            Arrays.asList("PUT", "DELETE", "PATCH", "CONNECT");
    /** An invented method token used to probe how the server handles unknown verbs. */
    private static final String BOGUS_METHOD = "PENTEST";

    @Override public String id() { return ID; }
    @Override public String category() { return "HTTP methods"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest seed = ctx.seedRequest();
        if (seed == null) return out;

        // --- Active method enumeration: send each verb and record how the server responds. ---
        try {
            StringBuilder table = new StringBuilder();
            int baseStatus = ctx.seedResponse() != null ? ctx.seedResponse().statusCode() : -1;
            if (baseStatus >= 0) {
                table.append(String.format("%-8s -> %d  (baseline / seed)%n", seed.method(), baseStatus));
            }

            List<String> acceptedDangerous = new ArrayList<>();
            HttpRequest lastReq = seed;
            HttpResponse lastResp = ctx.seedResponse();
            int bogusStatus = -1;
            HttpRequest bogusReq = null;
            HttpResponse bogusResp = null;

            List<String> battery = new ArrayList<>(ENUMERATED_METHODS);
            battery.add(BOGUS_METHOD);
            for (String m : battery) {
                HttpRequest req = seed.withMethod(m);
                HttpResponse resp = ctx.sendRequest(req);
                if (resp == null) {
                    table.append(String.format("%-8s -> (no response)%n", m));
                    continue;
                }
                int sc = resp.statusCode();
                boolean methodAllowed = sc != 405 && sc != 501;
                table.append(String.format("%-8s -> %d%s%n", m, sc, methodAllowed ? "" : "  (not allowed)"));
                if (DANGEROUS_METHODS.contains(m) && methodAllowed && sc < 400) {
                    acceptedDangerous.add(m + " (HTTP " + sc + ")");
                }
                if (m.equals(BOGUS_METHOD)) {
                    bogusStatus = sc;
                    bogusReq = req;
                    bogusResp = resp;
                }
                lastReq = req;
                lastResp = resp;
            }

            out.add(Finding.builder()
                    .checkId(ID + ".enumeration")
                    .title("HTTP method enumeration")
                    .severity(Severity.INFO)
                    .confidence(Confidence.CERTAIN)
                    .url(ctx.targetUrl())
                    .description("Each HTTP method was sent to the target path and the response status recorded. "
                            + "Use this to spot verbs the application should not expose - write methods on read-only "
                            + "endpoints, methods that bypass method-based access control, or a server that processes "
                            + "arbitrary/unknown methods.")
                    .remediation("Restrict each route to the methods it actually needs at the web server / framework "
                            + "layer and return 405 for everything else. Disable WebDAV verbs (PUT/DELETE) unless required.")
                    .evidence(table.toString().stripTrailing())
                    .request(lastReq)
                    .response(lastResp)
                    .build());

            if (!acceptedDangerous.isEmpty()) {
                out.add(Finding.builder()
                        .checkId(ID + ".dangerous-methods")
                        .title("Potentially dangerous HTTP methods accepted")
                        .severity(Severity.MEDIUM)
                        .confidence(Confidence.TENTATIVE)
                        .url(ctx.targetUrl())
                        .description("The server returned a success/redirect status for write or tunnelling methods: "
                                + String.join(", ", acceptedDangerous) + ". If these are not deliberately exposed they may "
                                + "permit content upload, deletion, or request tunnelling (CONNECT). Verify manually before reporting.")
                        .remediation("Confirm whether these methods are required. If not, disable them; if yes, ensure they "
                                + "enforce the same authentication, authorization, and CSRF protection as other write paths.")
                        .evidence(String.join("\n", acceptedDangerous))
                        .request(lastReq)
                        .response(lastResp)
                        .build());
            }

            if (bogusStatus >= 0 && bogusStatus < 400) {
                out.add(Finding.builder()
                        .checkId(ID + ".arbitrary-method")
                        .title("Server accepts arbitrary / unknown HTTP methods")
                        .severity(Severity.LOW)
                        .confidence(Confidence.TENTATIVE)
                        .url(ctx.targetUrl())
                        .description("An invented method `" + BOGUS_METHOD + "` returned HTTP " + bogusStatus
                                + " instead of 405/501. Servers that treat unknown methods like GET can let an attacker "
                                + "bypass method-based access controls (e.g. a WAF rule or framework guard that only filters GET/POST).")
                        .remediation("Reject unknown methods with 405 Method Not Allowed at the edge and in the application.")
                        .evidence(BOGUS_METHOD + " -> HTTP " + bogusStatus)
                        .request(bogusReq)
                        .response(bogusResp)
                        .build());
            }
        } catch (Exception e) {
            ctx.api().logging().logToError("[analyze-target] method enumeration failed: " + e);
        }

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
                                    (risky ? "List includes one of TRACE/PUT/DELETE/CONNECT/PATCH - verify each is intentionally exposed."
                                            : "Informational - confirm each is intentionally exposed."))
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
