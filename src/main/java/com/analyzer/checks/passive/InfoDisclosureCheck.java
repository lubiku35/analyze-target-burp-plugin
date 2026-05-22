package com.analyzer.checks.passive;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.util.ArrayList;
import java.util.List;

/**
 * Passive checks that look at the seed response body+headers for fingerprinting and source-map leaks.
 *
 * Server/X-Powered-By/X-AspNet-Version disclose stack info that helps attackers pick exploits.
 * `//# sourceMappingURL=` exposes original source in production bundles.
 */
public class InfoDisclosureCheck implements Check {
    private static final String ID = "info-disclosure";

    @Override public String id() { return ID; }
    @Override public String category() { return "Information disclosure"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        String url = ctx.targetUrl();

        // Stack fingerprinting headers
        String[] fingerprintHeaders = {"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"};
        for (String h : fingerprintHeaders) {
            String v = HttpUtil.headerValue(resp, h);
            if (v != null && !v.isBlank()) {
                out.add(Finding.builder()
                        .checkId(ID + ".fingerprint")
                        .title("Server fingerprinting header: " + h)
                        .severity(Severity.INFO)
                        .confidence(Confidence.CERTAIN)
                        .url(url)
                        .description("Response includes `" + h + ": " + v + "`. Discloses backend technology/version, "
                                + "letting attackers target known CVEs more efficiently.")
                        .remediation("Remove or generalise the `" + h + "` header at the web-server / reverse-proxy layer.")
                        .evidence(h + ": " + v)
                        .request(ctx.seedRequest())
                        .response(resp)
                        .build());
            }
        }

        // Verbose error patterns in body - cap scan to 1 MiB to bound CPU on huge responses
        String body = resp.bodyToString();
        if (body != null) {
            if (body.length() > 1_048_576) body = body.substring(0, 1_048_576);
            String[] errorMarkers = {
                    "Whitelabel Error Page", "java.lang.NullPointerException", "java.lang.Exception",
                    "Traceback (most recent call last)", "Fatal error:", "Warning:",
                    "Microsoft OLE DB Provider", "ODBC SQL Server Driver",
                    "ORA-00", "PSQLException", "MySQLSyntaxErrorException",
                    "ASP.NET is configured to show verbose error messages",
                    "<title>Application Error</title>"
            };
            for (String marker : errorMarkers) {
                int idx = body.indexOf(marker);
                if (idx >= 0) {
                    int start = Math.max(0, idx - 40);
                    int end = Math.min(body.length(), idx + marker.length() + 200);
                    out.add(Finding.builder()
                            .checkId(ID + ".verbose-error")
                            .title("Verbose error / stack trace exposed in response body")
                            .severity(Severity.LOW)
                            .confidence(Confidence.FIRM)
                            .url(url)
                            .description("Response body contains diagnostic output ('" + marker + "') that can leak internal paths, "
                                    + "library versions, SQL, or stack frames.")
                            .remediation("Disable detailed error pages in production; return a generic message and log details server-side.")
                            .evidence("…" + HttpUtil.truncate(body.substring(start, end), 400) + "…")
                            .request(ctx.seedRequest())
                            .response(resp)
                            .build());
                    break; // one finding per response is enough
                }
            }

            // Source map reference in JS responses
            String ct = HttpUtil.headerValue(resp, "Content-Type");
            if (ct != null && ct.toLowerCase().contains("javascript")) {
                int sm = body.lastIndexOf("//# sourceMappingURL=");
                if (sm < 0) sm = body.lastIndexOf("/*# sourceMappingURL=");
                if (sm >= 0) {
                    int end = Math.min(body.length(), sm + 200);
                    out.add(Finding.builder()
                            .checkId(ID + ".source-map")
                            .title("Source map reference in production JavaScript")
                            .severity(Severity.LOW)
                            .confidence(Confidence.FIRM)
                            .url(url)
                            .description("JS bundle references a source map. If the .map file is reachable, original source "
                                    + "(including comments, paths, sometimes credentials) is exposed.")
                            .remediation("Strip `sourceMappingURL` comments from production bundles, or restrict access to .map files.")
                            .evidence(body.substring(sm, end))
                            .request(ctx.seedRequest())
                            .response(resp)
                            .build());
                }
            }
        }
        return out;
    }
}
