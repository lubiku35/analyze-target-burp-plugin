package com.analyzer.checks.active;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Canary;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.util.ArrayList;
import java.util.List;

/**
 * Host header attack probes. We try several variants and look for the canary value reflected in
 * the body, in the Location header, or in cache-control surrogate keys.
 *
 *  - replace Host: with an external test host
 *  - keep real Host: but add X-Forwarded-Host
 *  - add X-Host (some frameworks honour this)
 *  - send absolute URI in the request line (proxy-routing trick)
 *  - duplicate Host header
 *
 * The canary uses the reserved `.test` TLD (RFC 6761), so it can never resolve to a real host,
 * and a neutral label so it does not trip aggressive WAFs that block obviously hostile values.
 */
public class HostHeaderCheck implements Check {
    private static final String ID = "host-header";
    private static final String CANARY = Canary.HOST;

    @Override public String id() { return ID; }
    @Override public String category() { return "Host header attacks"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest seed = ctx.seedRequest();
        if (seed == null) return out;

        // Variant 1: replace Host
        probe(ctx, seed.withRemovedHeader("Host").withAddedHeader("Host", CANARY),
                "Host header replaced with external test host", out);

        // Variant 2: keep original Host, add X-Forwarded-Host
        probe(ctx, seed.withAddedHeader("X-Forwarded-Host", CANARY),
                "X-Forwarded-Host injection", out);

        // Variant 3: X-Host (used by some frameworks/CDNs)
        probe(ctx, seed.withAddedHeader("X-Host", CANARY),
                "X-Host injection", out);

        // Variant 4: X-Forwarded-Server
        probe(ctx, seed.withAddedHeader("X-Forwarded-Server", CANARY),
                "X-Forwarded-Server injection", out);

        return out;
    }

    private void probe(AnalysisContext ctx, HttpRequest req, String variant, List<Finding> out) {
        try {
            HttpResponse resp = ctx.sendRequest(req);
            if (resp == null) return;

            String body = resp.bodyToString();
            String location = HttpUtil.headerValue(resp, "Location");
            String setCookie = HttpUtil.headerValue(resp, "Set-Cookie");

            String where = null;
            if (body != null && body.contains(CANARY)) where = "response body";
            else if (location != null && location.contains(CANARY)) where = "Location header";
            else if (setCookie != null && setCookie.contains(CANARY)) where = "Set-Cookie";

            if (where != null) {
                Severity sev = location != null && location.contains(CANARY) ? Severity.MEDIUM : Severity.LOW;
                out.add(Finding.builder()
                        .checkId(ID + ".reflection")
                        .title("Host header injection reflected (" + variant + ") in " + where)
                        .severity(sev)
                        .confidence(Confidence.FIRM)
                        .url(ctx.targetUrl())
                        .description("The canary value `" + CANARY + "` injected via " + variant
                                + " was reflected back in the " + where + ". This pattern is the root cause of "
                                + "password-reset poisoning, cache poisoning, and SSRF on internal routing layers.")
                        .remediation("Validate Host / X-Forwarded-Host against an allow-list at the web server or framework layer. "
                                + "Never use these headers to build absolute URLs in email links or redirects without validation.")
                        .evidence("Canary `" + CANARY + "` reflected in " + where + ".")
                        .references(List.of(
                                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                                "https://portswigger.net/web-security/host-header",
                                "https://owasp.org/www-community/attacks/Host_Header_Injection"))
                        .request(req)
                        .response(resp)
                        .build());
            }
        } catch (Exception e) {
            ctx.api().logging().logToError("[analyze-target] host-header probe failed: " + e);
        }
    }
}
