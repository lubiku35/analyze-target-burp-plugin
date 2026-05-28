package com.analyzer.checks.active;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cross-domain policy files for legacy Flash (crossdomain.xml) and Silverlight
 * (clientaccesspolicy.xml). A permissive policy (domain="*") lets any site make cross-domain,
 * credentialed requests through those plugins - effectively a CORS bypass for old clients.
 *
 * Active: fetches the two well-known paths off the target root.
 */
public class CrossDomainPolicyCheck implements Check {
    private static final String ID = "crossdomain-policy";
    private static final Pattern ALLOW_FROM = Pattern.compile("(?i)<allow-access-from\\s+domain=[\"']([^\"']*)[\"']");
    private static final Pattern CAP_DOMAIN = Pattern.compile("(?i)<domain\\s+uri=[\"']([^\"']*)[\"']");

    @Override public String id() { return ID; }
    @Override public String category() { return "Cross-domain policy"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI base;
        try {
            URI seed = new URI(ctx.targetUrl());
            base = new URI(seed.getScheme(), null, seed.getHost(), seed.getPort(), "/", null, null);
        } catch (Exception e) {
            return out;
        }
        probe(ctx, base.resolve("/crossdomain.xml").toString(), ALLOW_FROM,
                "Flash cross-domain policy (crossdomain.xml)", out);
        probe(ctx, base.resolve("/clientaccesspolicy.xml").toString(), CAP_DOMAIN,
                "Silverlight client access policy (clientaccesspolicy.xml)", out);
        return out;
    }

    private void probe(AnalysisContext ctx, String url, Pattern domainPattern, String label, List<Finding> out) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url);
            HttpResponse resp = ctx.sendRequest(req);
            if (resp == null || resp.statusCode() != 200) return;
            String body = resp.bodyToString();
            if (body == null || !body.contains("<")) return;

            Set<String> domains = new LinkedHashSet<>();
            Matcher m = domainPattern.matcher(body);
            while (m.find()) domains.add(m.group(1).trim());
            if (domains.isEmpty()) return;

            boolean wildcard = domains.stream().anyMatch(d -> d.equals("*") || d.isEmpty());
            Severity sev = wildcard ? Severity.LOW : Severity.INFO;
            out.add(Finding.builder()
                    .checkId(ID + (wildcard ? ".wildcard" : ".present"))
                    .title(label + (wildcard ? " allows ALL domains (*)" : " present"))
                    .severity(sev)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("A cross-domain policy file was served at " + url + ". "
                            + (wildcard
                            ? "It grants access to all domains (`*`), letting any site make credentialed cross-domain "
                              + "requests through legacy Flash/Silverlight clients - a CORS-style bypass."
                            : "It grants cross-domain access to the listed domains; confirm each is trusted."))
                    .remediation("Remove the policy file unless a Flash/Silverlight client genuinely needs it. Otherwise "
                            + "restrict it to an explicit list of trusted domains and never use `domain=\"*\"`.")
                    .evidence("Allowed domains:\n" + String.join("\n", domains))
                    .references(List.of(
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/",
                            "https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html"))
                    .request(req)
                    .response(resp)
                    .build());
        } catch (Exception e) {
            ctx.api().logging().logToError("[analyze-target] crossdomain-policy probe failed: " + e);
        }
    }
}
