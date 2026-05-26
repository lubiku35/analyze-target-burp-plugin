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

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Forces a 404 by requesting a guaranteed-non-existent path, then fingerprints the server /
 * framework from the error page body and headers. Many stacks reveal themselves in their default
 * 404 page even when `Server` and `X-Powered-By` have been stripped.
 *
 * Patterns are drawn from publicly documented default error pages — see
 * <a href="https://0xdf.gitlab.io/cheatsheets/404">0xdf's 404 fingerprinting cheatsheet</a> for a
 * larger catalogue and the OWASP WSTG INFO-02 / INFO-08 sections for the methodology.
 *
 * Emits ONE finding listing every matched fingerprint plus the URL used so the analyst can verify.
 */
public class ErrorPageFingerprintCheck implements Check {
    private static final String ID = "error-fingerprint";

    /** Fingerprint label → regex compiled with DOTALL where useful. */
    private static final Map<String, Pattern> FINGERPRINTS = new LinkedHashMap<>();
    static {
        // Web servers
        FINGERPRINTS.put("Apache httpd",
                Pattern.compile("(?i)(Apache/[\\d.]+|<address>Apache[^<]*Server at|The requested URL was not found on this server)"));
        FINGERPRINTS.put("nginx",
                Pattern.compile("(?i)(<center>\\s*nginx(/[\\d.]+)?\\s*</center>|<hr>\\s*<center>nginx</center>)"));
        FINGERPRINTS.put("Microsoft IIS",
                Pattern.compile("(?i)(<h2>HTTP Error 404[^<]*</h2>|HTTP Error 404\\.0|<h3>HTTP Error 404|IIS/[\\d.]+|Microsoft-IIS)"));
        FINGERPRINTS.put("LiteSpeed",
                Pattern.compile("(?i)<address>LiteSpeed Web Server"));
        FINGERPRINTS.put("Caddy",
                Pattern.compile("(?i)<title>Caddy"));
        // Java servlet containers
        FINGERPRINTS.put("Apache Tomcat",
                Pattern.compile("(?i)(Apache Tomcat/[\\d.]+|<h1>HTTP Status 404|The requested resource (\\[[^\\]]*\\] )?is not available)"));
        FINGERPRINTS.put("Eclipse Jetty",
                Pattern.compile("(?i)(Powered by\\s*<a [^>]*>Jetty|<title>Error 404\\s*</title>.*Powered by Jetty)"));
        FINGERPRINTS.put("WildFly / JBoss",
                Pattern.compile("(?i)(JBoss(WS)?|WildFly|<h1>Not Found</h1>.*JBoss)"));
        // PHP frameworks
        FINGERPRINTS.put("Laravel (Whoops)",
                Pattern.compile("(?i)(class=\"Whoops|Whoops, looks like something went wrong\\.|laravel)"));
        FINGERPRINTS.put("Symfony",
                Pattern.compile("(?i)(Symfony Exception|<title>An Error Occurred:|symfony/symfony-standard)"));
        FINGERPRINTS.put("CodeIgniter",
                Pattern.compile("(?i)(CodeIgniter|class=\"php-error\".*encountered while trying to retrieve the URL)"));
        // Python frameworks
        FINGERPRINTS.put("Django",
                Pattern.compile("(?i)(<title>Page not found at|<title>Page not found \\(404\\)|Django settings module|You're seeing this error because you have)"));
        FINGERPRINTS.put("Flask / Werkzeug",
                Pattern.compile("(?i)(<title>404 Not Found</title>.*<p>The requested URL was not found on the server|Werkzeug/[\\d.]+)"));
        // Ruby frameworks
        FINGERPRINTS.put("Ruby on Rails",
                Pattern.compile("(?i)(<h1>(Routing|Action Controller).*Error|The page you were looking for doesn't exist|<title>Action Controller:)"));
        // Node frameworks
        FINGERPRINTS.put("Express (Node.js)",
                Pattern.compile("(?i)(Cannot GET /|<pre>Cannot (GET|POST|PUT|DELETE) /)"));
        FINGERPRINTS.put("Koa (Node.js)",
                Pattern.compile("(?i)<title>Error</title>.*Not Found.*koa"));
        // Java app frameworks
        FINGERPRINTS.put("Spring Boot (Whitelabel)",
                Pattern.compile("(?i)(Whitelabel Error Page|This application has no explicit mapping for /error)"));
        FINGERPRINTS.put("Grails",
                Pattern.compile("(?i)Grails Runtime Exception"));
        // .NET frameworks
        FINGERPRINTS.put("ASP.NET MVC / Core",
                Pattern.compile("(?i)(<title>The resource cannot be found\\.|<h2>(404 -|HTTP Error 404)|Microsoft\\.AspNetCore)"));
        // Generic PHP
        FINGERPRINTS.put("PHP (generic)",
                Pattern.compile("(?i)(<b>(Notice|Warning|Fatal error)</b>:\\s+|on line <b>\\d+</b>|X-Powered-By: PHP)"));
        // CMS
        FINGERPRINTS.put("WordPress 404",
                Pattern.compile("(?i)(<body[^>]+class=\"[^\"]*\\berror404\\b|wp-includes/|wp-content/themes/)"));
        FINGERPRINTS.put("Drupal 404",
                Pattern.compile("(?i)(class=\"page-error|Drupal\\.settings)"));
        // Cloud / proxy edge
        FINGERPRINTS.put("Cloudflare (edge error)",
                Pattern.compile("(?i)(<title>Attention Required\\!|cloudflare-error|cf-error-details|Ray ID:)"));
        FINGERPRINTS.put("AWS API Gateway",
                Pattern.compile("(?i)(\\{\"message\":\\s*\"Missing Authentication Token\"|\\{\"message\":\\s*\"Forbidden\"\\})"));
        FINGERPRINTS.put("AWS S3 (XML 404)",
                Pattern.compile("(?i)<Code>NoSuchKey</Code>"));
        FINGERPRINTS.put("Akamai (edge error)",
                Pattern.compile("(?i)Reference\\s*&#?\\d*;?(\\d+\\.[0-9a-f]+|akamai)"));
    }

    @Override public String id() { return ID; }
    @Override public String category() { return "Error page fingerprint"; }
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

        // Random path = guaranteed 404 on any sane app. Prefix is human-readable in logs.
        String probePath = Canary.randomNotFoundPath();
        String url = base.resolve(probePath).toString();

        HttpRequest req;
        HttpResponse resp;
        try {
            req = HttpRequest.httpRequestFromUrl(url);
            resp = ctx.sendRequest(req);
        } catch (Exception e) {
            return out;
        }
        if (resp == null) return out;

        int status = resp.statusCode();
        String body = resp.bodyToString();
        if (body == null) body = "";
        // Combine body + headers for matching — fingerprints sometimes live in Server / X-Powered-By too.
        String headersDump = HttpUtil.responseHeadersOnly(resp);
        String haystack = headersDump + "\n" + (body.length() > 256_000 ? body.substring(0, 256_000) : body);

        Set<String> matches = new LinkedHashSet<>();
        for (Map.Entry<String, Pattern> e : FINGERPRINTS.entrySet()) {
            if (e.getValue().matcher(haystack).find()) matches.add(e.getKey());
        }

        // Always emit the finding when status is a real error code, even with zero matches —
        // the analyst gets to see the error-page contents in the detail panel.
        if (matches.isEmpty() && status < 400) return out;

        StringBuilder desc = new StringBuilder();
        desc.append("Forced a 404 by requesting `").append(probePath)
            .append("` and inspected the error page for known framework fingerprints.\n\n");
        desc.append("Server returned HTTP ").append(status).append(".\n\n");
        if (matches.isEmpty()) {
            desc.append("No catalogued fingerprint matched — review the raw response in the detail panel; the page "
                    + "may still leak information that's worth a manual look (custom error templates often include "
                    + "framework names in CSS class prefixes, asset paths, or inline scripts).");
        } else {
            desc.append("Matched fingerprint(s):\n  • ").append(String.join("\n  • ", matches)).append('\n');
            desc.append("\nUse these as a starting point for vulnerability research (look up CVEs for the matched "
                    + "stack and version, if visible). Multiple matches usually mean a reverse-proxy in front of an "
                    + "app server (e.g. nginx + Spring Boot).");
        }
        desc.append("\n\nFingerprint catalogue is drawn from 0xdf's 404 cheatsheet and WSTG INFO-02 / INFO-08.");

        out.add(Finding.builder()
                .checkId(ID + (matches.isEmpty() ? ".unmatched" : ".match"))
                .title(matches.isEmpty()
                        ? "Error page captured (no fingerprint match — manual review recommended)"
                        : "Error page reveals stack: " + String.join(", ", matches))
                .severity(matches.isEmpty() ? Severity.INFO : Severity.LOW)
                .confidence(matches.isEmpty() ? Confidence.TENTATIVE : Confidence.FIRM)
                .url(url)
                .description(desc.toString())
                .remediation("Replace default error pages with custom templates that disclose no implementation details. "
                        + "At the reverse-proxy / web-server layer, override 404 / 500 responses with branded pages that "
                        + "omit framework names, asset prefixes, and stack traces. Disable debug mode in production.")
                .evidence("Probe URL: " + url + "\nStatus: " + status
                        + (matches.isEmpty() ? "" : "\nMatched: " + String.join(", ", matches)))
                .references(List.of(
                        "https://0xdf.gitlab.io/cheatsheets/404",
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"))
                .request(req)
                .response(resp)
                .build());
        return out;
    }
}
