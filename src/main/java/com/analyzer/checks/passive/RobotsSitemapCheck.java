package com.analyzer.checks.passive;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
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
 * WSTG-INFO-03 - Review webserver metafiles.
 *
 * Fetches /robots.txt and /sitemap.xml and surfaces interesting paths. Disallow entries
 * often point at admin panels or staging artefacts; sitemap.xml is a free URL inventory.
 */
public class RobotsSitemapCheck implements Check {
    private static final String ID = "robots-sitemap";
    private static final Pattern DISALLOW = Pattern.compile("(?im)^\\s*Disallow:\\s*(.+)$");
    private static final Pattern SITEMAP_REF = Pattern.compile("(?im)^\\s*Sitemap:\\s*(.+)$");
    private static final Pattern SITEMAP_URL = Pattern.compile("(?i)<loc>([^<]+)</loc>");

    @Override public String id() { return ID; }
    @Override public String category() { return "Metafiles"; }
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

        // robots.txt
        String robotsUrl = base.resolve("/robots.txt").toString();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(robotsUrl);
            HttpResponse resp = ctx.sendRequest(req);
            if (resp != null && resp.statusCode() == 200) {
                String body = resp.bodyToString();
                if (body != null) {
                    Set<String> disallowed = collect(DISALLOW, body);
                    Set<String> sitemapRefs = collect(SITEMAP_REF, body);
                    if (!disallowed.isEmpty() || !sitemapRefs.isEmpty()) {
                        out.add(Finding.builder()
                                .checkId(ID + ".robots")
                                .title("/robots.txt exposes " + disallowed.size() + " Disallow path(s)")
                                .severity(Severity.INFO)
                                .confidence(Confidence.CERTAIN)
                                .url(robotsUrl)
                                .description("Disallow entries describe paths the operator does not want indexed - often "
                                        + "admin areas, staging artefacts, or sensitive endpoints. Review each for "
                                        + "additional attack surface.")
                                .remediation("N/A - informational. Avoid relying on robots.txt to hide sensitive paths; "
                                        + "use real authentication instead.")
                                .evidence(("Disallow paths:\n" + String.join("\n", disallowed)
                                        + (sitemapRefs.isEmpty() ? "" : "\n\nSitemap references:\n" + String.join("\n", sitemapRefs)))
                                        .trim())
                                .references(List.of(
                                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"))
                                .build());
                    }
                }
            }
        } catch (Exception e) {
            ctx.api().logging().logToError("[analyze-target] robots.txt probe failed: " + e);
        }

        // sitemap.xml
        String sitemapUrl = base.resolve("/sitemap.xml").toString();
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(sitemapUrl);
            HttpResponse resp = ctx.sendRequest(req);
            if (resp != null && resp.statusCode() == 200) {
                String body = resp.bodyToString();
                if (body != null) {
                    Set<String> urls = collect(SITEMAP_URL, body);
                    if (!urls.isEmpty()) {
                        out.add(Finding.builder()
                                .checkId(ID + ".sitemap")
                                .title("/sitemap.xml lists " + urls.size() + " URL(s)")
                                .severity(Severity.INFO)
                                .confidence(Confidence.CERTAIN)
                                .url(sitemapUrl)
                                .description("Sitemap enumerates URLs the operator wants indexed. Useful as a free crawl target list.")
                                .remediation("N/A - informational.")
                                .evidence(String.join("\n", urls.stream().limit(100).toList())
                                        + (urls.size() > 100 ? "\n… (truncated, " + (urls.size() - 100) + " more)" : ""))
                                .build());
                    }
                }
            }
        } catch (Exception e) {
            ctx.api().logging().logToError("[analyze-target] sitemap.xml probe failed: " + e);
        }

        return out;
    }

    private static Set<String> collect(Pattern p, String text) {
        Set<String> out = new LinkedHashSet<>();
        Matcher m = p.matcher(text);
        while (m.find()) out.add(m.group(1).trim());
        return out;
    }
}
