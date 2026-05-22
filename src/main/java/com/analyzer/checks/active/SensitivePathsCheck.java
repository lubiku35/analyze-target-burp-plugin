package com.analyzer.checks.active;

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
import java.util.List;

/**
 * Probes a small curated wordlist of sensitive files/paths against the site root. Conservative
 * by default (no recursion, no large wordlists, ~30 requests max) to keep traffic predictable.
 *
 * Each entry has a path + a content marker; a positive finding requires both 200 status and a
 * content match to cut down false positives from generic 200-with-HTML SPAs.
 */
public class SensitivePathsCheck implements Check {
    private static final String ID = "sensitive-paths";

    /**
     * marker: empty string → "200 status is enough"; literal substring otherwise.
     * regex: if non-null, body must match this pattern (used when substring is too noisy).
     */
    private record Probe(String path, String marker, java.util.regex.Pattern regex,
                         String description, Severity severity) {
        Probe(String path, String marker, String description, Severity severity) {
            this(path, marker, null, description, severity);
        }
        Probe(String path, java.util.regex.Pattern regex, String description, Severity severity) {
            this(path, "", regex, description, severity);
        }
        boolean matches(String body) {
            if (regex != null) return regex.matcher(body).find();
            if (marker.isEmpty()) return true;
            return body.contains(marker);
        }
    }

    private static final List<Probe> PROBES = List.of(
            new Probe("/.git/HEAD",       "ref: refs/",            "Exposed Git repository (.git/)", Severity.HIGH),
            new Probe("/.git/config",     "[core]",                "Exposed Git repository (.git/config)", Severity.HIGH),
            // Tight regex marker: a KEY=VALUE on its own line (.env grammar). Plain "=" matches every HTML form.
            new Probe("/.env",            java.util.regex.Pattern.compile("(?m)^[A-Z][A-Z0-9_]+=.+$"),
                    "Exposed .env file (likely secrets)", Severity.HIGH),
            new Probe("/.svn/entries",    "",                      "Exposed Subversion metadata", Severity.MEDIUM),
            new Probe("/.DS_Store",       "Bud1",                  ".DS_Store file exposes directory contents", Severity.LOW),
            new Probe("/web.config",      "<configuration",        "ASP.NET web.config exposed", Severity.MEDIUM),
            new Probe("/phpinfo.php",     "PHP Version",           "phpinfo() page exposed", Severity.MEDIUM),
            new Probe("/server-status",   "Apache Server Status",  "Apache server-status exposed", Severity.MEDIUM),
            new Probe("/server-info",     "Apache Server Information", "Apache server-info exposed", Severity.MEDIUM),
            new Probe("/actuator",        "_links",                "Spring Boot Actuator exposed", Severity.HIGH),
            new Probe("/actuator/env",    "propertySources",       "Spring Boot Actuator /env exposed", Severity.HIGH),
            new Probe("/actuator/health", "\"status\"",            "Spring Boot Actuator /health exposed", Severity.LOW),
            new Probe("/swagger.json",    "swagger",               "Swagger/OpenAPI spec exposed", Severity.LOW),
            new Probe("/openapi.json",    "openapi",               "OpenAPI spec exposed", Severity.LOW),
            new Probe("/robots.txt",      "",                      "robots.txt present (informational)", Severity.INFO),
            new Probe("/sitemap.xml",     "<urlset",               "sitemap.xml present (informational)", Severity.INFO),
            new Probe("/crossdomain.xml", "cross-domain-policy",   "Flash cross-domain policy exposed", Severity.LOW),
            new Probe("/clientaccesspolicy.xml", "access-policy",  "Silverlight client-access policy exposed", Severity.LOW),
            new Probe("/.well-known/security.txt", "Contact:",      "security.txt present (informational)", Severity.INFO),
            new Probe("/backup.zip",      "PK",                    "Backup archive exposed (backup.zip)", Severity.HIGH),
            new Probe("/backup.tar.gz",   "",                      "Backup archive exposed (backup.tar.gz)", Severity.HIGH),
            new Probe("/wp-admin/",       "WordPress",             "WordPress admin path present", Severity.INFO),
            new Probe("/wp-login.php",    "WordPress",             "WordPress login page present", Severity.INFO),
            new Probe("/manager/html",    "Tomcat",                "Tomcat Manager exposed", Severity.HIGH),
            new Probe("/jenkins/login",   "Jenkins",               "Jenkins login page exposed", Severity.MEDIUM),
            new Probe("/grafana/login",   "Grafana",               "Grafana login page exposed", Severity.INFO),
            new Probe("/console",         "H2 Console",            "H2 database console exposed", Severity.HIGH),
            new Probe("/api/docs",        "",                      "/api/docs present (informational)", Severity.INFO),
            new Probe("/debug",           "",                      "/debug endpoint present (verify)", Severity.LOW),
            new Probe("/_profiler",       "Symfony Profiler",      "Symfony web profiler exposed", Severity.HIGH)
    );

    @Override public String id() { return ID; }
    @Override public String category() { return "Sensitive paths"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI base;
        try {
            URI seed = new URI(ctx.targetUrl());
            // Reduce to scheme://host[:port]
            base = new URI(seed.getScheme(), null, seed.getHost(), seed.getPort(), "/", null, null);
        } catch (Exception e) {
            return out;
        }

        for (Probe p : PROBES) {
            if (Thread.currentThread().isInterrupted()) break;
            String url = base.resolve(p.path()).toString();
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpResponse resp = ctx.sendRequest(req);
                if (resp == null) continue;
                int sc = resp.statusCode();
                if (sc != 200) continue;
                String body = resp.bodyToString();
                if (body == null) body = "";
                if (!p.matches(body)) continue;

                out.add(Finding.builder()
                        .checkId(ID + ".hit")
                        .title(p.description())
                        .severity(p.severity())
                        .confidence((p.regex() == null && p.marker().isEmpty()) ? Confidence.TENTATIVE : Confidence.FIRM)
                        .url(url)
                        .description("Probe `" + p.path() + "` returned 200"
                                + (p.regex() != null ? " and matched the content fingerprint."
                                                     : p.marker().isEmpty() ? "."
                                                     : " and matched marker `" + p.marker() + "`.")
                                + " Verify the resource is intentionally public and contains no sensitive data.")
                        .remediation("Restrict access at the web server / framework level, or remove the artifact from production. "
                                + "For .git/.env/backups: never deploy these to a publicly reachable directory.")
                        .evidence("URL: " + url + "\nStatus: " + sc + "\nBody excerpt:\n" + HttpUtil.truncate(body, 600))
                        .request(req)
                        .response(resp)
                        .build());
            } catch (Exception e) {
                ctx.api().logging().logToError("[analyze-target] sensitive-paths probe failed (" + url + "): " + e);
            }
        }
        return out;
    }
}
