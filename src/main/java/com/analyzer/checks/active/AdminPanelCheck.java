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
import java.util.List;

/**
 * Enumerates well-known administrative / management interfaces — login pages, dashboards,
 * dev tooling. A reachable admin panel is a high-value pivot: default credentials, brute-force,
 * or known CVEs in the admin interface itself are all common paths to compromise.
 *
 * Aligned with OWASP WSTG-CONF-05 (Enumerate Infrastructure and Application Admin Interfaces).
 *
 * Each hit becomes one LOW finding (it's discovery, not a vuln on its own). The Summary's rule
 * engine elevates specific well-known panels (Tomcat Manager, Jenkins, Spring Actuator) to
 * concrete next-step suggestions.
 */
public class AdminPanelCheck implements Check {
    private static final String ID = "admin-panel";

    /**
     * Candidate path. {@code bodyMarker} is a case-insensitive substring that MUST appear in a
     * 200-OK response body for the hit to be reported — that's how we tell a real admin panel
     * from an SPA shell returning index.html for everything. {@code null} = accept any 200 that
     * isn't HTML or that has a non-trivial body.
     */
    private record Candidate(String path, String label, String bodyMarker) {}

    private static final List<Candidate> CANDIDATES = List.of(
            // Generic admin paths — require something that looks like a login form / admin chrome
            new Candidate("/admin",                  "Admin panel",                 "login"),
            new Candidate("/admin/",                 "Admin panel",                 "login"),
            new Candidate("/admin/login",            "Admin login",                 "password"),
            new Candidate("/administrator",          "Joomla administrator",        "joomla"),
            new Candidate("/administrator/",         "Joomla administrator",        "joomla"),
            new Candidate("/wp-admin/",              "WordPress admin",             "wp-"),
            new Candidate("/wp-login.php",           "WordPress login",             "wordpress"),
            new Candidate("/user/login",             "Drupal/generic login",        "login"),

            // Database tooling — these have well-known body markers
            new Candidate("/phpmyadmin/",            "phpMyAdmin",                  "phpmyadmin"),
            new Candidate("/adminer.php",            "Adminer",                     "adminer"),
            new Candidate("/adminer/",               "Adminer",                     "adminer"),
            new Candidate("/pma/",                   "phpMyAdmin (alt path)",       "phpmyadmin"),

            // Servlet containers / CI
            new Candidate("/manager/html",           "Tomcat Manager",              "tomcat"),
            new Candidate("/host-manager/html",      "Tomcat Host Manager",         "tomcat"),
            new Candidate("/jenkins/",               "Jenkins",                     "jenkins"),
            new Candidate("/jenkins/login",          "Jenkins login",               "jenkins"),
            new Candidate("/jmx-console",            "JBoss JMX console",           "jboss"),

            // Frameworks — Spring Actuator returns JSON (not HTML) when reachable
            new Candidate("/actuator",               "Spring Actuator root",        "_links"),
            new Candidate("/actuator/",              "Spring Actuator root",        "_links"),
            new Candidate("/actuator/health",        "Spring Actuator health",      "status"),
            new Candidate("/actuator/env",           "Spring Actuator env",         "propertySources"),
            new Candidate("/actuator/mappings",      "Spring Actuator mappings",    "mappings"),
            new Candidate("/actuator/loggers",       "Spring Actuator loggers",     "loggers"),
            new Candidate("/actuator/heapdump",      "Spring Actuator heap dump",   null),
            new Candidate("/management",             "Spring Boot management",      "_links"),
            new Candidate("/trace.axd",              "ASP.NET trace handler",       "application_trace"),
            new Candidate("/elmah.axd",              "ASP.NET ELMAH",               "elmah"),

            // Common dev tooling — each has a recognisable body marker
            new Candidate("/server-status",          "Apache server-status",        "apache server status"),
            new Candidate("/server-info",            "Apache server-info",          "server settings"),
            new Candidate("/__debug__/",             "Django debug",                "django"),
            new Candidate("/sidekiq",                "Sidekiq dashboard",           "sidekiq"),
            new Candidate("/rails/info/routes",      "Rails routes (dev mode)",     "routes")
    );

    @Override public String id() { return ID; }
    @Override public String category() { return "Admin interfaces"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI base;
        try { base = URI.create(ctx.targetUrl()); }
        catch (IllegalArgumentException e) { return out; }
        String origin = origin(base);
        if (origin == null) return out;

        // Snapshot the seed body length once — anything within ±5 % of it is treated as an SPA
        // shell catch-all rather than a real panel hit.
        int seedLen = ctx.seedResponse() == null || ctx.seedResponse().body() == null
                ? -1 : ctx.seedResponse().body().length();

        for (Candidate c : CANDIDATES) {
            if (Thread.currentThread().isInterrupted()) break;
            String url = origin + c.path();
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpResponse resp = ctx.sendRequest(req);
                if (resp == null) continue;
                int code = resp.statusCode();
                // 200 means it's serving content; 401/403 still means the panel exists and is just
                // gated. 3xx redirects are intentionally skipped — they are almost always a router
                // shipping the user to a login/index page and trigger massive false positives.
                if (!(code == 200 || code == 401 || code == 403)) continue;
                int len = resp.body() == null ? 0 : resp.body().length();
                if (code == 200 && len < 16) continue;

                if (code == 200) {
                    // Reject SPA shells: same body length as the seed (±5 %) is a router catch-all.
                    if (seedLen > 0 && Math.abs(len - seedLen) < Math.max(50, seedLen / 20)) continue;
                    // If the candidate declared a body marker, the response MUST contain it (case-insensitive).
                    if (c.bodyMarker() != null) {
                        String body = resp.bodyToString();
                        if (body == null || !body.toLowerCase().contains(c.bodyMarker().toLowerCase())) {
                            continue;
                        }
                    }
                }

                Severity sev = (code == 200) ? Severity.LOW : Severity.INFO;
                out.add(Finding.builder()
                        .checkId(ID + ".hit")
                        .title(c.label() + " reachable at " + c.path() + " (HTTP " + code + ")")
                        .severity(sev)
                        .confidence(Confidence.FIRM)
                        .url(url)
                        .description(
                                "The path " + c.path() + " returned HTTP " + code + " — consistent with a "
                              + c.label() + " being deployed at this origin.\n\n"
                              + "Administrative interfaces are first-class targets: try the product's "
                              + "default credentials, brute-force common usernames against the login form "
                              + "(throttle accordingly), and search for known CVEs in the panel software. "
                              + "Even a 401/403 confirms the route exists — many panels suffer from auth "
                              + "bypass tricks (header manipulation, path-traversal, role parameter abuse).\n\n"
                              + "Aligned with OWASP WSTG-CONF-05 (Enumerate Infrastructure and Application "
                              + "Admin Interfaces).")
                        .remediation(
                                "If the panel is needed in production, restrict access (VPN, IP allow-list, "
                              + "mTLS) and enforce strong auth + MFA. Where possible, separate the admin "
                              + "interface onto a non-public hostname so it never appears in scans.")
                        .evidence("Status: " + code
                                + "\nContent-Length: " + len
                                + "\nServer: " + headerValue(resp, "Server"))
                        .references(List.of(
                                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"))
                        .request(req)
                        .response(resp)
                        .build());
            } catch (Exception e) {
                ctx.api().logging().logToError("[analyze-target] " + ID + ": " + url + " failed: " + e);
            }
        }
        return out;
    }

    private static String origin(URI u) {
        String scheme = u.getScheme();
        String host = u.getHost();
        if (scheme == null || host == null) return null;
        int port = u.getPort();
        if (port == -1) return scheme + "://" + host;
        return scheme + "://" + host + ":" + port;
    }

    private static String headerValue(HttpResponse resp, String name) {
        try {
            return resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase(name))
                    .map(h -> h.value()).findFirst().orElse("");
        } catch (Exception e) { return ""; }
    }
}
