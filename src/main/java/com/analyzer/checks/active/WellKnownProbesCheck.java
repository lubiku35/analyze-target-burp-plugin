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
 * Pulls well-known descriptor files under {@code /.well-known/} — security.txt,
 * change-password (RFC 5785-style discovery), assetlinks.json, apple-app-site-association,
 * openid-configuration, oauth-authorization-server.
 *
 * Each hit is informational on its own but high-yield in context. {@code security.txt} reveals
 * vulnerability-report contact channels; OIDC/OAuth descriptors reveal auth-server URLs,
 * supported algorithms, and registered scopes; mobile-app association files reveal
 * cross-platform deep-link mappings.
 *
 * Aligned with OWASP WSTG-INFO-09 (Fingerprint Web Application) and the Web Application
 * Hacker's Handbook's "review every well-known descriptor file you can reach" maxim.
 */
public class WellKnownProbesCheck implements Check {
    private static final String ID = "well-known";

    private record Candidate(String path, String label, Severity sev) {}

    private static final List<Candidate> CANDIDATES = List.of(
            new Candidate("/.well-known/security.txt",                    "security.txt — disclosure contacts", Severity.INFO),
            new Candidate("/security.txt",                                "security.txt (legacy location)",     Severity.INFO),
            new Candidate("/.well-known/change-password",                 "change-password discovery",          Severity.INFO),
            new Candidate("/.well-known/openid-configuration",            "OpenID Connect discovery document",  Severity.LOW),
            new Candidate("/.well-known/oauth-authorization-server",      "OAuth 2.0 AS metadata",              Severity.LOW),
            new Candidate("/.well-known/jwks.json",                       "JWKS (public signing keys)",         Severity.INFO),
            new Candidate("/.well-known/assetlinks.json",                 "Android Asset Links",                Severity.INFO),
            new Candidate("/.well-known/apple-app-site-association",      "Apple App-Site Association",         Severity.INFO),
            new Candidate("/.well-known/matrix/server",                   "Matrix server descriptor",           Severity.INFO),
            new Candidate("/.well-known/host-meta",                       "Host-meta (XRD)",                    Severity.INFO),
            new Candidate("/.well-known/webfinger",                       "Webfinger discovery",                Severity.INFO),
            new Candidate("/humans.txt",                                  "humans.txt — author manifest",       Severity.INFO),
            new Candidate("/sitemap_index.xml",                           "Sitemap index",                      Severity.INFO),
            new Candidate("/sitemap.xml.gz",                              "Compressed sitemap",                 Severity.INFO),
            new Candidate("/ads.txt",                                     "ads.txt — ad seller manifest",       Severity.INFO),
            new Candidate("/app-ads.txt",                                 "app-ads.txt manifest",               Severity.INFO)
    );

    @Override public String id() { return ID; }
    @Override public String category() { return "Well-known descriptors"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI base;
        try { base = URI.create(ctx.targetUrl()); }
        catch (IllegalArgumentException e) { return out; }
        String origin = origin(base);
        if (origin == null) return out;

        // Most well-known descriptors are served as text/plain, application/json, or application/jrd+json.
        // SPA shells serve text/html for everything. Snapshot seed body length for shell detection too.
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
                // 200 only — 3xx are router redirects, not real descriptor hits.
                if (code != 200) continue;
                int len = resp.body() == null ? 0 : resp.body().length();
                if (len < 8) continue;

                // Reject responses that look like the SPA shell.
                String contentType = header(resp, "Content-Type").toLowerCase();
                if (contentType.contains("text/html")) continue;
                String head = resp.bodyToString();
                if (head != null) {
                    String lower = head.substring(0, Math.min(head.length(), 256)).toLowerCase();
                    if (lower.contains("<!doctype html") || lower.contains("<html")) continue;
                }
                if (seedLen > 0 && Math.abs(len - seedLen) < Math.max(50, seedLen / 20)) continue;
                out.add(Finding.builder()
                        .checkId(ID + ".hit")
                        .title(c.label() + " at " + c.path() + " (HTTP " + code + ")")
                        .severity(c.sev())
                        .confidence(Confidence.FIRM)
                        .url(url)
                        .description(
                                "The path " + c.path() + " is reachable (HTTP " + code + "). "
                              + "This is a well-known descriptor file. Most are informational on their "
                              + "own but the contents often unlock material follow-ups:\n\n"
                              + "  • security.txt — disclosure contact, scope, encryption key.\n"
                              + "  • OpenID/OAuth descriptors — authorization endpoint URLs, scopes, "
                              + "supported algorithms (alg=none / RS256 / HS256 attack surface).\n"
                              + "  • Apple/Android app-association files — universal-link / deep-link "
                              + "mappings into the mobile app, which often expose unauthenticated APIs.")
                        .remediation(
                                "Well-known files are usually intended to be public. The only check "
                              + "worth doing is confirming the contents are intentional and not leaking "
                              + "test/dev configuration that doesn't belong in production.")
                        .evidence("Status: " + code + "\nContent-Length: " + len
                                + "\nContent-Type: " + header(resp, "Content-Type"))
                        .references(List.of(
                                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/09-Fingerprint_Web_Application",
                                "https://www.rfc-editor.org/rfc/rfc8615",
                                "https://www.rfc-editor.org/rfc/rfc9116"))
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

    private static String header(HttpResponse resp, String name) {
        try {
            return resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase(name))
                    .map(h -> h.value()).findFirst().orElse("");
        } catch (Exception e) { return ""; }
    }
}
