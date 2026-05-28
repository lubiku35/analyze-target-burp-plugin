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
 * Probes a curated list of well-known API description endpoints and developer consoles —
 * Swagger / OpenAPI, GraphQL, Postman collections, RAML, API Blueprint, etc.
 *
 * Aligned with OWASP API Security Top 10 (2023) — A9 Improper Inventory Management — and
 * OWASP WSTG-CONF-05 (Enumerate Infrastructure and Application Admin Interfaces).
 *
 * Each hit is reported as a single low-severity finding (informational lean towards low because
 * a public API schema usually accelerates an attacker materially) and is keyed under
 * {@code api-discovery.hit} so the Summary's rule engine can suggest the right follow-up.
 */
public class ApiDiscoveryCheck implements Check {
    private static final String ID = "api-discovery";

    /** Endpoint candidate plus how to interpret a hit. Body matchers reduce false positives from generic 200 OK shells. */
    private record Candidate(String path, String label, String bodyHint) {}

    private static final List<Candidate> CANDIDATES = List.of(
            new Candidate("/swagger.json",            "OpenAPI/Swagger document",       "swagger"),
            new Candidate("/swagger.yaml",            "OpenAPI/Swagger document",       "swagger"),
            new Candidate("/openapi.json",            "OpenAPI document",               "openapi"),
            new Candidate("/openapi.yaml",            "OpenAPI document",               "openapi"),
            new Candidate("/api-docs",                "Swagger /api-docs",              "swagger"),
            new Candidate("/v2/api-docs",             "Springfox / Swagger v2 docs",    "swagger"),
            new Candidate("/v3/api-docs",             "Springdoc / Swagger v3 docs",    "openapi"),
            new Candidate("/swagger-ui",              "Swagger UI",                     "swagger"),
            new Candidate("/swagger-ui/",             "Swagger UI",                     "swagger"),
            new Candidate("/swagger-ui.html",         "Swagger UI",                     "swagger"),
            new Candidate("/swagger/index.html",      "Swagger UI",                     "swagger"),
            new Candidate("/api/swagger.json",        "Swagger doc under /api/",        "swagger"),
            new Candidate("/api/docs",                "Generic /api/docs",              null),
            new Candidate("/docs/",                   "Possible API docs route",        null),
            new Candidate("/redoc",                   "ReDoc OpenAPI viewer",           "redoc"),
            new Candidate("/redoc/",                  "ReDoc OpenAPI viewer",           "redoc"),
            new Candidate("/graphql",                 "GraphQL endpoint",               null),
            new Candidate("/graphql/",                "GraphQL endpoint",               null),
            new Candidate("/v1/graphql",              "GraphQL endpoint",               null),
            new Candidate("/api/graphql",             "GraphQL endpoint",               null),
            new Candidate("/graphiql",                "GraphiQL console",               "graphiql"),
            new Candidate("/playground",              "Apollo / GraphQL playground",    "playground"),
            new Candidate("/altair",                  "Altair GraphQL client",          null),
            new Candidate("/postman.json",            "Postman collection",             null),
            new Candidate("/api.raml",                "RAML API description",           null)
    );

    @Override public String id() { return ID; }
    @Override public String category() { return "API surface discovery"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI base;
        try { base = URI.create(ctx.targetUrl()); }
        catch (IllegalArgumentException e) { return out; }
        String origin = origin(base);
        if (origin == null) return out;

        // SPA-shell baseline.
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
                // 200 only — redirects to /login generate noise across most SPAs.
                if (code != 200) continue;
                String body = resp.bodyToString();
                String bodyLower = body == null ? "" : body.toLowerCase();
                int len = resp.body() == null ? 0 : resp.body().length();
                if (len < 16) continue;

                // For GraphQL endpoints, a 200 with "errors" / "data" / "Must provide query" usually means it's live.
                if (c.path().contains("graphql")) {
                    if (!(bodyLower.contains("graphql") || bodyLower.contains("must provide query")
                            || bodyLower.contains("\"data\"") || bodyLower.contains("\"errors\""))) {
                        continue;
                    }
                } else if (c.bodyHint() != null && !bodyLower.contains(c.bodyHint())) {
                    // A body hint was specified but didn't match → likely a generic 200 shell, skip.
                    continue;
                } else if (c.bodyHint() == null) {
                    // Candidate didn't carry a hint — fall back to SPA-shell detection.
                    if (seedLen > 0 && Math.abs(len - seedLen) < Math.max(50, seedLen / 20)) continue;
                }

                Severity sev = Severity.LOW;
                String description =
                        "Probed " + c.path() + " on the origin and received HTTP " + code + ". "
                      + "This looks like a " + c.label() + ".\n\n"
                      + "API description documents and interactive consoles are first-class enumeration "
                      + "targets — they typically advertise every endpoint, parameter, and authentication "
                      + "scheme the API exposes. Pull the schema and walk it for unauthenticated routes, "
                      + "mass-assignment opportunities, and IDORs.";
                String remediation =
                        "If the description is meant to be public this is a non-issue. If it isn't, "
                      + "restrict access (authenticated route, IP allow-list, or build-time exclusion). "
                      + "For GraphQL specifically: disable introspection in production "
                      + "(GraphQL.newSchema().build() with .fieldVisibility(NoIntrospectionGraphqlFieldVisibility))."
                      ;
                out.add(Finding.builder()
                        .checkId(ID + ".hit")
                        .title(c.label() + " exposed at " + c.path())
                        .severity(sev)
                        .confidence(Confidence.FIRM)
                        .url(url)
                        .description(description)
                        .remediation(remediation)
                        .evidence("Request: GET " + c.path() + "\nStatus: " + code
                                + "\nContent-Type: " + headerValue(resp, "Content-Type"))
                        .references(List.of(
                                "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
                                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"))
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
        } catch (Exception e) {
            return "";
        }
    }
}
