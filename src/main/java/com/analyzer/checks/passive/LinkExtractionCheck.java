package com.analyzer.checks.passive;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Crawls the seed response for links (href/src/action/data-*) and then <em>recursively</em>
 * resolves the discovered JavaScript files, looking for additional URL references inside their
 * contents. The output is two findings:
 *
 *   <ul>
 *     <li><b>link-extract.internal</b> — every same-origin path/URL discovered, deduped and capped.</li>
 *     <li><b>link-extract.external</b> — links pointing to <em>different</em> hosts (third-party CDNs,
 *         analytics, embedded widgets) — useful for attack-surface fingerprinting.</li>
 *   </ul>
 *
 * The findings feed the Summary panel via {@code link-extract.*} so the inventory shows in the
 * "JavaScript &amp; links" card.
 *
 * Aligned with OWASP WSTG-INFO-04 (Enumerate Applications on Webserver) and -INFO-07 (Map
 * Execution Paths). References to source code, comments, and JS files are some of the most
 * reliable cheap-to-collect signals during initial enumeration.
 */
public class LinkExtractionCheck implements Check {
    private static final String ID = "link-extract";

    /** Hard caps to keep the check bounded on huge pages. */
    private static final int MAX_TOTAL_LINKS  = 600;
    private static final int MAX_JS_FETCHES   = 25;
    private static final int MAX_BODY_BYTES   = 1024 * 1024; // 1 MiB per response
    private static final int RECURSION_DEPTH  = 1;            // crawl seed → its JS files (no deeper)

    // src="…" / href="…" / action="…" / data-*="…"
    private static final Pattern HTML_ATTR = Pattern.compile(
            "(?:src|href|action|data-[a-z0-9_-]+)\\s*=\\s*[\"']([^\"'#>]+)[\"']",
            Pattern.CASE_INSENSITIVE);

    // URLs that appear in JS source: '/api/foo', "https://x.example/bar", `path/to/x` etc.
    private static final Pattern JS_URL = Pattern.compile(
            "[\"'`](" +
                    "(?:https?:)?//[A-Za-z0-9._\\-~%:/?#\\[\\]@!$&'()*+,;=]+|" + // absolute
                    "/[A-Za-z0-9._\\-~%/?#\\[\\]@!$&'()*+,;=]+" +                // root-relative
            ")[\"'`]");

    // OpenAPI/Swagger/GraphQL fingerprints we want to flag separately for the Summary follow-ups.
    private static final Pattern API_FINGERPRINT = Pattern.compile(
            "(?i)(?:swagger|openapi|graphql|graphiql|playground)");

    @Override public String id() { return ID; }
    @Override public String category() { return "Link & path discovery"; }
    @Override public boolean isActive() { return true; } // fetches linked JS recursively

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse seed = ctx.seedResponse();
        if (seed == null) return out;
        String body = seed.bodyToString();
        if (body == null || body.isEmpty()) return out;
        if (body.length() > MAX_BODY_BYTES) body = body.substring(0, MAX_BODY_BYTES);

        URI base;
        String targetHost;
        try {
            base = URI.create(ctx.targetUrl());
            targetHost = base.getHost() == null ? "" : base.getHost().toLowerCase();
        } catch (IllegalArgumentException e) {
            return out;
        }

        // BFS-style crawl, depth-limited. The seed is depth 0; its JS files are depth 1.
        Set<String> internal = new LinkedHashSet<>();
        Set<String> external = new LinkedHashSet<>();
        Set<String> apiHits  = new LinkedHashSet<>();
        Set<String> jsToFetch = new LinkedHashSet<>();
        Set<String> visited  = new HashSet<>();

        // Pass 1: extract links from the seed HTML.
        extractFromHtml(body, base, targetHost, internal, external, jsToFetch);

        // Pass 2: pull links out of JS files referenced by the seed.
        Deque<String> queue = new ArrayDeque<>(jsToFetch);
        int fetched = 0;
        while (!queue.isEmpty() && fetched < MAX_JS_FETCHES) {
            if (Thread.currentThread().isInterrupted()) break;
            String jsUrl = queue.pop();
            if (!visited.add(jsUrl)) continue;
            try {
                HttpRequest jsReq = HttpRequest.httpRequestFromUrl(jsUrl);
                HttpResponse jsResp = ctx.cachedGet(jsReq); // shared with js-grep — fetch each JS once
                fetched++;
                if (jsResp == null || jsResp.statusCode() >= 400) continue;
                String jsBody = jsResp.bodyToString();
                if (jsBody == null || jsBody.isEmpty()) continue;
                if (jsBody.length() > MAX_BODY_BYTES) jsBody = jsBody.substring(0, MAX_BODY_BYTES);
                extractFromJs(jsBody, base, targetHost, internal, external);
                // Note any API surface fingerprints (Swagger/GraphQL/etc.) for the Summary rules.
                Matcher af = API_FINGERPRINT.matcher(jsBody);
                while (af.find()) apiHits.add(af.group().toLowerCase());
            } catch (Exception e) {
                ctx.api().logging().logToError("[analyze-target] link-extract: failed to fetch " + jsUrl + ": " + e);
            }
        }

        // Cap final outputs.
        List<String> internalList = capped(internal);
        List<String> externalList = capped(external);

        if (!internalList.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".internal")
                    .title("Discovered " + internalList.size() + " same-origin paths in HTML + JavaScript")
                    .severity(Severity.INFO)
                    .confidence(Confidence.FIRM)
                    .url(ctx.targetUrl())
                    .description(
                            "Crawled the seed response for href/src/action attributes and recursively "
                          + "scanned the referenced JavaScript files for URL-shaped tokens. The result "
                          + "is an inventory of same-origin paths the application uses. This is one of "
                          + "the highest-yield enumeration techniques during initial recon: client-side "
                          + "code typically references every endpoint the application can call, "
                          + "including ones not reachable through the UI you happened to click through.\n\n"
                          + "Aligned with OWASP WSTG-INFO-04 (Enumerate Applications on Webserver) and "
                          + "WSTG-INFO-07 (Map Execution Paths Through Application).")
                    .remediation(
                            "Informational. Walk the list manually and feed interesting paths into Burp's "
                          + "Repeater for further testing. Look for admin-only endpoints, debug routes, "
                          + "or unauthenticated APIs.")
                    .evidence(String.join("\n", internalList))
                    .references(List.of(
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver",
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application"))
                    .request(ctx.seedRequest())
                    .response(seed)
                    .build());
        }

        if (!externalList.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".external")
                    .title("Third-party hosts referenced (" + externalList.size() + ")")
                    .severity(Severity.INFO)
                    .confidence(Confidence.FIRM)
                    .url(ctx.targetUrl())
                    .description(
                            "Links to hosts other than the target. Useful for fingerprinting third-party "
                          + "dependencies (analytics, CDNs, embedded SDKs). Any third-party origin that "
                          + "executes JavaScript on the target's page becomes part of the trust boundary "
                          + "— a compromise there typically chains into the target.")
                    .remediation(
                            "Inventory each origin. Consider whether it should be replaced with a "
                          + "self-hosted copy or constrained via CSP (script-src / connect-src).")
                    .evidence(String.join("\n", externalList))
                    .references(List.of(
                            "https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"))
                    .request(ctx.seedRequest())
                    .response(seed)
                    .build());
        }

        if (!apiHits.isEmpty()) {
            out.add(Finding.builder()
                    .checkId("api-discovery.hit")
                    .title("API documentation/console fingerprint in JavaScript: " + String.join(", ", apiHits))
                    .severity(Severity.LOW)
                    .confidence(Confidence.TENTATIVE)
                    .url(ctx.targetUrl())
                    .description(
                            "Strings such as 'swagger', 'openapi', 'graphql', 'graphiql' appear in the "
                          + "site's JavaScript. That usually means a machine-readable API definition or "
                          + "interactive console is hosted somewhere on the target. Either is gold for "
                          + "enumeration: pulling the schema gives you every endpoint and parameter the "
                          + "application exposes.")
                    .remediation(
                            "If the API description is meant to be public, this is a non-issue. If it "
                          + "isn't, restrict access to it or remove it from production builds.")
                    .evidence("Markers: " + String.join(", ", apiHits))
                    .references(List.of(
                            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                            "https://swagger.io/docs/specification/about/"))
                    .request(ctx.seedRequest())
                    .response(seed)
                    .build());
        }
        return out;
    }

    /** Pull href/src/action/data-* values from the seed HTML; bucket internal vs external; queue JS files. */
    private static void extractFromHtml(String body, URI base, String targetHost,
                                        Set<String> internal, Set<String> external, Set<String> jsToFetch) {
        Matcher m = HTML_ATTR.matcher(body);
        while (m.find()) {
            if (internal.size() + external.size() >= MAX_TOTAL_LINKS) break;
            String raw = m.group(1).trim();
            if (raw.isEmpty() || raw.startsWith("data:") || raw.startsWith("javascript:")
                    || raw.startsWith("mailto:") || raw.startsWith("tel:") || raw.startsWith("#")) continue;
            URI resolved = safeResolve(base, raw);
            if (resolved == null) continue;
            String scheme = resolved.getScheme();
            if (scheme != null && !scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https")) continue;

            String host = resolved.getHost();
            boolean sameHost = host == null || host.equalsIgnoreCase(targetHost);
            if (sameHost) {
                internal.add(resolved.getRawPath() + (resolved.getRawQuery() == null ? "" : "?" + resolved.getRawQuery()));
            } else {
                external.add(resolved.getScheme() + "://" + host);
            }
            if (resolved.getRawPath() != null && resolved.getRawPath().toLowerCase().endsWith(".js") && sameHost) {
                if (jsToFetch.size() < MAX_JS_FETCHES) jsToFetch.add(resolved.toString());
            }
        }
    }

    /** Pull URL-shaped strings from a JS file's body. Same bucketing as the HTML pass. */
    private static void extractFromJs(String jsBody, URI base, String targetHost,
                                      Set<String> internal, Set<String> external) {
        Matcher m = JS_URL.matcher(jsBody);
        while (m.find()) {
            if (internal.size() + external.size() >= MAX_TOTAL_LINKS) break;
            String raw = m.group(1).trim();
            if (raw.isEmpty()) continue;
            URI resolved = safeResolve(base, raw);
            if (resolved == null) continue;
            String scheme = resolved.getScheme();
            if (scheme != null && !scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https")) continue;

            String host = resolved.getHost();
            boolean sameHost = host == null || host.equalsIgnoreCase(targetHost);
            if (sameHost) {
                String path = resolved.getRawPath();
                if (path != null && !path.isEmpty()) internal.add(path);
            } else {
                external.add(resolved.getScheme() + "://" + host);
            }
        }
    }

    private static URI safeResolve(URI base, String ref) {
        try { return base.resolve(new URI(ref)); }
        catch (URISyntaxException | IllegalArgumentException e) { return null; }
    }

    private static List<String> capped(Set<String> source) {
        List<String> out = new ArrayList<>(source);
        if (out.size() > 200) return out.subList(0, 200);
        return out;
    }
}
