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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pulls the seed response, scrapes <script src="…"> URLs, fetches each referenced JS file,
 * and greps for high-value patterns: API keys, JWTs, internal hostnames, AWS access keys, paths.
 *
 * Borderline-active: it does send HTTP requests for the linked JS files (which the browser would
 * fetch anyway), but it doesn't probe the target outside what the page already references.
 */
public class JavaScriptGrepCheck implements Check {
    private static final String ID = "js-grep";
    private static final int MAX_SCRIPTS = 25;
    private static final int MAX_BODY_BYTES = 1024 * 1024; // 1 MB cap per JS file

    private static final Pattern SCRIPT_SRC =
            Pattern.compile("<script[^>]*\\ssrc=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);

    /** name → regex. Ordered, deterministic findings. */
    private static final Map<String, Pattern> SECRET_PATTERNS = new LinkedHashMap<>();
    static {
        SECRET_PATTERNS.put("AWS access key ID",     Pattern.compile("\\bAKIA[0-9A-Z]{16}\\b"));
        SECRET_PATTERNS.put("AWS secret access key", Pattern.compile("(?i)aws_secret[_a-z]*\\s*[:=]\\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"));
        SECRET_PATTERNS.put("Google API key",        Pattern.compile("\\bAIza[0-9A-Za-z\\-_]{35}\\b"));
        SECRET_PATTERNS.put("Slack token",           Pattern.compile("\\bxox[abprs]-[0-9A-Za-z\\-]{10,72}\\b"));
        SECRET_PATTERNS.put("GitHub PAT",            Pattern.compile("\\bghp_[A-Za-z0-9]{36}\\b|\\bgithub_pat_[A-Za-z0-9_]{82}\\b"));
        SECRET_PATTERNS.put("Stripe live key",       Pattern.compile("\\bsk_live_[0-9a-zA-Z]{24,99}\\b"));
        SECRET_PATTERNS.put("Generic JWT",           Pattern.compile("\\beyJ[A-Za-z0-9_=-]{10,}\\.[A-Za-z0-9_=-]{10,}\\.[A-Za-z0-9_.+/=-]{10,}\\b"));
        SECRET_PATTERNS.put("Private key block",     Pattern.compile("-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) (?:PRIVATE )?KEY-----"));
        SECRET_PATTERNS.put("Bearer token assignment", Pattern.compile("(?i)bearer\\s+[A-Za-z0-9._\\-]{20,}"));
    }

    private static final Pattern ENDPOINT_PATTERN =
            Pattern.compile("[\"'](/?(?:api|v[0-9]+|graphql|rest|admin|internal)/[A-Za-z0-9_\\-./{}]+)[\"']");
    private static final Pattern INTERNAL_HOST =
            Pattern.compile("\\b(?:[a-z0-9-]+\\.)?(?:internal|local|corp|intranet|lan|test|dev|staging|qa)\\.[a-z0-9.-]+");

    @Override public String id() { return ID; }
    @Override public String category() { return "JavaScript grep"; }
    @Override public boolean isActive() { return true; } // fetches linked JS

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse seed = ctx.seedResponse();
        if (seed == null) return out;
        String body = seed.bodyToString();
        if (body == null || body.isEmpty()) return out;
        // Cap seed body scan to 1 MiB to bound regex CPU.
        if (body.length() > MAX_BODY_BYTES) body = body.substring(0, MAX_BODY_BYTES);

        URI base;
        try {
            base = URI.create(ctx.targetUrl());
        } catch (IllegalArgumentException e) {
            return out;
        }

        // Always grep the seed body itself
        grep(out, ctx.targetUrl(), body, "(seed response body)", HttpUtil.requestSnippet(ctx.seedRequest()),
                HttpUtil.responseSnippet(seed, 0));

        // Discover and fetch linked scripts
        Set<String> seen = new LinkedHashSet<>();
        Matcher m = SCRIPT_SRC.matcher(body);
        while (m.find() && seen.size() < MAX_SCRIPTS) {
            String src = m.group(1).trim();
            if (src.isEmpty() || src.startsWith("data:")) continue;
            URI resolved;
            try {
                resolved = base.resolve(src);
            } catch (IllegalArgumentException e) {
                continue;
            }
            if (!"http".equalsIgnoreCase(resolved.getScheme()) && !"https".equalsIgnoreCase(resolved.getScheme())) continue;
            seen.add(resolved.toString());
        }

        for (String jsUrl : seen) {
            if (Thread.currentThread().isInterrupted()) break;
            try {
                HttpRequest jsReq = HttpRequest.httpRequestFromUrl(jsUrl);
                HttpResponse jsResp = ctx.cachedGet(jsReq); // shared with link-extract — fetch each JS once
                if (jsResp == null || jsResp.statusCode() >= 400) continue;
                String jsBody = jsResp.bodyToString();
                if (jsBody == null || jsBody.isEmpty()) continue;
                if (jsBody.length() > MAX_BODY_BYTES) jsBody = jsBody.substring(0, MAX_BODY_BYTES);
                grep(out, jsUrl, jsBody, jsUrl, HttpUtil.requestSnippet(jsReq), HttpUtil.responseSnippet(jsResp, 0));
            } catch (Exception e) {
                ctx.api().logging().logToError("[analyze-target] js-grep: failed to fetch " + jsUrl + ": " + e);
            }
        }
        return out;
    }

    private void grep(List<Finding> out, String url, String body, String source,
                      String reqSnip, String respSnip) {
        // Secrets
        Set<String> dedup = new HashSet<>();
        for (Map.Entry<String, Pattern> e : SECRET_PATTERNS.entrySet()) {
            Matcher m = e.getValue().matcher(body);
            while (m.find()) {
                String match = m.group();
                if (!dedup.add(e.getKey() + "|" + match)) continue;
                out.add(Finding.builder()
                        .checkId(ID + ".secret")
                        .title("Possible secret in JavaScript: " + e.getKey())
                        .severity(Severity.HIGH)
                        .confidence(Confidence.TENTATIVE)
                        .url(url)
                        .description("Regex for `" + e.getKey() + "` matched content served by the application. "
                                + "Manual verification recommended - many matches are false positives (test fixtures, "
                                + "public keys, library samples).")
                        .remediation("If genuine, rotate the credential immediately, remove it from client-side code, "
                                + "and audit access logs for misuse.")
                        .evidence("Source: " + source + "\nMatch: " + HttpUtil.truncate(match, 200))
                        .requestSnippet(reqSnip)
                        .responseSnippet(respSnip)
                        .build()); // JS grep uses pre-rendered snippets from multiple JS fetches
            }
        }

        // Endpoints
        Set<String> endpoints = new LinkedHashSet<>();
        Matcher ep = ENDPOINT_PATTERN.matcher(body);
        while (ep.find() && endpoints.size() < 50) endpoints.add(ep.group(1));
        if (!endpoints.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".endpoints")
                    .title("API endpoints discovered in JavaScript (" + endpoints.size() + ")")
                    .severity(Severity.INFO)
                    .confidence(Confidence.FIRM)
                    .url(url)
                    .description("JavaScript references " + endpoints.size() + " API-like paths. "
                            + "Inventory them for additional attack surface (auth requirements, IDOR, mass assignment).")
                    .remediation("N/A - informational. Review each endpoint for proper authentication and authorisation.")
                    .evidence("Source: " + source + "\n" + String.join("\n", endpoints))
                    .requestSnippet(reqSnip)
                    .responseSnippet(respSnip)
                    .build());
        }

        // Internal hostnames
        Set<String> hosts = new LinkedHashSet<>();
        Matcher ih = INTERNAL_HOST.matcher(body);
        while (ih.find() && hosts.size() < 20) hosts.add(ih.group());
        if (!hosts.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".internal-hosts")
                    .title("Internal/non-prod hostnames referenced in JavaScript")
                    .severity(Severity.LOW)
                    .confidence(Confidence.TENTATIVE)
                    .url(url)
                    .description("References to internal/dev/staging hosts in client-side code reveal infrastructure topology.")
                    .remediation("Strip dev/staging hostnames from production builds. Use build-time environment variables.")
                    .evidence("Source: " + source + "\n" + String.join("\n", hosts))
                    .requestSnippet(reqSnip)
                    .responseSnippet(respSnip)
                    .build());
        }
    }
}
