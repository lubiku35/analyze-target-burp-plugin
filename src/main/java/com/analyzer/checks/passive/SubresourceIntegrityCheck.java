package com.analyzer.checks.passive;

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
 * Checks whether third-party {@code <script>} / {@code <link rel="stylesheet">} references on the
 * seed page carry an {@code integrity=} attribute (Subresource Integrity).
 *
 * Without SRI, a compromised third-party CDN can deliver attacker-controlled JavaScript to every
 * visitor. The risk is well-understood and the mitigation is mechanical, so this is a low-noise
 * recommendation to bundle into the deliverable.
 *
 * Aligned with the OWASP HTML Security Cheat Sheet's SRI section and MDN's SRI guide.
 */
public class SubresourceIntegrityCheck implements Check {
    private static final String ID = "sri";

    private static final Pattern SCRIPT_TAG =
            Pattern.compile("<script\\b[^>]*\\bsrc\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern LINK_TAG =
            Pattern.compile("<link\\b[^>]*\\brel\\s*=\\s*[\"']stylesheet[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern HAS_INTEGRITY = Pattern.compile("\\bintegrity\\s*=", Pattern.CASE_INSENSITIVE);
    private static final Pattern HREF_IN_LINK  = Pattern.compile("\\bhref\\s*=\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);

    @Override public String id() { return ID; }
    @Override public String category() { return "Subresource integrity"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse seed = ctx.seedResponse();
        if (seed == null) return out;
        String body = seed.bodyToString();
        if (body == null || body.isEmpty()) return out;

        URI base;
        String targetHost;
        try {
            base = URI.create(ctx.targetUrl());
            targetHost = base.getHost() == null ? "" : base.getHost().toLowerCase();
        } catch (IllegalArgumentException e) { return out; }

        Set<String> missing = new LinkedHashSet<>();

        // <script src="…">
        Matcher m = SCRIPT_TAG.matcher(body);
        while (m.find()) {
            String tag = m.group();
            String src = m.group(1);
            if (!isCrossOrigin(src, base, targetHost)) continue;
            if (!HAS_INTEGRITY.matcher(tag).find()) missing.add("script: " + src);
        }

        // <link rel="stylesheet" href="…">
        Matcher lm = LINK_TAG.matcher(body);
        while (lm.find()) {
            String tag = lm.group();
            Matcher hm = HREF_IN_LINK.matcher(tag);
            if (!hm.find()) continue;
            String href = hm.group(1);
            if (!isCrossOrigin(href, base, targetHost)) continue;
            if (!HAS_INTEGRITY.matcher(tag).find()) missing.add("stylesheet: " + href);
        }

        if (missing.isEmpty()) return out;
        out.add(Finding.builder()
                .checkId(ID + ".missing")
                .title("Cross-origin <script>/<link> tags without integrity= (" + missing.size() + ")")
                .severity(Severity.LOW)
                .confidence(Confidence.FIRM)
                .url(ctx.targetUrl())
                .description(
                        "The page loads " + missing.size() + " cross-origin script(s)/stylesheet(s) "
                      + "without a Subresource Integrity hash. If any of those origins is compromised "
                      + "(or routes through a hostile network), the attacker can deliver tampered "
                      + "JavaScript to every visitor.\n\n"
                      + "SRI is a one-line mitigation: add an `integrity=\"sha384-...\" crossorigin=\"anonymous\"` "
                      + "attribute and the browser refuses to execute the resource when the hash doesn't "
                      + "match.")
                .remediation(
                        "Generate SRI hashes (e.g. with `openssl dgst -sha384 -binary file.js | openssl "
                      + "base64 -A`) for each cross-origin resource and add the `integrity` attribute. "
                      + "When a CDN serves a versioned URL the hash is stable; when it serves a moving "
                      + "target (e.g. `latest.min.js`), pin a specific version first.")
                .evidence(String.join("\n", missing))
                .references(List.of(
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#subresource-integrity",
                        "https://www.w3.org/TR/SRI/"))
                .request(ctx.seedRequest())
                .response(seed)
                .build());
        return out;
    }

    /** True when ref is an http(s) URL whose host differs from the seed's host. */
    private static boolean isCrossOrigin(String ref, URI base, String targetHost) {
        if (ref == null || ref.isBlank()) return false;
        try {
            URI u = base.resolve(ref);
            String scheme = u.getScheme();
            if (scheme == null) return false;
            if (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https")) return false;
            String host = u.getHost();
            return host != null && !host.equalsIgnoreCase(targetHost);
        } catch (Exception e) { return false; }
    }
}
