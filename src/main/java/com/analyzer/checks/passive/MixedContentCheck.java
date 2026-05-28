package com.analyzer.checks.passive;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans an HTTPS page for resources loaded over plaintext HTTP — classical "mixed content".
 *
 * Aligned with OWASP WSTG-CRYP-03 (Testing for Sensitive Information Sent via Unencrypted
 * Channels) and the OWASP Transport Layer Security Cheat Sheet. Active mixed content
 * (scripts, frames, XHR) gets blocked by modern browsers; passive mixed content (images,
 * media) silently downgrades the page's security guarantees.
 */
public class MixedContentCheck implements Check {
    private static final String ID = "mixed-content";

    // src= or href= pointing at http:// (with optional whitespace)
    private static final Pattern HTTP_RESOURCE = Pattern.compile(
            "(?:src|href)\\s*=\\s*[\"'](http://[^\"'#>]+)[\"']",
            Pattern.CASE_INSENSITIVE);

    @Override public String id() { return ID; }
    @Override public String category() { return "Transport security"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        if (ctx.seedRequest() == null) return out;
        String url = ctx.targetUrl();
        if (url == null || !url.toLowerCase().startsWith("https://")) return out; // only meaningful on HTTPS pages

        HttpResponse seed = ctx.seedResponse();
        if (seed == null) return out;
        String body = seed.bodyToString();
        if (body == null || body.isEmpty()) return out;

        Set<String> hits = new LinkedHashSet<>();
        Matcher m = HTTP_RESOURCE.matcher(body);
        while (m.find()) {
            String href = m.group(1);
            // Exclude well-known constants that aren't really fetched (XML namespaces, schema URIs).
            String lower = href.toLowerCase();
            if (lower.contains("w3.org/") || lower.contains("xmlns") || lower.contains("//purl.org/")
                    || lower.contains("schemas.")) continue;
            hits.add(href);
            if (hits.size() >= 50) break;
        }

        if (hits.isEmpty()) return out;
        out.add(Finding.builder()
                .checkId(ID)
                .title("Mixed content: HTTPS page references " + hits.size() + " plaintext HTTP resource(s)")
                .severity(Severity.LOW)
                .confidence(Confidence.FIRM)
                .url(url)
                .description(
                        "This HTTPS page loads resources over plaintext HTTP. Modern browsers block "
                      + "active mixed content (scripts, iframes, XHR) outright; passive mixed content "
                      + "(images, fonts, media) still loads but is tamper-able by any on-path attacker "
                      + "and quietly weakens the page's security guarantees. Even one mixed reference "
                      + "can defeat the Strict-Transport-Security guarantees the page otherwise enjoys.\n\n"
                      + "Aligned with OWASP WSTG-CRYP-03 (Testing for Sensitive Information Sent via "
                      + "Unencrypted Channels).")
                .remediation(
                        "Switch every resource reference to HTTPS or to protocol-relative URLs (//host/...). "
                      + "Add a Content-Security-Policy with 'upgrade-insecure-requests' to have the browser "
                      + "promote http:// references at load time. Long-term: configure CSP's "
                      + "'block-all-mixed-content' (deprecated but widely supported as a safety net).")
                .evidence(String.join("\n", hits))
                .references(List.of(
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"))
                .request(ctx.seedRequest())
                .response(seed)
                .build());
        return out;
    }
}
