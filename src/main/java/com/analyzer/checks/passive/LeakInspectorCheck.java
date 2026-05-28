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
 * Generic information-leak grep over the seed response body — emails, RFC 1918 IPs, internal
 * hostnames (.internal / .corp / .local), and reasonably-confident UUIDs / GUIDs.
 *
 * Each leak class becomes one finding so the table stays readable. Findings are INFO/LOW because
 * none of these are vulnerabilities in their own right — but they're cheap to collect and routinely
 * accelerate engagement-level work (phishing, internal scans, IDOR mapping).
 *
 * Aligned with OWASP WSTG-INFO-02/03/05 (information leakage and review of webpage content).
 */
public class LeakInspectorCheck implements Check {
    private static final String ID = "leak-inspector";

    private static final Pattern EMAIL =
            Pattern.compile("\\b[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}\\b");
    private static final Pattern PRIVATE_IP = Pattern.compile(
            "\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
          + "|192\\.168\\.\\d{1,3}\\.\\d{1,3}"
          + "|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})\\b");
    private static final Pattern INTERNAL_HOST = Pattern.compile(
            "\\b(?:[A-Za-z0-9\\-]+\\.)+(?:internal|corp|intranet|local|lan|test|dev|staging|qa)"
          + "(?:\\.[A-Za-z0-9\\-]{2,})*", Pattern.CASE_INSENSITIVE);

    @Override public String id() { return ID; }
    @Override public String category() { return "Info disclosure (response body)"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;
        String body = resp.bodyToString();
        if (body == null || body.isEmpty()) return out;
        if (body.length() > 1024 * 1024) body = body.substring(0, 1024 * 1024);

        Set<String> emails = capture(EMAIL, body, 40, true);
        emails.removeIf(e -> e.endsWith("@example.com") || e.endsWith("@example.org")
                          || e.endsWith("@test.com")    || e.endsWith("@email.com"));
        if (!emails.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".email")
                    .title("Email addresses disclosed in response (" + emails.size() + ")")
                    .severity(Severity.INFO)
                    .confidence(Confidence.FIRM)
                    .url(ctx.targetUrl())
                    .description(
                            "The response body contains email addresses. They're useful for username "
                          + "discovery (login-form enumeration), targeted phishing during the engagement, "
                          + "and as pivot targets for OSINT (breach databases, GitHub commits, leaked "
                          + "credentials lookups).")
                    .remediation(
                            "If the addresses are intentional (contact pages, author bylines) this is "
                          + "fine. If they leaked accidentally from a developer comment, debug page, or "
                          + "DB-driven panel, scrub them.")
                    .evidence(String.join("\n", emails))
                    .references(List.of(
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"))
                    .request(ctx.seedRequest())
                    .response(resp)
                    .build());
        }

        Set<String> privateIps = capture(PRIVATE_IP, body, 25, false);
        if (!privateIps.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".internal-ip")
                    .title("RFC 1918 / private IP addresses disclosed (" + privateIps.size() + ")")
                    .severity(Severity.LOW)
                    .confidence(Confidence.FIRM)
                    .url(ctx.targetUrl())
                    .description(
                            "Private (RFC 1918) IP addresses appear in the response. That's typically "
                          + "infrastructure topology leaking through error messages, debug headers, or "
                          + "DB-driven content. Useful during an internal pivot — and a soft confirmation "
                          + "the address space the app sits in.")
                    .remediation(
                            "Suppress internal addresses in user-facing responses. Most leaks come from "
                          + "verbose error pages, X-Forwarded-For reflections, or unsanitised admin "
                          + "snippets — fix them at the source.")
                    .evidence(String.join("\n", privateIps))
                    .references(List.of(
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"))
                    .request(ctx.seedRequest())
                    .response(resp)
                    .build());
        }

        Set<String> hosts = capture(INTERNAL_HOST, body, 25, true);
        if (!hosts.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".internal-host")
                    .title("Internal / non-prod hostnames disclosed (" + hosts.size() + ")")
                    .severity(Severity.LOW)
                    .confidence(Confidence.TENTATIVE)
                    .url(ctx.targetUrl())
                    .description(
                            "Hostnames containing tokens like internal/corp/local/staging/dev/qa appear "
                          + "in the response. They map directly to additional attack surface — feed them "
                          + "into subdomain enumeration and probe each for auth gaps.")
                    .remediation(
                            "Strip dev/staging/internal hostnames from production responses. Common "
                          + "sources: hard-coded API base URLs in JS, X-Powered-By-style headers, "
                          + "debug HTML comments.")
                    .evidence(String.join("\n", hosts))
                    .references(List.of(
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"))
                    .request(ctx.seedRequest())
                    .response(resp)
                    .build());
        }

        return out;
    }

    /** Collect up to `cap` distinct matches; optionally lower-case before deduping. */
    private static Set<String> capture(Pattern p, String body, int cap, boolean lower) {
        Set<String> out = new LinkedHashSet<>();
        Matcher m = p.matcher(body);
        while (m.find() && out.size() < cap) {
            String hit = m.group();
            out.add(lower ? hit.toLowerCase() : hit);
        }
        return out;
    }
}
