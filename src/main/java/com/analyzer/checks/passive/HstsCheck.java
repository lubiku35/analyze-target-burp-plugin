package com.analyzer.checks.passive;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.util.ArrayList;
import java.util.List;

/**
 * Standalone HSTS check. Aligned with the OWASP HTTP Strict Transport Security Cheat Sheet.
 *
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html">
 *      OWASP HSTS Cheat Sheet</a>
 */
public class HstsCheck implements Check {
    private static final String ID = "hsts";
    private static final long MIN_RECOMMENDED_MAX_AGE = 31_536_000L; // 1 year — OWASP recommendation

    @Override public String id() { return ID; }
    @Override public String category() { return "HSTS"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        String url = ctx.targetUrl();
        boolean isHttps = url != null && url.toLowerCase().startsWith("https://");
        if (!isHttps) return out; // HSTS only applies to HTTPS responses

        HttpRequest req = ctx.seedRequest();
        String hsts = HttpUtil.headerValue(resp, "Strict-Transport-Security");

        if (hsts == null) {
            out.add(Finding.builder()
                    .checkId(ID + ".missing")
                    .title("Missing Strict-Transport-Security header")
                    .severity(Severity.MEDIUM)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("The HTTPS response does not set Strict-Transport-Security. An active network attacker "
                            + "(rogue WiFi, compromised router, malicious CA, BGP hijack) can downgrade subsequent "
                            + "navigations to plaintext HTTP and intercept credentials, session cookies, and form "
                            + "submissions. The very first visit is always vulnerable because the browser has no HSTS "
                            + "state to enforce — only the HSTS preload list closes that gap, and that requires this "
                            + "header to include the `preload` directive plus submission to hstspreload.org. The risk is "
                            + "especially acute on login, OAuth, and password-reset endpoints where credentials travel "
                            + "in clear after a downgrade.")
                    .remediation("Per the OWASP HSTS Cheat Sheet, send this header on every HTTPS response:\n\n"
                            + "    Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n\n"
                            + "Configure it once at the CDN / load balancer layer. Before enabling `preload`, verify "
                            + "every subdomain supports HTTPS — preload removal can take 6–12 months and is effectively "
                            + "irreversible for end users. After deploying, submit the apex domain at "
                            + "https://hstspreload.org/.")
                    .references(List.of(
                            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                            "https://hstspreload.org/"))
                    .request(req)
                    .response(resp)
                    .build());
            return out;
        }

        long maxAge = parseHstsMaxAge(hsts);
        List<String> weaknesses = new ArrayList<>();
        if (maxAge < 0)                        weaknesses.add("`max-age` missing");
        else if (maxAge < MIN_RECOMMENDED_MAX_AGE)
                                                weaknesses.add("`max-age` below the OWASP-recommended 1 year (current: " + maxAge + "s)");
        if (!hsts.toLowerCase().contains("includesubdomains")) weaknesses.add("missing `includeSubDomains`");
        if (!hsts.toLowerCase().contains("preload"))           weaknesses.add("missing `preload`");

        if (weaknesses.isEmpty()) return out; // strong HSTS, nothing to report

        out.add(Finding.builder()
                .checkId(ID + ".weak")
                .title("Weak Strict-Transport-Security configuration")
                .severity(Severity.LOW)
                .confidence(Confidence.FIRM)
                .url(url)
                .description("HSTS is present but has the following gaps:\n  - "
                        + String.join("\n  - ", weaknesses) + "\n\n"
                        + "A short `max-age` means the browser stops enforcing HTTPS soon after the user navigates away "
                        + "from the site. Missing `includeSubDomains` means a malicious subdomain (e.g. via DNS hijack on "
                        + "`cdn.example.com`) can still serve plaintext and steal cookies that are not tightly scoped. "
                        + "Missing `preload` plus absence from the preload list means first-visit MITM is still possible.")
                .remediation("Use the OWASP-recommended baseline:\n\n"
                        + "    Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n\n"
                        + "If you cannot serve every subdomain over HTTPS yet, drop `includeSubDomains` until you can — "
                        + "the wider gap is worse than the smaller one.")
                .evidence("Strict-Transport-Security: " + hsts)
                .references(List.of(
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                        "https://hstspreload.org/"))
                .request(req)
                .response(resp)
                .build());
        return out;
    }

    private static long parseHstsMaxAge(String hsts) {
        for (String part : hsts.split(";")) {
            String p = part.trim();
            if (p.toLowerCase().startsWith("max-age")) {
                int eq = p.indexOf('=');
                if (eq < 0) return -1;
                try {
                    return Long.parseLong(p.substring(eq + 1).trim().replaceAll("\"", ""));
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }
}
