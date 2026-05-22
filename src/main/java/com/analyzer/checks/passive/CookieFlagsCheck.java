package com.analyzer.checks.passive;

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
 * Validates Set-Cookie flags: Secure, HttpOnly, SameSite, and the __Secure- / __Host- prefix invariants.
 */
public class CookieFlagsCheck implements Check {
    private static final String ID = "cookies";

    @Override public String id() { return ID; }
    @Override public String category() { return "Cookie flags"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        List<String> setCookies = HttpUtil.headerValues(resp, "Set-Cookie");
        if (setCookies.isEmpty()) return out;

        boolean isHttps = ctx.targetUrl() != null && ctx.targetUrl().toLowerCase().startsWith("https://");

        for (String cookie : setCookies) {
            String name = cookieName(cookie);
            String lower = cookie.toLowerCase();
            List<String> issues = new ArrayList<>();
            Severity sev = Severity.LOW;

            boolean hasSecure   = lower.contains("; secure") || lower.endsWith(";secure") || lower.matches(".*;\\s*secure(;.*)?");
            boolean hasHttpOnly = lower.contains("httponly");
            boolean hasSameSite = lower.contains("samesite=");

            if (isHttps && !hasSecure) {
                issues.add("missing Secure flag");
                sev = escalate(sev, Severity.MEDIUM);
            }
            if (!hasHttpOnly && looksLikeSessionCookie(name)) {
                issues.add("missing HttpOnly flag on a likely session cookie");
                sev = escalate(sev, Severity.MEDIUM);
            } else if (!hasHttpOnly) {
                issues.add("missing HttpOnly flag");
            }
            if (!hasSameSite) {
                issues.add("missing SameSite attribute");
            } else if (lower.contains("samesite=none") && !hasSecure) {
                issues.add("SameSite=None without Secure (cookie will be rejected by modern browsers)");
                sev = escalate(sev, Severity.MEDIUM);
            }

            // __Host- prefix: must have Secure, Path=/, no Domain attribute
            if (name.startsWith("__Host-")) {
                if (!hasSecure) issues.add("__Host- cookie missing Secure flag (prefix invariant)");
                if (lower.contains("domain=")) issues.add("__Host- cookie sets Domain attribute (prefix invariant violated)");
                if (!lower.matches(".*;\\s*path=/(;.*|$)")) issues.add("__Host- cookie must set Path=/ exactly");
                if (!issues.isEmpty()) sev = escalate(sev, Severity.MEDIUM);
            }
            // __Secure- prefix: must have Secure
            if (name.startsWith("__Secure-") && !hasSecure) {
                issues.add("__Secure- cookie missing Secure flag (prefix invariant)");
                sev = escalate(sev, Severity.MEDIUM);
            }

            if (!issues.isEmpty()) {
                out.add(Finding.builder()
                        .checkId(ID + ".flags")
                        .title("Cookie '" + name + "' has missing or weak attributes")
                        .severity(sev)
                        .confidence(Confidence.CERTAIN)
                        .url(ctx.targetUrl())
                        .description("Cookie '" + name + "' issues: " + String.join("; ", issues) + ". "
                                + "Without `Secure`, the cookie travels over plaintext on any HTTP downgrade. Without `HttpOnly`, "
                                + "JavaScript (including XSS payloads) can read the cookie via `document.cookie` and exfiltrate it. "
                                + "Without `SameSite`, the cookie is sent on cross-origin requests, enabling CSRF (the modern "
                                + "browser default is `Lax` but legacy browsers and older Chrome versions still default to none). "
                                + "Violating `__Host-` / `__Secure-` prefix invariants makes the prefix meaningless — browsers "
                                + "will accept the cookie but the safety guarantees you expected won't apply.")
                        .remediation("Set Secure, HttpOnly (for cookies not read by JS), and SameSite=Lax or Strict. "
                                + "For high-value session cookies prefer the `__Host-` prefix with Path=/, no Domain attribute, "
                                + "and Secure — this binds the cookie to exactly the origin that set it, preventing subdomain "
                                + "injection. If you need a cookie shared across subdomains, use `__Secure-` instead (drops "
                                + "the Path=/ and no-Domain requirements). For SameSite=None (cross-site usage like OAuth "
                                + "iframes), Secure is mandatory or modern browsers reject the cookie outright.")
                        .evidence("Set-Cookie: " + cookie)
                        .references(List.of(
                                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
                                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes",
                                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes"))
                        .request(ctx.seedRequest())
                        .response(resp)
                        .build());
            }
        }
        return out;
    }

    private static String cookieName(String setCookie) {
        int eq = setCookie.indexOf('=');
        if (eq < 0) return setCookie.trim();
        return setCookie.substring(0, eq).trim();
    }

    private static boolean looksLikeSessionCookie(String name) {
        String n = name.toLowerCase();
        return n.contains("sess") || n.contains("auth") || n.contains("token")
                || n.contains("sid") || n.equals("jsessionid") || n.contains("phpsessid");
    }

    /** Returns whichever of the two severities is higher (lower ordinal = higher severity). */
    private static Severity escalate(Severity a, Severity b) {
        return a.ordinal() <= b.ordinal() ? a : b;
    }
}
