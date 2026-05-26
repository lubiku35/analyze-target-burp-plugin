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
 * Consolidated security-headers check. Emits ONE finding listing every missing or weak header
 * among: X-Content-Type-Options, X-Frame-Options / CSP frame-ancestors, Referrer-Policy,
 * Permissions-Policy, COOP/COEP/CORP. Aggregated to keep the findings table readable — a single
 * page often misses 5+ minor headers and previously emitted 5+ separate low-noise findings.
 *
 * CSP and HSTS get their own dedicated checks ({@code CspCheck}, {@code HstsCheck}) because they
 * deserve standalone visibility and detailed remediation.
 *
 * Aligned with the OWASP Secure Headers Cheat Sheet.
 *
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html">
 *      OWASP HTTP Security Response Headers Cheat Sheet</a>
 */
public class SecurityHeadersCheck implements Check {
    private static final String ID = "headers";

    @Override public String id() { return ID; }
    @Override public String category() { return "Security Headers"; }
    @Override public boolean isActive() { return false; }

    private record Issue(String headerLabel, Severity severity, String summary, String fix) {}

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        HttpRequest req = ctx.seedRequest();
        String url = ctx.targetUrl();
        List<Issue> issues = new ArrayList<>();

        // ---- X-Content-Type-Options ----
        String xcto = HttpUtil.headerValue(resp, "X-Content-Type-Options");
        if (xcto == null || !xcto.trim().equalsIgnoreCase("nosniff")) {
            issues.add(new Issue("X-Content-Type-Options",
                    Severity.LOW,
                    "Missing or non-`nosniff`. Browsers may MIME-sniff and execute uploads / served-as-JSON "
                            + "content as scripts in this origin's context.",
                    "Set `X-Content-Type-Options: nosniff` on every response."));
        }

        // ---- X-Frame-Options / CSP frame-ancestors ----
        String xfo = HttpUtil.headerValue(resp, "X-Frame-Options");
        String csp = HttpUtil.headerValue(resp, "Content-Security-Policy");
        boolean cspProtects = csp != null && csp.toLowerCase().contains("frame-ancestors");
        if (xfo == null && !cspProtects) {
            issues.add(new Issue("X-Frame-Options / frame-ancestors",
                    Severity.MEDIUM,
                    "Neither X-Frame-Options nor CSP `frame-ancestors` is set. Any origin can iframe the page, "
                            + "enabling clickjacking against state-changing endpoints.",
                    "Add `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`). Optionally also "
                            + "`X-Frame-Options: DENY` for legacy browsers."));
        } else if (xfo != null) {
            String lower = xfo.trim().toLowerCase();
            if (!(lower.equals("deny") || lower.equals("sameorigin") || lower.startsWith("allow-from"))) {
                issues.add(new Issue("X-Frame-Options",
                        Severity.LOW,
                        "Value `" + xfo + "` is not recognised by browsers (only DENY, SAMEORIGIN, or "
                                + "ALLOW-FROM <single-URL>) and will be ignored.",
                        "Use `DENY` or `SAMEORIGIN`. For multiple allowed framers, switch to CSP "
                                + "`frame-ancestors <list>`."));
            }
        }

        // ---- Referrer-Policy ----
        String rp = HttpUtil.headerValue(resp, "Referrer-Policy");
        if (rp == null) {
            issues.add(new Issue("Referrer-Policy",
                    Severity.LOW,
                    "Not set. Browsers fall back to defaults that may leak full URLs (with tokens in query "
                            + "strings) to cross-origin scripts and analytics.",
                    "Set `Referrer-Policy: strict-origin-when-cross-origin` (modern default — explicit is better) "
                            + "or `no-referrer` for maximum privacy."));
        } else {
            String v = rp.trim().toLowerCase();
            if (v.equals("unsafe-url") || v.equals("no-referrer-when-downgrade")) {
                issues.add(new Issue("Referrer-Policy",
                        Severity.LOW,
                        "Value `" + rp + "` leaks full URLs cross-origin — a common vector for OAuth `code` "
                                + "and password-reset token leakage into third-party loggers.",
                        "Use `strict-origin-when-cross-origin` or `no-referrer`."));
            }
        }

        // ---- Permissions-Policy ----
        String pp = HttpUtil.headerValue(resp, "Permissions-Policy");
        if (pp == null) {
            issues.add(new Issue("Permissions-Policy",
                    Severity.INFO,
                    "Not set. Powerful browser features (camera, microphone, geolocation, payment, USB, etc.) "
                            + "remain reachable by any JS that ends up running — including future XSS payloads.",
                    "Set `Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
                            + "interest-cohort=()` and extend with every feature the app does not need."));
        }

        // ---- COOP / COEP / CORP ----
        String coop = HttpUtil.headerValue(resp, "Cross-Origin-Opener-Policy");
        String coep = HttpUtil.headerValue(resp, "Cross-Origin-Embedder-Policy");
        String corp = HttpUtil.headerValue(resp, "Cross-Origin-Resource-Policy");
        List<String> isolationMissing = new ArrayList<>();
        if (coop == null) isolationMissing.add("Cross-Origin-Opener-Policy");
        if (coep == null) isolationMissing.add("Cross-Origin-Embedder-Policy");
        if (corp == null) isolationMissing.add("Cross-Origin-Resource-Policy");
        if (!isolationMissing.isEmpty()) {
            issues.add(new Issue("Cross-origin isolation (COOP / COEP / CORP)",
                    Severity.INFO,
                    "Missing: " + String.join(", ", isolationMissing) + ". Cross-origin isolation mitigates "
                            + "Spectre-class side-channel leaks and tames `window.opener` access.",
                    "Add `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, "
                            + "and `Cross-Origin-Resource-Policy: same-origin` (loosen per-resource as needed)."));
        }

        if (issues.isEmpty()) return out;

        // Compose ONE finding with the highest severity among the issues.
        Severity worst = Severity.INFO;
        StringBuilder desc = new StringBuilder();
        StringBuilder remediation = new StringBuilder();
        StringBuilder evidence = new StringBuilder();
        desc.append("The response is missing or has weak values for ")
            .append(issues.size())
            .append(" security-relevant header(s):\n\n");
        remediation.append("Per the OWASP HTTP Headers Cheat Sheet:\n\n");

        for (Issue i : issues) {
            if (i.severity().ordinal() < worst.ordinal()) worst = i.severity();
            desc.append("  • [").append(i.severity().label()).append("] ")
                .append(i.headerLabel()).append(" — ").append(i.summary()).append('\n');
            remediation.append("  • ").append(i.headerLabel()).append(": ").append(i.fix()).append('\n');
            String observed = HttpUtil.headerValue(resp, headerNameFor(i.headerLabel()));
            evidence.append(i.headerLabel()).append(": ")
                    .append(observed == null ? "(header absent)" : observed)
                    .append('\n');
        }
        desc.append("\nGrouped into a single finding because individual missing headers are typically minor on "
                + "their own — the cumulative posture is what matters. Address the highest-severity entries first.");

        out.add(Finding.builder()
                .checkId(ID + ".consolidated")
                .title("Security headers missing or weak (" + issues.size() + " issue" + (issues.size() == 1 ? "" : "s") + ")")
                .severity(worst)
                .confidence(Confidence.CERTAIN)
                .url(url)
                .description(desc.toString().trim())
                .remediation(remediation.toString().trim())
                .evidence(evidence.toString().trim())
                .references(List.of(
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"))
                .request(req)
                .response(resp)
                .build());
        return out;
    }

    /** Used to fetch the observed value for evidence display. */
    private static String headerNameFor(String label) {
        // Map the human label back to the canonical header name. For multi-header labels return the first.
        if (label.startsWith("X-Frame-Options")) return "X-Frame-Options";
        if (label.startsWith("Cross-origin"))   return "Cross-Origin-Opener-Policy";
        return label; // matches exactly for XCTO / Referrer-Policy / Permissions-Policy
    }
}
