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
 * Standalone CSP check. Emits at most ONE finding: missing, or weak (with itemised issues).
 *
 * Descriptions and remediation are aligned with the OWASP Content Security Policy Cheat Sheet.
 *
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html">
 *      OWASP CSP Cheat Sheet</a>
 */
public class CspCheck implements Check {
    private static final String ID = "csp";

    @Override public String id() { return ID; }
    @Override public String category() { return "Content-Security-Policy"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        HttpRequest req = ctx.seedRequest();
        String url = ctx.targetUrl();
        String csp = HttpUtil.headerValue(resp, "Content-Security-Policy");
        String cspReportOnly = HttpUtil.headerValue(resp, "Content-Security-Policy-Report-Only");

        if (csp == null && cspReportOnly == null) {
            out.add(Finding.builder()
                    .checkId(ID + ".missing")
                    .title("Missing Content-Security-Policy header")
                    .severity(Severity.LOW)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("The response sets no Content-Security-Policy. CSP is the primary defence-in-depth control "
                            + "against XSS, clickjacking (via `frame-ancestors`), data exfiltration via injected resources, "
                            + "and `<base>`/form hijacking. Without it, any unfiltered input that reaches the DOM can execute "
                            + "attacker-controlled JavaScript in the authenticated user's session — exfiltrate tokens, perform "
                            + "actions, scrape data. Browsers do not impose any default restriction in CSP's absence, so the "
                            + "application is fully exposed to whatever script it accidentally renders. CSP is also the only "
                            + "header that lets you tightly scope where forms may POST to and which origins may frame the page.")
                    .remediation("Per the OWASP CSP Cheat Sheet, start with a strict baseline and loosen as needed:\n\n"
                            + "    Content-Security-Policy: default-src 'self'; object-src 'none'; "
                            + "frame-ancestors 'none'; base-uri 'self'; form-action 'self'\n\n"
                            + "Deploy first with `Content-Security-Policy-Report-Only` plus a `report-uri` endpoint to "
                            + "collect violations without breaking the site, then switch to enforcement. For inline scripts "
                            + "you cannot remove, use per-request nonces (`'nonce-<random>'`) or static hashes "
                            + "(`'sha256-<hash>'`). Never use `'unsafe-inline'` in production.")
                    .references(List.of(
                            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                            "https://csp-evaluator.withgoogle.com/",
                            "https://owasp.org/www-project-secure-headers/"))
                    .request(req)
                    .response(resp)
                    .build());
            return out;
        }

        // CSP present — evaluate quality. Prefer enforced over report-only for analysis.
        String effective = csp != null ? csp : cspReportOnly;
        boolean reportOnly = csp == null;
        String lower = effective.toLowerCase();

        List<String> issues = new ArrayList<>();
        if (lower.contains("'unsafe-inline'")) issues.add("'unsafe-inline' (defeats most XSS protection)");
        if (lower.contains("'unsafe-eval'"))   issues.add("'unsafe-eval' (allows eval-based code injection)");
        if (lower.matches(".*\\b(script-src|default-src)[^;]*\\*[^;]*"))
            issues.add("wildcard '*' source in script-src / default-src");
        if (lower.contains("data:") && lower.matches(".*\\b(script-src|default-src)[^;]*\\bdata:.*"))
            issues.add("`data:` URI allowed in script-src / default-src (XSS payload vector)");
        if (!lower.contains("frame-ancestors")) issues.add("missing `frame-ancestors` (clickjacking control)");
        if (!lower.contains("object-src"))      issues.add("missing `object-src` (plugin / Flash control; should be 'none')");
        if (!lower.contains("base-uri"))        issues.add("missing `base-uri` (allows `<base>` tag hijacking)");
        if (!lower.contains("form-action"))     issues.add("missing `form-action` (forms may POST anywhere)");

        if (reportOnly) issues.add(0, "policy is report-only — violations are logged but not blocked");

        if (issues.isEmpty()) return out; // strong CSP, nothing to report

        out.add(Finding.builder()
                .checkId(ID + ".weak")
                .title(reportOnly
                        ? "Content-Security-Policy is report-only and has weaknesses"
                        : "Weak Content-Security-Policy")
                .severity(reportOnly ? Severity.INFO : Severity.LOW)
                .confidence(Confidence.FIRM)
                .url(url)
                .description("CSP " + (reportOnly ? "(report-only) " : "") + "is present but has the following issues:\n  - "
                        + String.join("\n  - ", issues) + "\n\n"
                        + "Each weakness corresponds to a known XSS-bypass class. `'unsafe-inline'` makes the policy nearly "
                        + "useless against injected `<script>` tags. Wildcard sources allow any CDN-hosted attacker file "
                        + "(common bypass). `data:` in script-src lets attackers inline payloads as base64. Missing "
                        + "`frame-ancestors` means the page is iframable by any origin, enabling clickjacking. Run the "
                        + "policy through https://csp-evaluator.withgoogle.com/ for a per-directive walkthrough.")
                .remediation("Per OWASP guidance: remove `'unsafe-inline'` / `'unsafe-eval'`; replace inline scripts with "
                        + "nonces or hashes. Replace wildcards with explicit hostnames. Always set `frame-ancestors`, "
                        + "`object-src`, `base-uri`, and `form-action` (typically `'none'` or `'self'`). Once the "
                        + "report-only policy emits zero violations in production, switch the header name to enforce.")
                .evidence((reportOnly ? "Content-Security-Policy-Report-Only: " : "Content-Security-Policy: ") + effective)
                .references(List.of(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                        "https://csp-evaluator.withgoogle.com/",
                        "https://content-security-policy.com/"))
                .request(req)
                .response(resp)
                .build());
        return out;
    }
}
