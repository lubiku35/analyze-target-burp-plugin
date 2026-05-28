package com.analyzer.checks.passive;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Surfaces URL parameters and form fields whose <em>name</em> suggests they carry a redirect
 * target — {@code return}, {@code redirect}, {@code next}, {@code url}, {@code dest}, etc.
 *
 * The check is intentionally <em>passive</em>: it doesn't try to confirm the redirect is
 * exploitable, just flags the parameter so the tester can probe it manually. Confirming open
 * redirects requires sending crafted values and inspecting the resulting Location header /
 * client-side redirect logic, which sits comfortably outside the recon-only scope of this plugin.
 *
 * Aligned with OWASP WSTG-CLNT-04 (Testing for Client-side URL Redirect) and the OWASP
 * Unvalidated Redirects and Forwards Cheat Sheet.
 */
public class OpenRedirectParamCheck implements Check {
    private static final String ID = "open-redirect";

    /** Lower-cased parameter-name candidates ordered by how strongly they suggest redirect intent. */
    private static final Set<String> NAMES = new LinkedHashSet<>(Arrays.asList(
            "redirect", "redirect_uri", "redirect_url", "redirecturl", "redir",
            "return", "returnurl", "return_url", "returnto", "return_to",
            "next", "url", "u", "target", "dest", "destination", "continue",
            "go", "goto", "out", "callback", "callback_url", "checkout_url", "successurl"));

    private static final Pattern HIDDEN_INPUT = Pattern.compile(
            "<input[^>]*name\\s*=\\s*[\"']([A-Za-z0-9_\\-]+)[\"'][^>]*>", Pattern.CASE_INSENSITIVE);

    @Override public String id() { return ID; }
    @Override public String category() { return "Open-redirect candidates"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest req = ctx.seedRequest();
        if (req == null) return out;

        Set<String> hits = new LinkedHashSet<>();

        // URL + body parameters in the seed request itself.
        try {
            for (HttpParameter p : req.parameters()) {
                String name = p.name() == null ? "" : p.name().toLowerCase();
                if (NAMES.contains(name)) hits.add(name + " (" + p.type() + ")");
            }
        } catch (Exception ignored) { /* defensive — older API quirks */ }

        // Form/hidden inputs visible in the seed HTML.
        HttpResponse resp = ctx.seedResponse();
        String body = resp == null ? null : resp.bodyToString();
        if (body != null && !body.isEmpty()) {
            Matcher m = HIDDEN_INPUT.matcher(body);
            while (m.find()) {
                String name = m.group(1).toLowerCase();
                if (NAMES.contains(name)) hits.add(name + " (form input)");
            }
        }

        if (hits.isEmpty()) return out;
        out.add(Finding.builder()
                .checkId(ID + ".candidate")
                .title("Possible open-redirect parameter(s): " + String.join(", ", hits))
                .severity(Severity.LOW)
                .confidence(Confidence.TENTATIVE)
                .url(ctx.targetUrl())
                .description(
                        "Parameter name(s) " + String.join(", ", hits) + " match common open-redirect "
                      + "conventions. The check is passive — it only spotted the name, not a real "
                      + "vulnerability. Confirming exploitability requires sending crafted values "
                      + "(e.g. `//evil.example/`, `https:evil.example`, `\\\\evil.example`) and "
                      + "inspecting the response Location header / client-side redirect handler.\n\n"
                      + "Open-redirects are typically a low-severity bug in isolation but become "
                      + "high-impact when chained: phishing campaigns, OAuth flow hijacks "
                      + "(redirect_uri parameter), and bypasses of allow-list filters.\n\n"
                      + "Aligned with OWASP WSTG-CLNT-04 (Testing for Client-side URL Redirect) "
                      + "and OWASP Unvalidated Redirects and Forwards Cheat Sheet.")
                .remediation(
                        "Validate redirect targets against a strict allow-list of fully-qualified "
                      + "URLs or relative paths. Reject `//`-prefixed values, backslash variants, and "
                      + "anything containing user-controlled scheme. For OAuth, keep `redirect_uri` "
                      + "registration tight (no wildcards, no path-relative matching).")
                .evidence("Parameter(s) detected: " + String.join("\n", hits))
                .references(List.of(
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"))
                .request(req)
                .response(resp)
                .build());
        return out;
    }
}
