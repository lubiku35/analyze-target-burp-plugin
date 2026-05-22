package com.analyzer.checks.passive;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WSTG-SESS / WSTG-CONF - Form security passive review.
 *
 * Looks at every <form> in the seed response and flags:
 *  - password fields without autocomplete=off (low - modern guidance varies)
 *  - login forms submitted over http:// while the page is https:// (mixed-content downgrade)
 *  - forms with method=POST that have no obvious anti-CSRF token field
 *  - forms posting to a different origin
 */
public class FormSecurityCheck implements Check {
    private static final String ID = "form-security";

    private static final Pattern FORM = Pattern.compile("(?is)<form\\b([^>]*)>(.*?)</form>");
    private static final Pattern ATTR = Pattern.compile("(?i)([a-z\\-]+)\\s*=\\s*([\"']?)([^\"'>\\s]+)\\2");
    private static final Pattern PASSWORD_INPUT = Pattern.compile(
            "(?i)<input[^>]*\\btype\\s*=\\s*[\"']?password[\"']?[^>]*>");
    private static final Pattern HIDDEN_INPUT = Pattern.compile(
            "(?i)<input[^>]*\\btype\\s*=\\s*[\"']?hidden[\"']?[^>]*>");
    private static final Pattern NAME_ATTR = Pattern.compile("(?i)\\bname\\s*=\\s*[\"']?([a-z0-9_\\-\\[\\]\\.]+)");
    private static final Pattern AUTOCOMPLETE = Pattern.compile("(?i)\\bautocomplete\\s*=\\s*[\"']?(off|new-password)[\"']?");
    private static final Pattern CSRF_NAME =
            Pattern.compile("(?i)(csrf|xsrf|authenticity[_\\-]?token|__requestverificationtoken|nonce)");

    @Override public String id() { return ID; }
    @Override public String category() { return "Forms"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;
        String body = resp.bodyToString();
        if (body == null || body.isEmpty()) return out;

        URI base;
        try {
            base = new URI(ctx.targetUrl());
        } catch (Exception e) {
            return out;
        }
        boolean pageIsHttps = "https".equalsIgnoreCase(base.getScheme());
        Matcher fm = FORM.matcher(body);
        int formIndex = 0;
        while (fm.find()) {
            formIndex++;
            String formAttrs = fm.group(1);
            String formBody = fm.group(2);

            String method = attr(formAttrs, "method");
            String action = attr(formAttrs, "action");
            if (method == null) method = "GET";
            method = method.toUpperCase();

            boolean hasPassword = PASSWORD_INPUT.matcher(formBody).find();
            String resolvedAction = resolveAction(base, action);

            // 1. Password form posting over http:// from an https:// page
            if (hasPassword && pageIsHttps && resolvedAction != null && resolvedAction.startsWith("http://")) {
                out.add(Finding.builder()
                        .checkId(ID + ".password-over-http")
                        .title("Login form on HTTPS page posts password over HTTP")
                        .severity(Severity.HIGH)
                        .confidence(Confidence.CERTAIN)
                        .url(ctx.targetUrl())
                        .description("Form #" + formIndex + " contains a password input but `action` is http://. "
                                + "The credential will travel in plaintext, defeating the HTTPS that loaded the page.")
                        .remediation("Set `action` to a same-origin HTTPS URL. Browsers may auto-upgrade with mixed-content "
                                + "blocking, but never rely on it.")
                        .evidence("<form " + HttpUtil.truncate(formAttrs.trim(), 200) + ">")
                        .request(ctx.seedRequest())
                        .response(resp)
                        .build());
            }

            // 2. POST form without an obvious CSRF token
            if ("POST".equals(method)) {
                boolean hasToken = hiddenTokenLooksLikeCsrf(formBody);
                if (!hasToken) {
                    out.add(Finding.builder()
                            .checkId(ID + ".csrf-token-missing")
                            .title("POST form has no obvious anti-CSRF token (form #" + formIndex + ")")
                            .severity(Severity.LOW)
                            .confidence(Confidence.TENTATIVE)
                            .url(ctx.targetUrl())
                            .description("Form #" + formIndex + " submits with method=POST but contains no hidden input matching "
                                    + "common CSRF token names (csrf*, xsrf*, authenticity_token, __RequestVerificationToken, nonce). "
                                    + "Verify the application protects state-changing actions via SameSite cookies, double-submit cookies, "
                                    + "or framework CSRF middleware.")
                            .remediation("Add a per-session CSRF token to the form and validate server-side, or rely on a same-site "
                                    + "session cookie strategy plus Origin/Referer checks.")
                            .evidence("<form " + HttpUtil.truncate(formAttrs.trim(), 200) + ">")
                            .references(List.of(
                                    "https://owasp.org/www-community/attacks/csrf",
                                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery"))
                            .request(ctx.seedRequest())
                            .response(resp)
                            .build());
                }
            }

            // 3. Password field without autocomplete=off / new-password
            if (hasPassword) {
                Matcher pm = PASSWORD_INPUT.matcher(formBody);
                while (pm.find()) {
                    String tag = pm.group();
                    if (!AUTOCOMPLETE.matcher(tag).find()) {
                        out.add(Finding.builder()
                                .checkId(ID + ".password-autocomplete")
                                .title("Password field without autocomplete=off (form #" + formIndex + ")")
                                .severity(Severity.INFO)
                                .confidence(Confidence.FIRM)
                                .url(ctx.targetUrl())
                                .description("A password input has no autocomplete directive. Modern guidance is mixed - managers "
                                        + "ignore the hint anyway - but on shared/kiosk devices browser-cached passwords are a residual risk.")
                                .remediation("If the form is on a shared-device portal or sensitive admin login, set "
                                        + "`autocomplete=\"new-password\"` (signup) or `\"off\"` (other). Otherwise leave it.")
                                .evidence(HttpUtil.truncate(tag, 200))
                                .request(ctx.seedRequest())
                                .response(resp)
                                .build());
                        break; // one report per form
                    }
                }
            }
        }
        return out;
    }

    private static String attr(String formAttrs, String name) {
        Matcher m = ATTR.matcher(formAttrs);
        while (m.find()) {
            if (m.group(1).equalsIgnoreCase(name)) return m.group(3);
        }
        return null;
    }

    private static String resolveAction(URI base, String action) {
        if (action == null || action.isEmpty()) return base.toString();
        try {
            return base.resolve(action).toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean hiddenTokenLooksLikeCsrf(String formBody) {
        Matcher h = HIDDEN_INPUT.matcher(formBody);
        while (h.find()) {
            Matcher n = NAME_ATTR.matcher(h.group());
            if (n.find() && CSRF_NAME.matcher(n.group(1)).find()) return true;
        }
        return false;
    }
}
