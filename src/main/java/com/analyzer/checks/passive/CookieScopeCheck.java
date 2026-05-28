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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cookie scoping problems, complementary to {@code CookieFlagsCheck} (which covers
 * Secure/HttpOnly/SameSite/prefixes). This check looks at where a cookie is valid and where the
 * session identifier travels:
 *
 * <ul>
 *   <li>Overly broad {@code Domain} — a cookie scoped to a parent/registrable domain is shared with
 *       every subdomain, so a single XSS or rogue subdomain can steal it.</li>
 *   <li>Session identifier in the URL — {@code ;jsessionid=…} or session-like query parameters leak
 *       the token into logs, browser history, and the Referer header (session fixation / hijack).</li>
 * </ul>
 *
 * Strictly passive.
 */
public class CookieScopeCheck implements Check {
    private static final String ID = "cookie-scope";

    private static final Pattern DOMAIN_ATTR = Pattern.compile("(?i);\\s*domain\\s*=\\s*([^;]+)");
    private static final Pattern SESSION_IN_URL = Pattern.compile(
            "(?i)(;jsessionid=|[?&](?:jsessionid|phpsessid|sid|sessionid|session_id|aspsessionid)=)[^&;\\s]+");

    @Override public String id() { return ID; }
    @Override public String category() { return "Cookie scope"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest req = ctx.seedRequest();
        HttpResponse resp = ctx.seedResponse();

        // 1. Session identifier carried in the URL.
        String url = ctx.targetUrl();
        if (url != null) {
            Matcher sm = SESSION_IN_URL.matcher(url);
            if (sm.find()) {
                out.add(Finding.builder()
                        .checkId(ID + ".session-in-url")
                        .title("Session identifier exposed in the URL")
                        .severity(Severity.MEDIUM)
                        .confidence(Confidence.FIRM)
                        .url(url)
                        .description("The request URL carries a session identifier (`"
                                + HttpUtil.truncate(sm.group(), 60) + "`). Session tokens in URLs leak through "
                                + "browser history, proxy and server access logs, and the `Referer` header sent to "
                                + "third-party sites — and they make session fixation trivial (an attacker can hand a "
                                + "victim a pre-set session URL).")
                        .remediation("Carry session identifiers only in cookies with Secure + HttpOnly set. Disable "
                                + "URL-based session tracking (e.g. servlet `tracking-mode=COOKIE`, "
                                + "`session.use_only_cookies=1` in PHP). Regenerate the session ID on login.")
                        .evidence("URL: " + HttpUtil.truncate(url, 200))
                        .references(List.of(
                                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"))
                        .request(req)
                        .response(resp)
                        .build());
            }
        }

        // 2. Broadly-scoped cookies.
        if (resp != null) {
            for (String setCookie : HttpUtil.headerValues(resp, "Set-Cookie")) {
                Matcher dm = DOMAIN_ATTR.matcher(setCookie);
                if (!dm.find()) continue;
                String domain = dm.group(1).trim().toLowerCase();
                String bare = domain.startsWith(".") ? domain.substring(1) : domain;
                // A registrable-domain-level scope (<= 2 labels, e.g. example.com) shared across all
                // subdomains is the broad case worth flagging.
                if (countLabels(bare) <= 2) {
                    String name = cookieName(setCookie);
                    out.add(Finding.builder()
                            .checkId(ID + ".broad-domain")
                            .title("Cookie '" + name + "' scoped to a broad domain (" + domain + ")")
                            .severity(Severity.LOW)
                            .confidence(Confidence.FIRM)
                            .url(ctx.targetUrl())
                            .description("Cookie '" + name + "' sets `Domain=" + domain + "`, so it is sent to "
                                    + "every subdomain of " + bare + ". Any subdomain — including one compromised by "
                                    + "a takeover or hosting attacker-controlled content — can read it. For a session "
                                    + "or auth cookie this widens the blast radius of a single XSS considerably.")
                            .remediation("Drop the Domain attribute so the cookie is host-only (valid only for the "
                                    + "exact host that set it), or scope it to the narrowest subdomain that needs it. "
                                    + "For host-locked session cookies prefer the `__Host-` prefix, which forbids Domain entirely.")
                            .evidence("Set-Cookie: " + HttpUtil.truncate(setCookie, 200))
                            .references(List.of(
                                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies"))
                            .request(req)
                            .response(resp)
                            .build());
                }
            }
        }
        return out;
    }

    private static int countLabels(String host) {
        if (host.isEmpty()) return 0;
        int n = 1;
        for (int i = 0; i < host.length(); i++) if (host.charAt(i) == '.') n++;
        return n;
    }

    private static String cookieName(String setCookie) {
        int eq = setCookie.indexOf('=');
        return eq < 0 ? setCookie.trim() : setCookie.substring(0, eq).trim();
    }
}
