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
 * Inspects the seed response for missing or weak security-relevant headers.
 *
 * Covered: CSP (presence + unsafe-inline / wildcard / missing frame-ancestors),
 * HSTS (presence + max-age + includeSubDomains + preload), X-Content-Type-Options,
 * X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP.
 */
public class SecurityHeadersCheck implements Check {
    private static final String CHECK_ID_PREFIX = "headers";

    @Override public String id() { return CHECK_ID_PREFIX; }
    @Override public String category() { return "Security Headers"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        HttpRequest req = ctx.seedRequest();
        String url = ctx.targetUrl();

        checkCsp(req, resp, url, out);
        checkHsts(req, resp, url, out);
        checkXcto(req, resp, url, out);
        checkXfo(req, resp, url, out);
        checkReferrerPolicy(req, resp, url, out);
        checkPermissionsPolicy(req, resp, url, out);
        checkCrossOriginIsolation(req, resp, url, out);

        return out;
    }

    // ---------- CSP ----------
    private void checkCsp(HttpRequest req, HttpResponse resp, String url, List<Finding> out) {
        String csp = HttpUtil.headerValue(resp, "Content-Security-Policy");
        if (csp == null) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".csp.missing")
                    .title("Missing Content-Security-Policy header")
                    .severity(Severity.MEDIUM)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("The response does not set a Content-Security-Policy header. CSP is the primary defence-in-depth "
                            + "control against XSS, clickjacking, data-exfiltration via injected resources, and protocol/scheme "
                            + "downgrades. Without it, a single unfiltered input that reaches the DOM can execute attacker-controlled "
                            + "JavaScript in the user's authenticated session - read tokens, perform actions, exfiltrate data. "
                            + "Modern browsers do not impose any default restriction in CSP's absence; the application is fully "
                            + "exposed to whatever script it accidentally renders. CSP is also the only header that lets you "
                            + "block plugin loading (Flash/Java applets) and restrict the URLs that forms may POST to.")
                    .remediation("Add a Content-Security-Policy header. Start with a restrictive default such as "
                            + "`default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
                            + "form-action 'self'` and loosen per-directive only as needed. Use the Report-Only variant "
                            + "first to gather violations without breaking the site, then enforce. For inline scripts you "
                            + "cannot remove, use nonces (`'nonce-<random>'`) or hashes - never `'unsafe-inline'`.")
                    .references(List.of(
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                            "https://owasp.org/www-project-secure-headers/",
                            "https://csp-evaluator.withgoogle.com/"))
                    .request(req)
                    .response(resp)
                    .build());
            return;
        }

        String cspLower = csp.toLowerCase();
        List<String> issues = new ArrayList<>();
        if (cspLower.contains("'unsafe-inline'")) issues.add("uses 'unsafe-inline' (defeats most XSS protection)");
        if (cspLower.contains("'unsafe-eval'"))   issues.add("uses 'unsafe-eval' (allows eval-based code injection)");
        if (cspLower.matches(".*\\b(script-src|default-src)[^;]*\\*[^;]*")) {
            issues.add("uses a wildcard '*' source in script-src/default-src");
        }
        if (cspLower.contains("data:")) issues.add("allows data: URIs in a directive (often script-src/img-src)");
        if (!cspLower.contains("frame-ancestors")) {
            issues.add("missing 'frame-ancestors' (clickjacking control)");
        }
        if (!cspLower.contains("object-src")) {
            issues.add("missing 'object-src' (plugin/Flash control; should typically be 'none')");
        }
        if (!issues.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".csp.weak")
                    .title("Weak Content-Security-Policy")
                    .severity(Severity.MEDIUM)
                    .confidence(Confidence.FIRM)
                    .url(url)
                    .description("CSP header is present but has weaknesses: " + String.join("; ", issues) + ". "
                            + "Each weakness corresponds to a known XSS bypass class. `'unsafe-inline'` makes the policy "
                            + "near-useless against injected `<script>` tags. Wildcard sources like `*` or `https:` allow "
                            + "any CDN hosting an attacker-controlled file (a common bypass is hosting payload code on a "
                            + "permitted CDN). `data:` URIs in script-src let attackers inline payloads as base64. "
                            + "Missing `frame-ancestors` means the page can be iframed by any origin (clickjacking primitive). "
                            + "Run the CSP through https://csp-evaluator.withgoogle.com/ for a per-directive breakdown.")
                    .remediation("Remove 'unsafe-inline' / 'unsafe-eval'; replace inline scripts with nonces or hashes. "
                            + "Replace wildcards with explicit hostnames. Always set frame-ancestors and object-src "
                            + "(both `'none'` unless you have a specific reason). Add `base-uri 'self'` to prevent "
                            + "`<base>`-tag-based attacks, and `form-action 'self'` to bound where forms can POST.")
                    .evidence("Content-Security-Policy: " + csp)
                    .references(List.of(
                            "https://csp-evaluator.withgoogle.com/",
                            "https://content-security-policy.com/",
                            "https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/"))
                    .request(req)
                    .response(resp)
                    .build());
        }
    }

    // ---------- HSTS ----------
    private void checkHsts(HttpRequest req, HttpResponse resp, String url, List<Finding> out) {
        boolean isHttps = url != null && url.toLowerCase().startsWith("https://");
        String hsts = HttpUtil.headerValue(resp, "Strict-Transport-Security");
        if (!isHttps) return; // HSTS only applies over HTTPS
        if (hsts == null) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".hsts.missing")
                    .title("Missing Strict-Transport-Security header")
                    .severity(Severity.MEDIUM)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("HTTPS response does not set Strict-Transport-Security, so an active network attacker (rogue WiFi, "
                            + "compromised router, malicious CA) can downgrade subsequent navigations to plaintext HTTP and "
                            + "intercept credentials, session cookies, and form submissions. The first visit is always "
                            + "vulnerable (no HSTS state to enforce) - only the HSTS preload list closes that gap, which "
                            + "requires this header with the `preload` directive. This is especially important on login, "
                            + "password-reset, and OAuth endpoints where credentials travel in clear after a downgrade.")
                    .remediation("Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` to all "
                            + "HTTPS responses (or set it once at the CDN/load-balancer layer). Before enabling `preload`, "
                            + "verify every subdomain supports HTTPS - preloading is effectively irreversible "
                            + "(removal can take 6-12 months). After deploying, submit to https://hstspreload.org/.")
                    .references(List.of("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                            "https://hstspreload.org/"))
                    .request(req)
                    .response(resp)
                    .build());
            return;
        }
        long maxAge = parseHstsMaxAge(hsts);
        List<String> weaknesses = new ArrayList<>();
        if (maxAge < 0)              weaknesses.add("max-age missing");
        else if (maxAge < 15552000)  weaknesses.add("max-age < 6 months (current: " + maxAge + ")");
        if (!hsts.toLowerCase().contains("includesubdomains")) weaknesses.add("missing includeSubDomains");
        if (!hsts.toLowerCase().contains("preload"))           weaknesses.add("missing preload");
        if (!weaknesses.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".hsts.weak")
                    .title("Weak Strict-Transport-Security configuration")
                    .severity(Severity.LOW)
                    .confidence(Confidence.FIRM)
                    .url(url)
                    .description("HSTS header is present but has weaknesses: " + String.join("; ", weaknesses) + ". "
                            + "A short `max-age` means the browser stops enforcing HTTPS soon after the user leaves the site. "
                            + "Missing `includeSubDomains` means a malicious subdomain (e.g. `cdn.example.com` if attacker "
                            + "controls DNS for it) can still serve plaintext and steal cookies that aren't scoped tightly. "
                            + "Missing `preload` plus absence from the preload list means first-visit MITM is still possible.")
                    .remediation("Use `max-age=63072000; includeSubDomains; preload` (2 years). Submit the apex domain "
                            + "to hstspreload.org. If you cannot serve every subdomain over HTTPS, drop includeSubDomains "
                            + "until you can - but the wider gap is worse than fixing the subdomain.")
                    .evidence("Strict-Transport-Security: " + hsts)
                    .references(List.of("https://hstspreload.org/"))
                    .request(req)
                    .response(resp)
                    .build());
        }
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

    // ---------- X-Content-Type-Options ----------
    private void checkXcto(HttpRequest req, HttpResponse resp, String url, List<Finding> out) {
        String v = HttpUtil.headerValue(resp, "X-Content-Type-Options");
        if (v == null || !v.trim().equalsIgnoreCase("nosniff")) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".xcto.missing")
                    .title("Missing X-Content-Type-Options: nosniff")
                    .severity(Severity.LOW)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff responses and execute content "
                            + "the server did not intend to serve as such. Classic attack: a file-upload endpoint that returns a "
                            + "user-uploaded text/plain file - without nosniff, IE/Edge (and historically Firefox) may sniff "
                            + "embedded `<script>` tags and execute them in the origin's context. Same risk for served-as-JSON "
                            + "endpoints when an attacker controls the first few bytes of the response.")
                    .remediation("Set `X-Content-Type-Options: nosniff` on every response. There is no downside; "
                            + "configure it once at the proxy/framework layer.")
                    .evidence(v == null ? "(header absent)" : "X-Content-Type-Options: " + v)
                    .references(List.of("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"))
                    .request(req)
                    .response(resp)
                    .build());
        }
    }

    // ---------- X-Frame-Options / frame-ancestors ----------
    private void checkXfo(HttpRequest req, HttpResponse resp, String url, List<Finding> out) {
        String xfo = HttpUtil.headerValue(resp, "X-Frame-Options");
        String csp = HttpUtil.headerValue(resp, "Content-Security-Policy");
        boolean cspProtects = csp != null && csp.toLowerCase().contains("frame-ancestors");
        if (xfo == null && !cspProtects) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".xfo.missing")
                    .title("Missing clickjacking protection (no X-Frame-Options or CSP frame-ancestors)")
                    .severity(Severity.MEDIUM)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("Neither X-Frame-Options nor `frame-ancestors` in CSP is set, so any attacker page can embed this "
                            + "page in an iframe. Combined with CSS opacity tricks, this enables clickjacking: the victim sees "
                            + "an attacker's UI but their clicks land on the framed page - e.g. clicking 'Delete Account', "
                            + "approving an OAuth consent, or transferring funds. Particularly dangerous on state-changing "
                            + "endpoints (settings, payment confirmation, admin actions). frame-ancestors in CSP takes "
                            + "precedence over X-Frame-Options where both are set; CSP supports a list of allowed framing "
                            + "origins, X-Frame-Options does not.")
                    .remediation("Add `Content-Security-Policy: frame-ancestors 'none'` (or `'self'` if you have a legitimate "
                            + "in-app embedder). Optionally also `X-Frame-Options: DENY` for older browsers. Apply globally - "
                            + "the cost of accidentally framing a page you intended to allow is much lower than the cost of "
                            + "missing a state-changing endpoint.")
                    .references(List.of(
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                            "https://owasp.org/www-community/attacks/Clickjacking"))
                    .request(req)
                    .response(resp)
                    .build());
        } else if (xfo != null) {
            String lower = xfo.trim().toLowerCase();
            if (!(lower.equals("deny") || lower.equals("sameorigin") || lower.startsWith("allow-from"))) {
                out.add(Finding.builder()
                        .checkId(CHECK_ID_PREFIX + ".xfo.invalid")
                        .title("Invalid X-Frame-Options value")
                        .severity(Severity.LOW)
                        .confidence(Confidence.FIRM)
                        .url(url)
                        .description("X-Frame-Options value '" + xfo + "' is not recognised by browsers, which will ignore it "
                                + "entirely. Common mistake: comma-separated origins (e.g. `ALLOW-FROM https://a.com, https://b.com`) "
                                + "- XFO only accepts DENY, SAMEORIGIN, or a single ALLOW-FROM URL. For multiple allowed framers, "
                                + "use CSP `frame-ancestors`.")
                        .remediation("Use `DENY` or `SAMEORIGIN`. For fine-grained control over framing origins, "
                                + "switch to `Content-Security-Policy: frame-ancestors <list>`.")
                        .evidence("X-Frame-Options: " + xfo)
                        .request(req)
                        .response(resp)
                        .build());
            }
        }
    }

    // ---------- Referrer-Policy ----------
    private void checkReferrerPolicy(HttpRequest req, HttpResponse resp, String url, List<Finding> out) {
        String v = HttpUtil.headerValue(resp, "Referrer-Policy");
        if (v == null) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".referrer-policy.missing")
                    .title("Missing Referrer-Policy header")
                    .severity(Severity.LOW)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("Without an explicit Referrer-Policy, browsers fall back to `strict-origin-when-cross-origin` "
                            + "on most modern engines but older browsers default to leaking the full URL. The risk: URLs that "
                            + "contain secrets in query strings (password-reset tokens, OAuth `code` params, signed S3 URLs, "
                            + "API keys) are sent verbatim to every cross-origin resource - analytics, CDN-hosted fonts, "
                            + "third-party scripts - and end up in their access logs. This is how OAuth tokens routinely leak.")
                    .remediation("Set `Referrer-Policy: strict-origin-when-cross-origin` (the modern default - explicit is better) "
                            + "or `no-referrer` for maximum privacy. Combine with placing secrets in POST bodies or "
                            + "Authorization headers, never in URLs.")
                    .references(List.of("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"))
                    .request(req)
                    .response(resp)
                    .build());
        } else if (v.trim().equalsIgnoreCase("unsafe-url") || v.trim().equalsIgnoreCase("no-referrer-when-downgrade")) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".referrer-policy.weak")
                    .title("Weak Referrer-Policy value")
                    .severity(Severity.LOW)
                    .confidence(Confidence.FIRM)
                    .url(url)
                    .description("Referrer-Policy '" + v + "' leaks the full URL (path + query) to cross-origin destinations. "
                            + "Tokens or PII embedded in URLs reach third-party loggers. This is one of the more common "
                            + "ways OAuth `code` and password-reset tokens get logged in analytics platforms.")
                    .remediation("Use `strict-origin-when-cross-origin` or `no-referrer`.")
                    .evidence("Referrer-Policy: " + v)
                    .request(req)
                    .response(resp)
                    .build());
        }
    }

    // ---------- Permissions-Policy ----------
    private void checkPermissionsPolicy(HttpRequest req, HttpResponse resp, String url, List<Finding> out) {
        String v = HttpUtil.headerValue(resp, "Permissions-Policy");
        if (v == null) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".permissions-policy.missing")
                    .title("Missing Permissions-Policy header")
                    .severity(Severity.INFO)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("Permissions-Policy disables powerful browser features the application doesn't use - camera, "
                            + "microphone, geolocation, payment, USB, FLoC/topics, etc. Absence isn't itself exploitable, but "
                            + "if XSS happens later, the attacker payload gains access to whatever defaults the user's browser "
                            + "permits. Most apps need none of these capabilities; disabling them reduces blast radius for "
                            + "any future XSS or supply-chain compromise.")
                    .remediation("Set `Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
                            + "interest-cohort=()`. Extend with every feature your app does not legitimately need; the list of "
                            + "controlled features is at https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy.")
                    .references(List.of("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"))
                    .request(req)
                    .response(resp)
                    .build());
        }
    }

    // ---------- COOP / COEP / CORP ----------
    private void checkCrossOriginIsolation(HttpRequest req, HttpResponse resp, String url, List<Finding> out) {
        String coop = HttpUtil.headerValue(resp, "Cross-Origin-Opener-Policy");
        String coep = HttpUtil.headerValue(resp, "Cross-Origin-Embedder-Policy");
        String corp = HttpUtil.headerValue(resp, "Cross-Origin-Resource-Policy");

        List<String> missing = new ArrayList<>();
        if (coop == null) missing.add("Cross-Origin-Opener-Policy");
        if (coep == null) missing.add("Cross-Origin-Embedder-Policy");
        if (corp == null) missing.add("Cross-Origin-Resource-Policy");
        if (!missing.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(CHECK_ID_PREFIX + ".coop-coep-corp.missing")
                    .title("Cross-origin isolation headers not fully set")
                    .severity(Severity.INFO)
                    .confidence(Confidence.CERTAIN)
                    .url(url)
                    .description("Missing: " + String.join(", ", missing) + ". COOP/COEP/CORP enable cross-origin isolation, "
                            + "which mitigates Spectre-class side-channel leaks (cross-origin SharedArrayBuffer reads), "
                            + "tames `window.opener` access (a phishing primitive), and bounds resource embedding. Most "
                            + "exploitable on apps that handle sensitive data and load third-party content (auth pages, "
                            + "admin consoles). COOP `same-origin` is the most impactful - it closes the tab-handle leak "
                            + "that lets a popup-spawning attacker page read the opener's URL.")
                    .remediation("Add `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, "
                            + "and `Cross-Origin-Resource-Policy: same-origin` (loosen per-resource as needed). Some "
                            + "third-party embeds (e.g. social-login widgets) may break under COEP; deploy gradually and "
                            + "monitor `coep-report` reports.")
                    .references(List.of("https://web.dev/coop-coep/"))
                    .request(req)
                    .response(resp)
                    .build());
        }
    }
}
