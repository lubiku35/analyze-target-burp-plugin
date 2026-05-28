package com.analyzer.checks.active;

import burp.api.montoya.http.message.requests.HttpRequest;
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

/**
 * Confirms that the site forces HTTPS. Issues a single GET to the plaintext {@code http://} origin
 * and checks whether the server redirects to {@code https://}. A site that serves content over HTTP
 * without an immediate redirect exposes users to passive eavesdropping and active downgrade/MITM.
 *
 * One extra request — gated by the global "Passive only" toggle via {@link #isActive()}.
 */
public class HttpsRedirectCheck implements Check {
    private static final String ID = "https-redirect";

    @Override public String id() { return ID; }
    @Override public String category() { return "Transport / HTTPS redirect"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI target;
        try {
            target = URI.create(ctx.targetUrl());
        } catch (RuntimeException e) {
            return out;
        }
        String host = target.getHost();
        if (host == null) return out;

        String httpUrl = "http://" + host + "/";
        HttpRequest probe;
        try {
            probe = HttpRequest.httpRequestFromUrl(httpUrl);
        } catch (RuntimeException e) {
            return out;
        }

        HttpResponse resp = ctx.cachedGet(probe);
        if (resp == null) return out; // host may simply not listen on :80 — not a finding

        int status = resp.statusCode();
        String location = HttpUtil.headerValue(resp, "Location");
        boolean redirectsToHttps = status >= 300 && status < 400
                && location != null && location.toLowerCase().startsWith("https://");

        if (redirectsToHttps) {
            // Good behaviour. Note it only if HSTS is absent on the redirect, since redirect-without-HSTS
            // still leaves the very first request downgradeable.
            String hsts = HttpUtil.headerValue(resp, "Strict-Transport-Security");
            if (hsts == null) {
                out.add(Finding.builder()
                        .checkId(ID + ".no-hsts-on-redirect")
                        .title("HTTP redirects to HTTPS but the redirect sets no HSTS header")
                        .severity(Severity.LOW)
                        .confidence(Confidence.FIRM)
                        .url(httpUrl)
                        .description("The plaintext endpoint correctly returns " + status + " → " + location
                                + ", but the redirect response carries no `Strict-Transport-Security` header. The "
                                + "first plaintext request is still interceptable (sslstrip), and without HSTS the "
                                + "browser has no instruction to use HTTPS pre-emptively next time.")
                        .remediation("Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on the "
                                + "redirect (and on HTTPS responses), and consider HSTS preloading.")
                        .evidence("Request: GET " + httpUrl + "\nResponse: " + status + " " + resp.reasonPhrase()
                                + "\nLocation: " + location)
                        .references(List.of(
                                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_HTTP_Strict_Transport_Security",
                                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"))
                        .request(probe)
                        .response(resp)
                        .build());
            }
            return out;
        }

        // No redirect to HTTPS. If the plaintext endpoint served a 2xx it's actively serving over HTTP.
        Severity sev = Severity.LOW;
        out.add(Finding.builder()
                .checkId(ID + ".no-redirect")
                .title("HTTP endpoint does not redirect to HTTPS")
                .severity(sev)
                .confidence(Confidence.FIRM)
                .url(httpUrl)
                .description("A request to `" + httpUrl + "` returned " + status + " "
                        + (status >= 200 && status < 300
                            ? "and served content directly over plaintext HTTP — no redirect to HTTPS. "
                              + "Traffic (including any session cookies sent over HTTP) is exposed to network "
                              + "eavesdroppers and active downgrade attacks."
                            : "with no HTTPS redirect. Verify whether the site is reachable over plaintext at all.")
                        + (location != null ? "\n\nLocation header: " + location : ""))
                .remediation("Redirect all HTTP traffic to HTTPS with a 301/308 before serving any content, set "
                        + "HSTS, and mark all cookies `Secure` so they are never transmitted over plaintext.")
                .evidence("Request: GET " + httpUrl + "\nResponse: " + status + " " + resp.reasonPhrase()
                        + (location != null ? "\nLocation: " + location : ""))
                .references(List.of(
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"))
                .request(probe)
                .response(resp)
                .build());
        return out;
    }
}
