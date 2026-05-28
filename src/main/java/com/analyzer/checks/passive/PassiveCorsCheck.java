package com.analyzer.checks.passive;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.util.List;
import java.util.ArrayList;

/**
 * Passive CORS review: reads the {@code Access-Control-Allow-Origin} / {@code -Allow-Credentials}
 * headers already present on the seed response and flags dangerous configurations without sending
 * anything. Complements the active {@code CorsCheck}, which injects crafted Origins to probe the
 * server's allow-list logic — this one catches misconfigurations visible in normal traffic.
 */
public class PassiveCorsCheck implements Check {
    private static final String ID = "cors-passive";

    @Override public String id() { return ID; }
    @Override public String category() { return "CORS (passive)"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest req = ctx.seedRequest();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        String acao = HttpUtil.headerValue(resp, "Access-Control-Allow-Origin");
        if (acao == null || acao.isBlank()) return out;
        acao = acao.trim();

        boolean creds = "true".equalsIgnoreCase(
                String.valueOf(HttpUtil.headerValue(resp, "Access-Control-Allow-Credentials")).trim());
        String origin = HttpUtil.headerValue(req, "Origin");

        Severity sev;
        String summary;

        if (acao.equals("*")) {
            if (creds) {
                sev = Severity.MEDIUM;
                summary = "ACAO is `*` together with Allow-Credentials: true. Browsers reject this exact "
                        + "combination, but it signals the server is trying to allow any origin with credentials — "
                        + "often paired with origin-reflection logic that IS exploitable. Probe it actively.";
            } else {
                sev = Severity.LOW;
                summary = "ACAO is the wildcard `*` without credentials. Fine for genuinely public, "
                        + "unauthenticated data, but it means any site can read this response — confirm the "
                        + "endpoint exposes nothing sensitive.";
            }
        } else if (acao.equalsIgnoreCase("null")) {
            sev = creds ? Severity.MEDIUM : Severity.LOW;
            summary = "ACAO is `null`. The `null` origin is forgeable from a sandboxed iframe or a "
                    + "`data:`/`file:` document, so trusting it is effectively an allow-all"
                    + (creds ? " — and credentials are allowed, so cross-origin reads of authenticated data are possible." : ".");
        } else if (origin != null && acao.equalsIgnoreCase(origin.trim())) {
            sev = creds ? Severity.MEDIUM : Severity.LOW;
            summary = "ACAO reflects the request Origin (`" + HttpUtil.truncate(origin, 80) + "`)"
                    + (creds ? " with Allow-Credentials: true. This is the classic exploitable CORS misconfig: any "
                             + "attacker origin is echoed back and can read authenticated responses."
                             : ". Reflection without credentials is lower risk but still widens who can read the response; "
                             + "confirm the allow-list isn't simply echoing whatever Origin is sent.");
        } else {
            sev = Severity.INFO;
            summary = "ACAO allows a specific cross-origin: `" + HttpUtil.truncate(acao, 100) + "`"
                    + (creds ? " with credentials" : "") + ". Confirm that origin is trusted and the trust is intentional.";
        }

        out.add(Finding.builder()
                .checkId(ID + ".acao")
                .title("CORS Access-Control-Allow-Origin: " + HttpUtil.truncate(acao, 40)
                        + (creds ? " (+credentials)" : ""))
                .severity(sev)
                .confidence(Confidence.FIRM)
                .url(ctx.targetUrl())
                .description(summary + "\n\nObserved headers:\n"
                        + "  Access-Control-Allow-Origin: " + acao + "\n"
                        + "  Access-Control-Allow-Credentials: " + (creds ? "true" : "(absent/false)"))
                .remediation("Maintain an explicit server-side allow-list of trusted origins and echo back only "
                        + "an exact match. Never reflect arbitrary Origins, never trust `null`, and never combine "
                        + "`*` with credentials. Scope CORS to the specific endpoints that need it.")
                .evidence("Access-Control-Allow-Origin: " + acao
                        + "\nAccess-Control-Allow-Credentials: " + (creds ? "true" : "(absent)")
                        + (origin != null ? "\nRequest Origin: " + origin : ""))
                .references(List.of(
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing"))
                .request(req)
                .response(resp)
                .build());
        return out;
    }
}
