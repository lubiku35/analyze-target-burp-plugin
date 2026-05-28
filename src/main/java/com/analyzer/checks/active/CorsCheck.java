package com.analyzer.checks.active;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Canary;
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
 * Tests common CORS misconfigurations:
 *   - reflective Origin (server echoes whatever Origin was sent)
 *   - null origin accepted (sandboxed iframes, file://)
 *   - regex bypasses: prefix/suffix matching flaws (target.com.external / external host with target prefix)
 *   - wildcard with credentials (browser will block but server config is dangerous)
 */
public class CorsCheck implements Check {
    private static final String ID = "cors";

    @Override public String id() { return ID; }
    @Override public String category() { return "CORS"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest seed = ctx.seedRequest();
        if (seed == null) return out;

        String host;
        try {
            host = new URI(ctx.targetUrl()).getHost();
        } catch (Exception e) {
            return out;
        }
        if (host == null) return out;

        // Canaries are self-explanatory in target access logs — see com.analyzer.checks.Canary.
        String reflective   = Canary.corsOrigin();
        String nullOrigin   = "null";
        String suffixBypass = Canary.suffixBypassOrigin(host);
        String prefixBypass = Canary.prefixBypassOrigin(host);

        probe(ctx, seed.withRemovedHeader("Origin").withAddedHeader("Origin", reflective),
                "Reflective Origin", reflective, out);
        probe(ctx, seed.withRemovedHeader("Origin").withAddedHeader("Origin", nullOrigin),
                "Null Origin", nullOrigin, out);
        probe(ctx, seed.withRemovedHeader("Origin").withAddedHeader("Origin", suffixBypass),
                "Suffix-bypass Origin (target.host." + Canary.HOST + ")", suffixBypass, out);
        probe(ctx, seed.withRemovedHeader("Origin").withAddedHeader("Origin", prefixBypass),
                "Prefix-bypass Origin (target-name prefix on external canary host)", prefixBypass, out);

        return out;
    }

    private void probe(AnalysisContext ctx, HttpRequest req, String variant, String sentOrigin, List<Finding> out) {
        try {
            HttpResponse resp = ctx.sendRequest(req);
            if (resp == null) return;

            String aco  = HttpUtil.headerValue(resp, "Access-Control-Allow-Origin");
            String acc  = HttpUtil.headerValue(resp, "Access-Control-Allow-Credentials");
            if (aco == null) return;

            boolean reflected = aco.trim().equalsIgnoreCase(sentOrigin);
            boolean wildcard  = aco.trim().equals("*");
            boolean credentials = acc != null && acc.trim().equalsIgnoreCase("true");

            if (reflected) {
                Severity sev = credentials ? Severity.MEDIUM : Severity.LOW;
                out.add(Finding.builder()
                        .checkId(ID + ".reflection")
                        .title("CORS reflects arbitrary Origin (" + variant + ")" + (credentials ? " with credentials" : ""))
                        .severity(sev)
                        .confidence(Confidence.CERTAIN)
                        .url(ctx.targetUrl())
                        .description("The server returned `Access-Control-Allow-Origin: " + aco + "` in response to Origin `"
                                + sentOrigin + "`. " + (credentials
                                ? "Combined with `Access-Control-Allow-Credentials: true`, this allows a malicious origin to "
                                  + "read authenticated responses cross-origin."
                                : "Reflective Origin is the building block of CORS bypass attacks even without credentials."))
                        .remediation("Validate Origin against an explicit allow-list. Never reflect arbitrary values, and never "
                                + "combine reflection with `Allow-Credentials: true`.")
                        .evidence("Sent Origin: " + sentOrigin + "\nAccess-Control-Allow-Origin: " + aco
                                + (acc != null ? "\nAccess-Control-Allow-Credentials: " + acc : ""))
                        .references(List.of(
                                "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing",
                                "https://portswigger.net/web-security/cors",
                                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"))
                        .request(req)
                        .response(resp)
                        .build());
            } else if (wildcard && credentials) {
                out.add(Finding.builder()
                        .checkId(ID + ".wildcard-credentials")
                        .title("CORS wildcard with credentials (invalid + dangerous config)")
                        .severity(Severity.MEDIUM)
                        .confidence(Confidence.CERTAIN)
                        .url(ctx.targetUrl())
                        .description("Server returns `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`. "
                                + "Browsers reject this combo, but it usually indicates the underlying CORS code is broken - under other "
                                + "code paths it may reflect the Origin instead.")
                        .remediation("Pick one: either drop credentials and keep the wildcard, or list specific allowed origins. Never both.")
                        .evidence("Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true")
                        .request(req)
                        .response(resp)
                        .build());
            }
        } catch (Exception e) {
            ctx.api().logging().logToError("[analyze-target] cors probe failed: " + e);
        }
    }
}
