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
 * Sensitive-content caching check. Authenticated or per-user responses that lack
 * {@code Cache-Control: no-store} can be retained by shared proxies or the browser's
 * back/forward cache, exposing them to other users of a shared machine or to cache poisoning.
 *
 * Passive: reads the seed response only. To avoid noise it only fires when the response looks
 * personalised (it sets a cookie, or the request carried Authorization / Cookie).
 */
public class CacheControlCheck implements Check {
    private static final String ID = "cache-control";

    @Override public String id() { return ID; }
    @Override public String category() { return "Caching"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        boolean setsCookie = !HttpUtil.headerValues(resp, "Set-Cookie").isEmpty();
        boolean authed = HttpUtil.headerValue(ctx.seedRequest(), "Authorization") != null
                || HttpUtil.headerValue(ctx.seedRequest(), "Cookie") != null;
        if (!setsCookie && !authed) return out;

        String cc = HttpUtil.headerValue(resp, "Cache-Control");
        String pragma = HttpUtil.headerValue(resp, "Pragma");
        String ccLower = cc == null ? "" : cc.toLowerCase();

        if (ccLower.contains("no-store")) return out; // best practice already in place

        boolean publicCache = ccLower.contains("public");
        boolean privateOnly = ccLower.contains("private");

        String reason;
        if (cc == null && pragma == null) {
            reason = "No Cache-Control or Pragma header present.";
        } else if (publicCache) {
            reason = "Cache-Control marks the response `public`: " + cc;
        } else if (!privateOnly) {
            reason = "Cache-Control lacks `no-store`/`private`: " + (cc != null ? cc : "(none)");
        } else {
            reason = "Cache-Control is `private` but not `no-store`: " + cc;
        }

        Severity sev = (cc == null && pragma == null) || publicCache ? Severity.LOW : Severity.INFO;
        out.add(Finding.builder()
                .checkId(ID + ".sensitive-cacheable")
                .title("Sensitive response may be cacheable")
                .severity(sev)
                .confidence(Confidence.TENTATIVE)
                .url(ctx.targetUrl())
                .description("This response appears to carry per-user or authenticated content (it sets a cookie, or the "
                        + "request was authenticated) but does not set `Cache-Control: no-store`. Shared proxies or the "
                        + "browser cache may retain it, exposing it to other users of a shared machine or via cache poisoning.")
                .remediation("For authenticated or personalised responses send `Cache-Control: no-store` (add `Pragma: no-cache` "
                        + "for legacy clients). Reserve `public` and long `max-age` for genuinely static, non-sensitive assets.")
                .evidence(reason)
                .references(List.of(
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"))
                .request(ctx.seedRequest())
                .response(resp)
                .build());
        return out;
    }
}
