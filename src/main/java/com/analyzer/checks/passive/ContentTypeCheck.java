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
 * Content-Type / charset hygiene on the seed response. Browsers fall back to MIME-sniffing when the
 * declared type is missing, wrong, or ambiguous, which has historically enabled XSS (a response the
 * server thinks is data gets executed as HTML/script) and charset-based XSS (UTF-7). This is distinct
 * from {@code SecurityHeadersCheck}, which reports the absence of the {@code X-Content-Type-Options}
 * header globally — here we look at the correctness of the declared type itself.
 *
 * Strictly passive.
 */
public class ContentTypeCheck implements Check {
    private static final String ID = "content-type";

    @Override public String id() { return ID; }
    @Override public String category() { return "Content-Type hygiene"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        String body = resp.bodyToString();
        boolean hasBody = body != null && !body.isEmpty();
        if (!hasBody) return out;

        String ct = HttpUtil.headerValue(resp, "Content-Type");
        String nosniff = HttpUtil.headerValue(resp, "X-Content-Type-Options");
        boolean sniffBlocked = nosniff != null && nosniff.toLowerCase().contains("nosniff");
        String trimmedBody = body.length() > 4096 ? body.substring(0, 4096) : body;
        String lead = trimmedBody.stripLeading().toLowerCase();
        boolean looksHtml = lead.startsWith("<!doctype html") || lead.startsWith("<html") || lead.contains("<head") || lead.contains("<body");

        // 1. No Content-Type at all on a body-bearing response.
        if (ct == null || ct.isBlank()) {
            out.add(build(ctx, resp, ID + ".missing", Severity.LOW,
                    "Response has a body but no Content-Type header",
                    "The response carries a body with no `Content-Type`, forcing every browser to guess the "
                        + "type by sniffing the bytes. If the content is attacker-influenced, a browser may sniff it "
                        + "as HTML and execute embedded script.",
                    "Always send an explicit, correct `Content-Type` (with charset for text) and add "
                        + "`X-Content-Type-Options: nosniff`."));
            return out;
        }

        String ctl = ct.toLowerCase();
        boolean isText = ctl.startsWith("text/") || ctl.contains("html") || ctl.contains("xml")
                || ctl.contains("javascript") || ctl.contains("json");

        // 2. Text content without a charset → charset sniffing (historically UTF-7 XSS).
        if (isText && !ctl.contains("charset=")) {
            out.add(build(ctx, resp, ID + ".no-charset", Severity.LOW,
                    "Text response declares no charset",
                    "`Content-Type: " + ct + "` omits a `charset`. Without an explicit charset the browser "
                        + "infers one, which has historically allowed UTF-7-based XSS and other encoding confusion in "
                        + "pages that reflect user input.",
                    "Append an explicit charset, e.g. `Content-Type: " + ct + "; charset=utf-8`, and serve all "
                        + "text as UTF-8."));
        }

        // 3. Body is clearly HTML but the declared type isn't, and sniffing isn't blocked.
        if (looksHtml && !ctl.contains("html") && !sniffBlocked) {
            out.add(build(ctx, resp, ID + ".mismatch", Severity.LOW,
                    "Response body looks like HTML but Content-Type is '" + HttpUtil.truncate(ct, 60) + "'",
                    "The body begins with HTML markup yet the declared `Content-Type` is `" + ct + "` and "
                        + "`X-Content-Type-Options: nosniff` is not set. A browser may sniff the response as HTML and "
                        + "render/execute it, turning a data endpoint into an XSS sink.",
                    "Declare the type that matches the actual content, or — if the data must not render as HTML — "
                        + "set `X-Content-Type-Options: nosniff` and an accurate type such as `application/json`."));
        }

        return out;
    }

    private Finding build(AnalysisContext ctx, HttpResponse resp, String checkId, Severity sev,
                          String title, String desc, String rem) {
        return Finding.builder()
                .checkId(checkId)
                .title(title)
                .severity(sev)
                .confidence(Confidence.FIRM)
                .url(ctx.targetUrl())
                .description(desc)
                .remediation(rem)
                .evidence("Content-Type: " + String.valueOf(HttpUtil.headerValue(resp, "Content-Type")))
                .references(List.of(
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver",
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options"))
                .request(ctx.seedRequest())
                .response(resp)
                .build();
    }
}
