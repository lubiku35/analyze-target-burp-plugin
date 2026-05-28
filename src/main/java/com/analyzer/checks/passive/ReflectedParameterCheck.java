package com.analyzer.checks.passive;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Passively flags request parameters whose values are reflected verbatim in the response body.
 * Reflection is the precondition for reflected XSS, HTML injection, and several open-redirect and
 * header-injection variants — so a fast inventory of "which inputs come back out, and in what
 * context" is one of the highest-yield leads at the start of a test.
 *
 * <p>This is a lead, not a confirmed vulnerability: it does not inject payloads or prove the
 * reflection is exploitable (no encoding analysis, no break-out test). It only tells you where to
 * point Burp Repeater next. Strictly passive — reads the seed request/response and sends nothing.</p>
 */
public class ReflectedParameterCheck implements Check {
    private static final String ID = "reflection";

    /** Ignore very short or low-entropy values — they reflect by coincidence and just create noise. */
    private static final int MIN_VALUE_LEN = 4;
    private static final int MAX_BODY_BYTES = 2 * 1024 * 1024;

    @Override public String id() { return ID; }
    @Override public String category() { return "Input reflection"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest req = ctx.seedRequest();
        HttpResponse resp = ctx.seedResponse();
        if (req == null || resp == null) return out;

        String body = resp.bodyToString();
        if (body == null || body.isEmpty()) return out;
        if (body.length() > MAX_BODY_BYTES) body = body.substring(0, MAX_BODY_BYTES);

        // Only consider responses that render in a browser — reflection into JSON/binary is far less
        // likely to be an XSS sink, and flagging it inflates false positives.
        String contentType = HttpUtil.headerValue(resp, "Content-Type");
        boolean htmlish = contentType == null || contentType.toLowerCase().contains("html")
                || contentType.toLowerCase().contains("xml");

        List<ParsedHttpParameter> params;
        try {
            params = req.parameters();
        } catch (RuntimeException e) {
            return out;
        }

        // name -> where it reflected, deduped by parameter name.
        Map<String, String> reflected = new LinkedHashMap<>();
        for (ParsedHttpParameter p : params) {
            if (p.type() == HttpParameterType.COOKIE) continue; // cookies are not user-controlled sinks here
            String raw = p.value();
            if (raw == null) continue;
            String decoded = urlDecode(raw);
            if (decoded.length() < MIN_VALUE_LEN) continue;
            if (decoded.chars().allMatch(Character::isDigit)) continue; // skip plain numeric ids

            boolean hit = body.contains(decoded) || (!decoded.equals(raw) && body.contains(raw));
            if (hit) {
                reflected.put(p.name(), p.type() + " parameter `" + p.name() + "` = "
                        + HttpUtil.truncate(decoded, 80));
            }
        }

        if (reflected.isEmpty()) return out;

        Severity sev = htmlish ? Severity.LOW : Severity.INFO;
        out.add(Finding.builder()
                .checkId(ID + ".reflected-params")
                .title(reflected.size() + " request parameter(s) reflected in the response")
                .severity(sev)
                .confidence(Confidence.TENTATIVE)
                .url(ctx.targetUrl())
                .description("The following request inputs appear verbatim in the response body:\n- "
                        + String.join("\n- ", reflected.values()) + "\n\n"
                        + "Reflection is the precondition for reflected XSS and HTML injection. "
                        + (htmlish
                            ? "The response is HTML/XML, so each reflection is a candidate injection sink."
                            : "The response is not HTML, so XSS risk is lower — but reflection can still enable "
                              + "header injection, open redirect, or content-type-confusion attacks.")
                        + "\n\nThis is a lead only. Confirm manually: inject a context-appropriate payload in "
                        + "Burp Repeater and check whether it executes or is correctly encoded on output.")
                .remediation("Apply context-aware output encoding at every reflection point (HTML entity, "
                        + "attribute, JS-string, or URL encoding as appropriate). Prefer a framework's auto-escaping "
                        + "templating. Treat all request input as untrusted regardless of source.")
                .evidence("Reflected parameters:\n" + String.join("\n", reflected.values()))
                .references(List.of(
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"))
                .request(req)
                .response(resp)
                .build());
        return out;
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            return s;
        }
    }
}
