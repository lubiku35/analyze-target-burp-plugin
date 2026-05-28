package com.analyzer.checks.passive;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
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
 * Passively flags serialized-object markers in the captured exchange. Server-side deserialization of
 * attacker-controllable data is a classic path to remote code execution, so spotting that an app
 * round-trips serialized blobs through cookies, parameters, or hidden fields is a strong lead worth
 * chasing with a dedicated tool (ysoserial, ViewState exploitation, PHPGGC).
 *
 * <p>Detected formats:</p>
 * <ul>
 *   <li>Java serialized stream — base64 beginning {@code rO0AB} (the {@code 0xAC 0xED 0x00 0x05}
 *       stream magic), or the raw {@code \xAC\xED} bytes.</li>
 *   <li>ASP.NET {@code __VIEWSTATE} — flagged for manual MAC/encryption review.</li>
 *   <li>PHP serialized data — {@code O:<n>:"Class"} / {@code a:<n>:{} } shapes in inputs.</li>
 * </ul>
 *
 * Strictly passive: reads the seed request/response only. Exploitability is unproven
 * ({@link Confidence#TENTATIVE}); confirm the blob is actually deserialized server-side before reporting.
 */
public class SerializedObjectCheck implements Check {
    private static final String ID = "deserialization";
    private static final int MAX_BODY_BYTES = 2 * 1024 * 1024;

    private static final Pattern JAVA_B64   = Pattern.compile("rO0AB[A-Za-z0-9+/=]{8,}");
    private static final Pattern JAVA_RAW   = Pattern.compile("\\xAC\\xED\\x00\\x05");
    private static final Pattern PHP_SER    = Pattern.compile("(?:^|[=&;\\s\"'])(?:O:\\d+:\"[^\"]+\"|a:\\d+:\\{)");
    private static final Pattern VIEWSTATE  = Pattern.compile("(?i)__VIEWSTATE");

    @Override public String id() { return ID; }
    @Override public String category() { return "Insecure deserialization"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest req = ctx.seedRequest();
        HttpResponse resp = ctx.seedResponse();

        // Build the searchable surface: request body + parameter values + cookies + response body.
        StringBuilder sb = new StringBuilder();
        if (req != null) {
            String rb = req.bodyToString();
            if (rb != null) sb.append(rb).append('\n');
            String cookie = HttpUtil.headerValue(req, "Cookie");
            if (cookie != null) sb.append(cookie).append('\n');
            try {
                for (ParsedHttpParameter p : req.parameters()) {
                    if (p.value() != null) sb.append(p.name()).append('=').append(p.value()).append('\n');
                }
            } catch (RuntimeException ignored) { /* params unparueable — body+cookie still scanned */ }
        }
        if (resp != null) {
            for (String sc : HttpUtil.headerValues(resp, "Set-Cookie")) sb.append(sc).append('\n');
            String body = resp.bodyToString();
            if (body != null) {
                sb.append(body.length() > MAX_BODY_BYTES ? body.substring(0, MAX_BODY_BYTES) : body);
            }
        }
        String surface = sb.toString();
        if (surface.isEmpty()) return out;

        // Java serialized — highest severity (ysoserial gadget chains → RCE).
        String javaB64 = firstMatch(JAVA_B64, surface);
        boolean javaRaw = JAVA_RAW.matcher(surface).find();
        if (!javaB64.isEmpty() || javaRaw) {
            out.add(finding(ctx, req, resp, ID + ".java",
                    "Java serialized object detected",
                    Severity.HIGH,
                    "A Java serialized object stream was found in the exchange (base64 `rO0AB…` or raw "
                        + "`0xACED0005` magic). If this value is attacker-controllable and deserialized by the "
                        + "server, it is a direct path to remote code execution via gadget chains.",
                    "Never deserialize untrusted data with Java's native serialization. Use a data-only "
                        + "format (JSON) with a safe parser, enable a deserialization allow-list/look-ahead "
                        + "(e.g. `ObjectInputFilter`), and remove dangerous gadget libraries from the classpath. "
                        + "Confirm exploitability with ysoserial against a controlled value.",
                    !javaB64.isEmpty() ? "Match: " + HttpUtil.truncate(javaB64, 120) : "raw 0xACED0005 stream",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"));
        }

        // ASP.NET ViewState — MAC/encryption can't be confirmed passively, so flag for review.
        if (VIEWSTATE.matcher(surface).find()) {
            out.add(finding(ctx, req, resp, ID + ".viewstate",
                    "ASP.NET __VIEWSTATE present — review MAC / encryption",
                    Severity.LOW,
                    "The page uses ASP.NET ViewState. ViewState is a serialized .NET object graph. If "
                        + "`enableViewStateMac` is disabled or the machineKey is known/leaked, ViewState becomes "
                        + "a deserialization RCE sink (the ViewState-YSoSerial.Net class of attacks).",
                    "Ensure ViewState MAC is enabled and a strong, secret, per-app machineKey is configured. "
                        + "Do not store sensitive data in ViewState. Confirm MAC status with a tool such as "
                        + "viewstate / ysoserial.net before reporting impact.",
                    "Found __VIEWSTATE field in the response.",
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Insecure_Deserialization"));
        }

        // PHP serialized — medium; object injection if unserialize() touches user input.
        if (PHP_SER.matcher(surface).find()) {
            out.add(finding(ctx, req, resp, ID + ".php",
                    "PHP serialized data detected",
                    Severity.MEDIUM,
                    "A PHP serialized structure (`O:n:\"Class\"…` or `a:n:{…}`) appears in the exchange. If it "
                        + "reaches `unserialize()` on attacker-controllable input, PHP Object Injection can lead to "
                        + "file write, SQLi, or RCE through magic-method gadget chains.",
                    "Avoid `unserialize()` on user input — use `json_decode()` instead. If unavoidable, pass "
                        + "`['allowed_classes' => false]` and validate the input. Confirm with PHPGGC before reporting impact.",
                    "Match: " + HttpUtil.truncate(firstMatch(PHP_SER, surface), 120),
                    "https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"));
        }

        return out;
    }

    private static String firstMatch(Pattern p, String s) {
        Matcher m = p.matcher(s);
        return m.find() ? m.group() : "";
    }

    private Finding finding(AnalysisContext ctx, HttpRequest req, HttpResponse resp,
                            String checkId, String title, Severity sev,
                            String desc, String rem, String evidence, String ref) {
        return Finding.builder()
                .checkId(checkId)
                .title(title)
                .severity(sev)
                .confidence(Confidence.TENTATIVE)
                .url(ctx.targetUrl())
                .description(desc)
                .remediation(rem)
                .evidence(evidence)
                .references(List.of(ref))
                .request(req)
                .response(resp)
                .build();
    }
}
