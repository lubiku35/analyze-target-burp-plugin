package com.analyzer.checks.passive;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WSTG-INFO-05 — Review webpage content for information leakage.
 *
 * Extracts HTML/JS comments and flags suspicious ones: TODO/FIXME notes,
 * embedded credentials, internal IPs/hostnames, debug flags.
 *
 * NOTE: Patterns are anchored to comment delimiters so we don't grep random source code.
 */
public class HtmlCommentsCheck implements Check {
    private static final String ID = "html-comments";

    private static final Pattern HTML_COMMENT = Pattern.compile("<!--([\\s\\S]*?)-->");
    private static final Pattern JS_BLOCK_COMMENT = Pattern.compile("/\\*([\\s\\S]*?)\\*/");
    private static final Pattern JS_LINE_COMMENT  = Pattern.compile("(?m)^\\s*//(.*)$");

    private static final Pattern SUSPICIOUS = Pattern.compile(
            "(?i)\\b(todo|fixme|hack|xxx|bug|password|passwd|pwd|secret|api[\\-_ ]?key|token|backdoor|debug|admin|internal only|do not deploy)\\b");
    private static final Pattern INTERNAL_IP =
            Pattern.compile("\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
                    + "|192\\.168\\.\\d{1,3}\\.\\d{1,3}"
                    + "|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}"
                    + "|127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b");

    private static final int MAX_BODY = 1_048_576;     // 1 MiB scan window
    private static final int MAX_COMMENTS_PER_KIND = 200;

    @Override public String id() { return ID; }
    @Override public String category() { return "Information leakage"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;
        String body = resp.bodyToString();
        if (body == null || body.isEmpty()) return out;
        if (body.length() > MAX_BODY) body = body.substring(0, MAX_BODY);

        Set<String> suspicious = new LinkedHashSet<>();
        Set<String> internals = new LinkedHashSet<>();

        scan(HTML_COMMENT, body, suspicious, internals);
        scan(JS_BLOCK_COMMENT, body, suspicious, internals);

        // Only scan JS line comments (`// …`) when the response is JavaScript. In HTML responses
        // line-comment regex catches things like `https://` URLs at the start of a line, which is noise.
        String contentType = HttpUtil.headerValue(resp, "Content-Type");
        if (contentType != null && contentType.toLowerCase().contains("javascript")) {
            scan(JS_LINE_COMMENT, body, suspicious, internals);
        }

        if (!suspicious.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".suspicious-comment")
                    .title("Suspicious developer comment(s) in response body (" + suspicious.size() + ")")
                    .severity(Severity.LOW)
                    .confidence(Confidence.TENTATIVE)
                    .url(ctx.targetUrl())
                    .description("HTML/JS comments contain keywords (TODO/FIXME/password/admin/debug etc.) that frequently leak "
                            + "implementation details or credentials. Review each manually.")
                    .remediation("Strip comments from production HTML/JS at the build step. Never ship credentials, "
                            + "internal hostnames, or 'do not deploy' notes in client-side code.")
                    .evidence(String.join("\n---\n", suspicious))
                    .references(List.of(
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"))
                    .request(ctx.seedRequest())
                    .response(resp)
                    .build());
        }
        if (!internals.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".internal-ip")
                    .title("Internal IP address(es) in response body (" + internals.size() + ")")
                    .severity(Severity.LOW)
                    .confidence(Confidence.FIRM)
                    .url(ctx.targetUrl())
                    .description("RFC1918 / loopback IP addresses appear in the response — typically inside comments or JS strings. "
                            + "These reveal internal network topology.")
                    .remediation("Replace internal IPs/hostnames in production assets with env-driven config; strip dev artefacts at build time.")
                    .evidence(String.join("\n", internals))
                    .request(ctx.seedRequest())
                    .response(resp)
                    .build());
        }
        return out;
    }

    private static void scan(Pattern p, String body, Set<String> suspicious, Set<String> internals) {
        Matcher m = p.matcher(body);
        int found = 0;
        while (m.find() && found < MAX_COMMENTS_PER_KIND) {
            String content = m.group(1);
            if (content == null) continue;
            String trimmed = content.trim();
            if (trimmed.isEmpty() || trimmed.length() < 4) continue;
            String snippet = HttpUtil.truncate(trimmed, 200);
            if (SUSPICIOUS.matcher(trimmed).find()) suspicious.add(snippet);
            Matcher ip = INTERNAL_IP.matcher(trimmed);
            while (ip.find()) internals.add(ip.group() + "  (in: \"" + HttpUtil.truncate(trimmed, 80) + "\")");
            found++;
        }
    }
}
