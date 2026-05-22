package com.analyzer.checks;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Global redaction toggle. When enabled, request/response snippets used in findings and exported
 * reports have sensitive headers replaced with `<redacted>`.
 *
 * Default: ON. Findings include cookies/Authorization headers verbatim, which would leak into any
 * exported report when analyzing authenticated sessions. The UI exposes a toggle for users who
 * explicitly want unredacted output.
 */
public final class Redaction {
    private static final AtomicBoolean ENABLED = new AtomicBoolean(true);

    /** Header names redacted when enabled. */
    private static final Set<String> SENSITIVE = Set.of(
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "x-amz-security-token",
            "x-csrf-token"
    );

    private Redaction() {}

    public static boolean enabled() { return ENABLED.get(); }
    public static void setEnabled(boolean v) { ENABLED.set(v); }
    public static boolean isSensitive(String headerName) {
        return ENABLED.get() && headerName != null && SENSITIVE.contains(headerName.toLowerCase());
    }

    /** Applies redaction to a textual HTTP message snippet (works on either request or response). */
    public static String redactSnippet(String snippet) {
        if (snippet == null || !ENABLED.get()) return snippet;
        StringBuilder out = new StringBuilder(snippet.length());
        boolean inHeaders = true;
        for (String line : snippet.split("\\n", -1)) {
            if (inHeaders && line.isEmpty()) {
                inHeaders = false;
                out.append('\n');
                continue;
            }
            if (inHeaders) {
                int colon = line.indexOf(':');
                if (colon > 0) {
                    String name = line.substring(0, colon).trim();
                    if (isSensitive(name)) {
                        out.append(name).append(": <redacted>");
                    } else {
                        out.append(line);
                    }
                } else {
                    out.append(line);
                }
            } else {
                out.append(line);
            }
            out.append('\n');
        }
        // strip the trailing newline we always add
        if (out.length() > 0 && out.charAt(out.length() - 1) == '\n') {
            out.setLength(out.length() - 1);
        }
        return out.toString();
    }
}
