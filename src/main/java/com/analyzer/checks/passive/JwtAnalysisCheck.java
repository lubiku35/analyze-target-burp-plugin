package com.analyzer.checks.passive;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive JWT inspection. Finds JSON Web Tokens already present in the seed exchange — the request
 * {@code Authorization: Bearer …} header, request {@code Cookie} header, and response
 * {@code Set-Cookie} headers — decodes the header and payload, and flags weak configurations:
 *
 * <ul>
 *   <li>{@code alg=none} — the token is unsigned; if the server accepts it, authentication is bypassable.</li>
 *   <li>HMAC algorithms (HS256/384/512) — secret-key signing, brute-forceable offline if the secret is weak.</li>
 *   <li>Missing {@code exp} claim — the token never expires.</li>
 *   <li>Already-expired {@code exp} — usually benign, noted for completeness.</li>
 *   <li>Sensitive claims (email, roles, admin flags) — PII / privilege data exposed client-side.</li>
 * </ul>
 *
 * Strictly passive: it only reads tokens that were already in the captured traffic and sends nothing.
 * Exploitability (whether the server actually honours {@code alg=none} or a weak secret) must be
 * confirmed manually — hence {@link Confidence#TENTATIVE} on the security implications.
 */
public class JwtAnalysisCheck implements Check {
    private static final String ID = "jwt";

    /** header.payload(.signature) — signature segment may be empty for alg=none. */
    private static final Pattern JWT = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]*");

    private static final Pattern ALG  = Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXP  = Pattern.compile("\"exp\"\\s*:\\s*(\\d{6,})");
    private static final String[] SENSITIVE_CLAIMS = {
            "email", "e-mail", "role", "roles", "admin", "is_admin", "isadmin",
            "password", "ssn", "phone", "permissions", "scope", "groups"
    };

    @Override public String id() { return ID; }
    @Override public String category() { return "JWT / tokens"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpRequest req = ctx.seedRequest();
        HttpResponse resp = ctx.seedResponse();

        // Collect candidate strings from the places a JWT legitimately lives.
        StringBuilder haystack = new StringBuilder();
        String auth = HttpUtil.headerValue(req, "Authorization");
        if (auth != null) haystack.append(auth).append('\n');
        String cookieHdr = HttpUtil.headerValue(req, "Cookie");
        if (cookieHdr != null) haystack.append(cookieHdr).append('\n');
        if (resp != null) {
            for (String sc : HttpUtil.headerValues(resp, "Set-Cookie")) haystack.append(sc).append('\n');
        }
        if (haystack.length() == 0) return out;

        Set<String> seen = new LinkedHashSet<>();
        Matcher m = JWT.matcher(haystack);
        while (m.find()) seen.add(m.group());

        for (String token : seen) {
            String[] parts = token.split("\\.", -1);
            if (parts.length < 2) continue;
            String header  = decodeSegment(parts[0]);
            String payload = decodeSegment(parts[1]);
            if (header == null || payload == null) continue; // not actually base64url JSON

            String alg = firstGroup(ALG, header);
            List<String> issues = new ArrayList<>();
            Severity sev = Severity.INFO;
            Confidence conf = Confidence.TENTATIVE;

            if (alg != null && alg.equalsIgnoreCase("none")) {
                issues.add("alg=none — token is unsigned. If the server accepts it, an attacker can forge "
                        + "arbitrary claims (auth bypass / privilege escalation).");
                sev = Severity.HIGH;
            } else if (alg != null && alg.toUpperCase().startsWith("HS")) {
                issues.add("HMAC signing (" + alg + ") — the signature relies on a shared secret. If that "
                        + "secret is weak it can be brute-forced offline, letting an attacker mint valid tokens.");
                sev = escalate(sev, Severity.LOW);
            }

            Long exp = parseLong(firstGroup(EXP, payload));
            if (exp == null) {
                issues.add("No `exp` claim — the token never expires, so a captured token is valid forever.");
                sev = escalate(sev, Severity.LOW);
            } else if (exp * 1000L < System.currentTimeMillis()) {
                issues.add("Token is expired (exp in the past) — noted for completeness.");
            }

            List<String> sensitive = new ArrayList<>();
            String lowerPayload = payload.toLowerCase();
            for (String claim : SENSITIVE_CLAIMS) {
                if (lowerPayload.contains("\"" + claim + "\"")) sensitive.add(claim);
            }
            if (!sensitive.isEmpty()) {
                issues.add("Payload carries sensitive claim(s): " + String.join(", ", sensitive)
                        + ". JWT payloads are base64, NOT encrypted — anything here is readable by the client "
                        + "and anyone who captures the token.");
                sev = escalate(sev, Severity.LOW);
            }

            if (issues.isEmpty()) {
                issues.add("No obvious weakness in the token configuration — listed for inventory.");
            }

            out.add(Finding.builder()
                    .checkId(ID + (alg != null && alg.equalsIgnoreCase("none") ? ".alg-none" : ".token"))
                    .title("JWT detected" + (alg != null ? " (alg=" + alg + ")" : ""))
                    .severity(sev)
                    .confidence(conf)
                    .url(ctx.targetUrl())
                    .description("A JSON Web Token was present in the captured exchange.\n\n"
                            + "Decoded header: " + HttpUtil.truncate(header, 400) + "\n"
                            + "Decoded payload: " + HttpUtil.truncate(payload, 600) + "\n\n"
                            + "Observations:\n- " + String.join("\n- ", issues))
                    .remediation("Sign tokens with a strong asymmetric algorithm (RS256/ES256) and reject "
                            + "`alg=none` and algorithm-confusion (RS↔HS) server-side. Always set a short `exp`. "
                            + "Keep PII and authorization decisions out of the (readable) payload; validate "
                            + "the signature and `aud`/`iss` on every request.")
                    .evidence("Token: " + HttpUtil.truncate(token, 120)
                            + "\nHeader: " + HttpUtil.truncate(header, 200)
                            + "\nPayload: " + HttpUtil.truncate(payload, 300))
                    .references(List.of(
                            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
                            "https://datatracker.ietf.org/doc/html/rfc8725"))
                    .request(req)
                    .response(resp)
                    .build());
        }
        return out;
    }

    /** Base64url-decode a JWT segment to a UTF-8 string; returns null if it isn't valid JSON-looking base64url. */
    private static String decodeSegment(String seg) {
        if (seg == null || seg.isEmpty()) return null;
        try {
            int pad = (4 - (seg.length() % 4)) % 4;
            String padded = seg + "====".substring(0, pad);
            byte[] raw = Base64.getUrlDecoder().decode(padded);
            String s = new String(raw, StandardCharsets.UTF_8);
            return s.contains("{") ? s : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String firstGroup(Pattern p, String s) {
        if (s == null) return null;
        Matcher m = p.matcher(s);
        return m.find() ? m.group(1) : null;
    }

    private static Long parseLong(String s) {
        if (s == null) return null;
        try { return Long.parseLong(s); } catch (NumberFormatException e) { return null; }
    }

    /** Returns whichever severity is higher (lower ordinal = higher severity). */
    private static Severity escalate(Severity a, Severity b) {
        return a.ordinal() <= b.ordinal() ? a : b;
    }
}
