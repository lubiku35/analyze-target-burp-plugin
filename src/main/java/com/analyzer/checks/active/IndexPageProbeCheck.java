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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Probes common index / default-page filenames at the site root. Each filename's extension is a
 * strong stack hint — `/index.php` returning 200 means the server runs PHP; `/Default.aspx` means
 * ASP.NET; `/index.jsp` or `/index.do` means a Java servlet container.
 *
 * We probe a curated list (no full wordlist scan — keeps traffic predictable at ~25 requests) and
 * emit ONE consolidated finding listing every hit with the inferred technology. The result
 * complements {@link com.analyzer.checks.passive.TechFingerprintCheck} which looks at headers
 * and cookies; this one looks at filesystem layout, which sometimes reveals stacks that headers
 * have been stripped to hide.
 */
public class IndexPageProbeCheck implements Check {
    private static final String ID = "index-probe";

    /** Path → human-readable technology hint. */
    private static final Map<String, String> PROBES = new LinkedHashMap<>();
    static {
        // Static / generic
        PROBES.put("/index.html",   "Static HTML");
        PROBES.put("/index.htm",    "Static HTML (legacy)");
        PROBES.put("/home.html",    "Static HTML (home variant)");
        // PHP
        PROBES.put("/index.php",    "PHP");
        PROBES.put("/index.php3",   "PHP (very old)");
        PROBES.put("/index.php4",   "PHP 4 (EOL)");
        PROBES.put("/index.php5",   "PHP 5 (EOL)");
        PROBES.put("/index.phtml",  "PHP (phtml)");
        PROBES.put("/home.php",     "PHP");
        // Java
        PROBES.put("/index.jsp",    "Java servlet container (JSP)");
        PROBES.put("/index.jspx",   "Java (JSPX)");
        PROBES.put("/index.do",     "Java Struts (.do)");
        PROBES.put("/index.action", "Java Struts 2 (.action)");
        // ASP / ASP.NET
        PROBES.put("/index.asp",    "Classic ASP");
        PROBES.put("/index.aspx",   "ASP.NET Web Forms");
        PROBES.put("/Default.aspx", "ASP.NET Web Forms (PascalCase default)");
        PROBES.put("/Default.asp",  "Classic ASP (PascalCase default)");
        PROBES.put("/default.htm",  "IIS legacy default");
        PROBES.put("/Main.aspx",    "ASP.NET (Main convention)");
        // ColdFusion
        PROBES.put("/index.cfm",    "Adobe ColdFusion");
        // CGI / Perl
        PROBES.put("/index.cgi",    "CGI script");
        PROBES.put("/index.pl",     "Perl CGI");
        // Python / Ruby (rarely served raw, but occasionally on misconfigured servers)
        PROBES.put("/index.py",     "Python script (unusual — possible misconfig)");
        PROBES.put("/app.py",       "Python Flask-style entry (unusual — possible misconfig)");
        PROBES.put("/index.rb",     "Ruby script (unusual — possible misconfig)");
    }

    @Override public String id() { return ID; }
    @Override public String category() { return "Index page enumeration"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI base;
        try {
            URI seed = new URI(ctx.targetUrl());
            base = new URI(seed.getScheme(), null, seed.getHost(), seed.getPort(), "/", null, null);
        } catch (Exception e) {
            return out;
        }

        // Snapshot the seed body length so we can spot SPA catch-all 200s (the same index.html for
        // every URL). Without this filter every probed path looks like a "hit" on a modern SPA.
        int seedLen = ctx.seedResponse() == null || ctx.seedResponse().body() == null
                ? -1 : ctx.seedResponse().body().length();

        List<String> hits = new ArrayList<>();
        HttpRequest firstReq = null;
        HttpResponse firstResp = null;

        for (Map.Entry<String, String> probe : PROBES.entrySet()) {
            if (Thread.currentThread().isInterrupted()) break;
            String url = base.resolve(probe.getKey()).toString();
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpResponse resp = ctx.sendRequest(req);
                if (resp == null) continue;
                int sc = resp.statusCode();
                // 200 means the file is served directly (the only signal we trust). 403 means it's
                // there but access-denied — also a useful stack signal. 3xx are noise on modern apps
                // (router redirects to /login) and previously produced large false-positive counts.
                if (!(sc == 200 || sc == 403)) continue;

                int bodyLen = resp.body() == null ? 0 : resp.body().length();
                // Reject SPA catch-alls: if the 200 has the same body size as the seed (±5 %), it's
                // almost certainly the router returning index.html.
                if (sc == 200 && seedLen > 0 && Math.abs(bodyLen - seedLen) < Math.max(50, seedLen / 20)) {
                    continue;
                }

                hits.add(String.format("%s  →  HTTP %d, %d bytes  [%s]",
                        probe.getKey(), sc, bodyLen, probe.getValue()));
                if (firstReq == null) {
                    firstReq = req;
                    firstResp = resp;
                }
            } catch (Exception e) {
                ctx.api().logging().logToError("[analyze-target] index-probe failed (" + url + "): " + e);
            }
        }

        if (hits.isEmpty()) return out;

        // Severity: INFO when nothing high-value (just .html / .htm); LOW when a server-side
        // extension is exposed (.php / .jsp / .aspx / .cfm) — these are stack-fingerprinting hits.
        boolean serverSideHit = hits.stream().anyMatch(h ->
                h.contains(".php") || h.contains(".jsp") || h.contains(".do") || h.contains(".action")
                        || h.contains(".asp") || h.contains(".cfm") || h.contains(".cgi") || h.contains(".pl"));
        Severity sev = serverSideHit ? Severity.LOW : Severity.INFO;

        out.add(Finding.builder()
                .checkId(ID + ".hits")
                .title("Index / default page enumeration revealed " + hits.size() + " reachable file(s)")
                .severity(sev)
                .confidence(Confidence.FIRM)
                .url(base.toString())
                .description("Common index / default-page filenames were probed at the site root. Each hit doubles as "
                        + "a stack hint: a reachable `/index.php` strongly implies PHP, `/Default.aspx` implies "
                        + "ASP.NET Web Forms, `/index.jsp` or `/.do` implies a Java servlet container, `/index.cfm` "
                        + "implies ColdFusion. This complements header-based fingerprinting and sometimes reveals "
                        + "stacks where the operator has stripped `Server` / `X-Powered-By`.\n\n"
                        + "Hits:\n  " + String.join("\n  ", hits))
                .remediation("If the file is intentionally public (e.g. the actual landing page), no action needed. "
                        + "If it is a leftover from a previous deployment or a default page shipped with the server, "
                        + "remove it. Avoid serving stack-revealing extensions where you can (use rewrite rules to "
                        + "expose extensionless URLs).")
                .evidence(String.join("\n", hits))
                .references(List.of(
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"))
                .request(firstReq)
                .response(firstResp)
                .build());
        return out;
    }
}
