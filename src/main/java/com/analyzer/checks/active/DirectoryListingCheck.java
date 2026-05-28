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
import java.util.List;

/**
 * Probes the directory containing the seed resource for an auto-generated directory listing
 * (Apache {@code mod_autoindex}, nginx {@code autoindex on}, IIS directory browsing, Python
 * {@code http.server}). An open listing hands an attacker a free file inventory — backups, configs,
 * source, and other files never meant to be linked.
 *
 * One extra request — gated by the global "Passive only" toggle via {@link #isActive()}.
 */
public class DirectoryListingCheck implements Check {
    private static final String ID = "dir-listing";

    /** Signatures of the common server-generated index pages. */
    private static final String[] SIGNATURES = {
            "<title>index of /",          // Apache / nginx
            "index of /",
            "directory listing for",      // Python http.server / Tornado
            "[to parent directory]",      // IIS
            "<h1>directory: "             // some app servers
    };

    @Override public String id() { return ID; }
    @Override public String category() { return "Directory listing"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI target;
        try {
            target = URI.create(ctx.targetUrl());
        } catch (RuntimeException e) {
            return out;
        }

        String dirUrl = directoryOf(target);
        if (dirUrl == null) return out;

        HttpRequest probe;
        try {
            probe = HttpRequest.httpRequestFromUrl(dirUrl);
        } catch (RuntimeException e) {
            return out;
        }

        HttpResponse resp = ctx.cachedGet(probe);
        if (resp == null || resp.statusCode() != 200) return out;

        String body = resp.bodyToString();
        if (body == null || body.isEmpty()) return out;
        String head = (body.length() > 8192 ? body.substring(0, 8192) : body).toLowerCase();

        String matched = null;
        for (String sig : SIGNATURES) {
            if (head.contains(sig)) { matched = sig; break; }
        }
        if (matched == null) return out;

        out.add(Finding.builder()
                .checkId(ID + ".enabled")
                .title("Directory listing enabled at " + dirUrl)
                .severity(Severity.MEDIUM)
                .confidence(Confidence.FIRM)
                .url(dirUrl)
                .description("Requesting the directory `" + dirUrl + "` returned an auto-generated file listing "
                        + "(matched signature: \"" + matched + "\"). Directory browsing exposes the full contents of "
                        + "the directory — including backups, archives, configuration, and source files that are not "
                        + "linked anywhere and were never meant to be discoverable.")
                .remediation("Disable automatic directory indexing (Apache `Options -Indexes`, nginx `autoindex off;`, "
                        + "IIS: turn off Directory Browsing). Place an index file in each directory and ensure no "
                        + "sensitive files are served from web-accessible paths.")
                .evidence("GET " + dirUrl + " → 200; listing signature \"" + matched + "\" present.\n"
                        + HttpUtil.truncate(body, 400))
                .references(List.of(
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
                        "https://owasp.org/www-community/attacks/Forced_browsing"))
                .request(probe)
                .response(resp)
                .build());
        return out;
    }

    /** Build the URL of the directory containing the seed resource (the path up to the last '/'). */
    private static String directoryOf(URI target) {
        String scheme = target.getScheme();
        String host = target.getHost();
        if (scheme == null || host == null) return null;
        String path = target.getPath();
        if (path == null || path.isEmpty()) path = "/";
        int lastSlash = path.lastIndexOf('/');
        String dir = (lastSlash <= 0) ? "/" : path.substring(0, lastSlash + 1);
        if (dir.equals("/") && (path.equals("/") || lastSlash == path.length() - 1)) {
            // Seed already targets a directory root — nothing new to probe beyond it.
            // Still worth checking the root itself once.
            dir = "/";
        }
        int port = target.getPort();
        String authority = host + (port == -1 ? "" : ":" + port);
        return scheme + "://" + authority + dir;
    }
}
