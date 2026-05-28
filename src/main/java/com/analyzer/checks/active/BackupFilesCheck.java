package com.analyzer.checks.active;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests for backup / editor temp / OS-cruft files left on the web root.
 *
 * The list comes from years of real findings during pentests: editor backups (~, .swp, .bak),
 * version-control hide files (.svn/, .hg/, .bzr/), OS metadata (.DS_Store, Thumbs.db), CI/build
 * leftovers (config.bak, settings.json.old), and dump files. The probe uses a self-explanatory
 * path so a defender reading their logs immediately understands the intent.
 *
 * Aligned with OWASP WSTG-CONF-04 (Review Old Backup and Unreferenced Files for Sensitive
 * Information).
 */
public class BackupFilesCheck implements Check {
    private static final String ID = "backup-files";

    /** Path + severity if found. */
    private record Candidate(String path, Severity severity, String note) {}

    private static final List<Candidate> CANDIDATES = List.of(
            // Version control directories left in the web root
            new Candidate("/.svn/entries",        Severity.HIGH,   "Subversion metadata — source disclosure"),
            new Candidate("/.svn/wc.db",          Severity.HIGH,   "Subversion working-copy DB — source disclosure"),
            new Candidate("/.hg/store",           Severity.HIGH,   "Mercurial metadata — source disclosure"),
            new Candidate("/.hg/hgrc",            Severity.HIGH,   "Mercurial config — source disclosure"),
            new Candidate("/.bzr/branch-format",  Severity.HIGH,   "Bazaar metadata — source disclosure"),
            new Candidate("/CVS/Root",            Severity.HIGH,   "CVS metadata — source disclosure"),

            // OS / editor cruft
            new Candidate("/.DS_Store",           Severity.LOW,    "macOS Finder metadata — leaks file names"),
            new Candidate("/Thumbs.db",           Severity.LOW,    "Windows thumbnail cache — leaks file names"),
            new Candidate("/desktop.ini",         Severity.LOW,    "Windows folder config — leaks file names"),

            // Editor backups for common config files
            new Candidate("/web.config.bak",      Severity.MEDIUM, "Backup of web.config — credentials likely"),
            new Candidate("/web.config~",         Severity.MEDIUM, "Editor backup of web.config — credentials likely"),
            new Candidate("/web.config.old",      Severity.MEDIUM, "Old web.config — credentials likely"),
            new Candidate("/.htaccess.bak",       Severity.MEDIUM, "Backup of .htaccess"),
            new Candidate("/.htpasswd",           Severity.HIGH,   "Apache password file"),
            new Candidate("/wp-config.php.bak",   Severity.HIGH,   "WordPress config backup — DB creds"),
            new Candidate("/wp-config.php~",      Severity.HIGH,   "WordPress editor backup — DB creds"),
            new Candidate("/wp-config.php.old",   Severity.HIGH,   "Old WordPress config — DB creds"),
            new Candidate("/wp-config.php.save",  Severity.HIGH,   "Saved WordPress config — DB creds"),
            new Candidate("/configuration.php.bak", Severity.HIGH, "Joomla config backup — DB creds"),
            new Candidate("/config.php.bak",      Severity.HIGH,   "PHP config backup"),
            new Candidate("/config.php~",         Severity.HIGH,   "Editor backup of config.php"),
            new Candidate("/database.yml.bak",    Severity.HIGH,   "Rails DB config backup — DB creds"),
            new Candidate("/settings.py.bak",     Severity.HIGH,   "Django settings backup — SECRET_KEY / DB creds"),
            new Candidate("/local_settings.py",   Severity.HIGH,   "Django local settings — SECRET_KEY / DB creds"),
            new Candidate("/appsettings.json.bak",Severity.MEDIUM, ".NET Core settings backup"),
            new Candidate("/parameters.yml.bak",  Severity.MEDIUM, "Symfony parameters backup"),

            // Dumps / archives
            new Candidate("/dump.sql",            Severity.HIGH,   "SQL dump — database contents"),
            new Candidate("/dump.sql.gz",         Severity.HIGH,   "Compressed SQL dump"),
            new Candidate("/database.sql",        Severity.HIGH,   "SQL dump — database contents"),
            new Candidate("/db.sql",              Severity.HIGH,   "SQL dump — database contents"),
            new Candidate("/backup.sql",          Severity.HIGH,   "SQL dump — database contents"),
            new Candidate("/backup.zip",          Severity.HIGH,   "Archive backup"),
            new Candidate("/backup.tar.gz",       Severity.HIGH,   "Archive backup"),
            new Candidate("/site.zip",            Severity.HIGH,   "Archive backup — full site contents"),
            new Candidate("/www.zip",             Severity.HIGH,   "Archive backup — full site contents"),
            new Candidate("/site-backup.zip",     Severity.HIGH,   "Archive backup — full site contents"),
            new Candidate("/api/v1/swagger.json.bak", Severity.MEDIUM, "Backup of API description"),
            new Candidate("/.bash_history",       Severity.MEDIUM, "Shell history"),
            new Candidate("/.zsh_history",        Severity.MEDIUM, "Shell history"),
            new Candidate("/.ssh/id_rsa",         Severity.CRITICAL, "SSH private key — RCE if reachable")
    );

    @Override public String id() { return ID; }
    @Override public String category() { return "Backup files / leftovers"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI base;
        try { base = URI.create(ctx.targetUrl()); }
        catch (IllegalArgumentException e) { return out; }
        String origin = origin(base);
        if (origin == null) return out;

        // Cache the seed's body length once: an SPA shell's 200 catch-all is almost always exactly
        // the size of the seed page. Anything within ±5 % of that is treated as a shell.
        int seedLen = ctx.seedResponse() == null || ctx.seedResponse().body() == null
                ? -1 : ctx.seedResponse().body().length();

        for (Candidate c : CANDIDATES) {
            if (Thread.currentThread().isInterrupted()) break;
            String url = origin + c.path();
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                HttpResponse resp = ctx.sendRequest(req);
                if (resp == null) continue;
                int code = resp.statusCode();
                // Backup files should be served as 200 OK directly. 3xx redirects are almost always
                // a router shipping the user to a login page — not a confirmed backup hit.
                if (code != 200) continue;
                int len = resp.body() == null ? 0 : resp.body().length();
                if (len < 16) continue;
                // A backup file's payload is never HTML. If the server is returning HTML at this path
                // it's almost certainly an SPA's catch-all 200, not an actual leaked file.
                String contentType = headerValue(resp, "Content-Type").toLowerCase();
                if (contentType.contains("text/html")) continue;
                String head = resp.bodyToString();
                if (head != null) {
                    String lower = head.substring(0, Math.min(head.length(), 256)).toLowerCase();
                    if (lower.contains("<!doctype html") || lower.contains("<html")) continue;
                }
                // SPA shell detection: same body size as the seed, ±5 %.
                if (seedLen > 0 && Math.abs(len - seedLen) < Math.max(50, seedLen / 20)) continue;
                out.add(Finding.builder()
                        .checkId(ID + ".hit")
                        .title("Backup / leftover file reachable: " + c.path())
                        .severity(c.severity())
                        .confidence(Confidence.FIRM)
                        .url(url)
                        .description(
                                "The path " + c.path() + " is reachable with HTTP " + code + " — "
                              + c.note() + ".\n\n"
                              + "Backup files and editor cruft routinely contain credentials, source "
                              + "code, or full database dumps. They're invisible to normal users but "
                              + "trivially discoverable with directory enumeration.\n\n"
                              + "Aligned with OWASP WSTG-CONF-04 (Review Old Backup and Unreferenced "
                              + "Files for Sensitive Information).")
                        .remediation(
                                "Remove the file from the web root and add a deploy-time check that "
                              + "rejects glob patterns like *.bak, *~, *.old, *.swp, .DS_Store, .svn, "
                              + ".hg. For credentials in the file: rotate them.")
                        .evidence("Status: " + code + "\nContent-Length: " + len)
                        .references(List.of(
                                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html"))
                        .request(req)
                        .response(resp)
                        .build());
            } catch (Exception e) {
                ctx.api().logging().logToError("[analyze-target] " + ID + ": " + url + " failed: " + e);
            }
        }
        return out;
    }

    private static String headerValue(HttpResponse resp, String name) {
        try {
            return resp.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase(name))
                    .map(h -> h.value()).findFirst().orElse("");
        } catch (Exception e) { return ""; }
    }

    private static String origin(URI u) {
        String scheme = u.getScheme();
        String host = u.getHost();
        if (scheme == null || host == null) return null;
        int port = u.getPort();
        if (port == -1) return scheme + "://" + host;
        return scheme + "://" + host + ":" + port;
    }
}
