package com.analyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.HyperlinkEvent;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Font;
import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Read-only narrative summary of an analysis run. Updated after each run completes (and again on
 * load when state is restored). The synthesis renders as cards on a Burp-native background, with
 * sections for: target, severity counts, probable stack, JavaScript inventory (libraries / paths),
 * highest-impact findings, and rule-based follow-ups.
 */
public class SummaryPanel extends JPanel {
    private final MontoyaApi api;
    private final Palette palette;
    private final JTextPane content = new JTextPane();

    public SummaryPanel(MontoyaApi api, Palette palette) {
        super(new BorderLayout());
        this.api = api;
        this.palette = palette;
        setBackground(palette.background);
        setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        // Title strip
        JPanel titleBar = new JPanel(new BorderLayout());
        titleBar.setBackground(palette.background);
        titleBar.setBorder(BorderFactory.createEmptyBorder(10, 14, 8, 14));
        JLabel title = new JLabel("Target analysis");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        title.setForeground(palette.accent);
        titleBar.add(title, BorderLayout.WEST);
        add(titleBar, BorderLayout.NORTH);

        content.setContentType("text/html");
        content.setEditable(false);
        content.setOpaque(true);
        content.setBackground(palette.background);
        content.setForeground(palette.foreground);
        content.setBorder(BorderFactory.createEmptyBorder(0, 14, 14, 14));
        // Read-only summary — keep the default arrow cursor so it doesn't look like a resize/text edge.
        content.setCursor(java.awt.Cursor.getDefaultCursor());
        content.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED && e.getURL() != null) {
                try {
                    if (Desktop.isDesktopSupported()) Desktop.getDesktop().browse(URI.create(e.getURL().toString()));
                } catch (Exception ignored) {}
            }
        });

        JScrollPane scroll = new JScrollPane(content,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(palette.background);
        add(scroll, BorderLayout.CENTER);

        clear();
    }

    /** Render the empty-state when no analysis has run yet. */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            content.setText(html(
                    "<div class='card'>"
                  + "<div class='muted'>No analysis run yet. Send a request to the Target tab and click "
                  + "<b>Run analysis</b> — a synthesis of the findings will appear here.</div>"
                  + "</div>"));
            content.setCaretPosition(0);
        });
    }

    /** Build and render the summary for the latest analysis run. Safe to call from any thread. */
    public void updateSummary(HttpRequest target, List<Finding> findings) {
        SwingUtilities.invokeLater(() -> {
            StringBuilder body = new StringBuilder(8192);

            // -- Target card -----------------------------------------------------------
            body.append("<div class='card'>");
            body.append("<div class='section'>Target</div>");
            if (target != null) {
                String acc = toHex(palette.accent);
                // Render the method as a table cell so cellpadding actually applies in Swing's HTMLEditorKit.
                body.append("<table cellpadding='5' cellspacing='0' style='border-collapse:separate;'><tr>")
                    .append("<td bgcolor='").append(acc).append("'><font color='#ffffff'><b>")
                    .append(esc(target.method())).append("</b></font></td>")
                    .append("<td>&nbsp;&nbsp;<code>").append(esc(target.url())).append("</code></td>")
                    .append("</tr></table>");
            } else {
                body.append("<div class='muted'>(no target — restore state failed?)</div>");
            }
            body.append("</div>");

            // -- Severity overview -----------------------------------------------------
            EnumMap<Severity, Integer> counts = new EnumMap<>(Severity.class);
            for (Severity s : Severity.values()) counts.put(s, 0);
            for (Finding f : findings) counts.merge(f.severity(), 1, Integer::sum);

            body.append("<div class='card'>");
            body.append("<div class='section'>Findings — ").append(findings.size()).append(" total</div>");

            // Swing's HTMLEditorKit ignores CSS padding/border-radius on inline-block spans, so render
            // the badges as <table> cells with cellpadding/cellspacing — those it honours.
            body.append("<table cellpadding='7' cellspacing='6' style='border-collapse:separate;'><tr>");
            for (Severity s : Severity.values()) {
                String hex = toHex(palette.severityBg(s.label()));
                String fg  = toHex(palette.severityFg(s.label()));
                body.append("<td bgcolor='").append(hex).append("' align='center'>")
                    .append("<font color='").append(fg).append("'><b>")
                    .append(s.label()).append(": ").append(counts.get(s))
                    .append("</b></font></td>");
            }
            body.append("</tr></table>");
            body.append("</div>");

            // -- Probable stack --------------------------------------------------------
            Set<String> stackHints = collectStackHints(findings);
            body.append("<div class='card'>");
            body.append("<div class='section'>Probable stack</div>");
            if (stackHints.isEmpty()) {
                body.append("<div class='muted'>No stack-fingerprint hits in this run.</div>");
            } else {
                body.append("<ul class='clean'>");
                for (String hint : stackHints) {
                    body.append("<li>").append(esc(hint)).append("</li>");
                }
                body.append("</ul>");
            }
            body.append("</div>");

            // -- JavaScript inventory: libraries + linked paths ------------------------
            Set<String> jsLibraries = collectJsLibraries(findings);
            Set<String> linkInventory = collectLinkInventory(findings);
            if (!jsLibraries.isEmpty() || !linkInventory.isEmpty()) {
                body.append("<div class='card'>");
                body.append("<div class='section'>JavaScript &amp; links</div>");
                if (!jsLibraries.isEmpty()) {
                    body.append("<div class='sub'>Detected libraries</div>");
                    body.append("<ul class='clean'>");
                    for (String lib : jsLibraries) body.append("<li>").append(esc(lib)).append("</li>");
                    body.append("</ul>");
                }
                if (!linkInventory.isEmpty()) {
                    body.append("<div class='sub'>Discovered paths / endpoints (top 20)</div>");
                    body.append("<ul class='clean'>");
                    int i = 0;
                    for (String link : linkInventory) {
                        if (i++ >= 20) break;
                        body.append("<li><code>").append(esc(link)).append("</code></li>");
                    }
                    body.append("</ul>");
                }
                body.append("</div>");
            }

            // -- Highest-impact findings ----------------------------------------------
            body.append("<div class='card'>");
            body.append("<div class='section'>Highest-impact findings</div>");
            List<Finding> top = findings.stream()
                    .sorted(Comparator.comparingInt((Finding f) -> f.severity().ordinal())
                            .thenComparing(Finding::title))
                    .limit(7)
                    .toList();
            if (top.isEmpty()) {
                body.append("<div class='muted'>(none)</div>");
            } else {
                // Render each row as a 2-column table — left cell holds the padded severity badge,
                // right cell holds the title + check id. Tables are the only inline element Swing's
                // HTMLEditorKit reliably pads via cellpadding.
                body.append("<table cellpadding='4' cellspacing='4' style='border-collapse:separate;'>");
                int idx = 0;
                for (Finding f : top) {
                    idx++;
                    String hex = toHex(palette.severityBg(f.severity().label()));
                    String fg  = toHex(palette.severityFg(f.severity().label()));
                    body.append("<tr>")
                        .append("<td valign='top'><font color='").append(toHex(palette.mutedForeground))
                        .append("'>").append(idx).append(".</font></td>")
                        .append("<td valign='top' bgcolor='").append(hex).append("' align='center'>")
                        .append("<font color='").append(fg).append("'><b>")
                        .append(f.severity().label()).append("</b></font></td>")
                        .append("<td valign='top'>").append(esc(f.title()))
                        .append(" <font color='").append(toHex(palette.mutedForeground))
                        .append("'>(").append(esc(f.checkId())).append(")</font></td>")
                        .append("</tr>");
                }
                body.append("</table>");
            }
            body.append("</div>");

            // -- Suggested follow-ups -------------------------------------------------
            List<String> suggestions = SuggestionRules.suggest(findings);
            body.append("<div class='card'>");
            body.append("<div class='section'>Suggested follow-ups</div>");
            if (suggestions.isEmpty()) {
                body.append("<div class='muted'>No rule-based suggestions for this run.</div>");
            } else {
                body.append("<ul class='clean'>");
                for (String s : suggestions) body.append("<li>").append(s).append("</li>");
                body.append("</ul>");
            }
            body.append("</div>");

            body.append("<div class='footer'>This summary is synthesised by a small rule engine over "
                      + "the findings list — it doesn't see anything you don't. Treat suggestions as ideas, "
                      + "not gospel.</div>");

            content.setText(html(body.toString()));
            content.setCaretPosition(0);
        });
    }

    /** Wraps the body in a theme-aware HTML shell. All colours are sourced from the Palette. */
    private String html(String inner) {
        String fg    = toHex(palette.foreground);
        String mut   = toHex(palette.mutedForeground);
        String acc   = toHex(palette.accent);
        String bg    = toHex(palette.background);
        String card  = toHex(palette.panelBackground);
        String border = toHex(palette.border);
        return "<html><head><style>"
                + "body{font-family:-apple-system,'SF Pro Text','Segoe UI',sans-serif;font-size:12.5px;"
                + "color:" + fg + ";background:" + bg + ";margin:0;padding:0;}"
                + ".card{background:" + card + ";border:1px solid " + border + ";"
                + "padding:12px 14px;margin:0 0 10px 0;}"
                + ".section{color:" + acc + ";font-weight:700;font-size:11px;text-transform:uppercase;"
                + "letter-spacing:0.6px;margin-bottom:8px;}"
                + ".sub{color:" + mut + ";font-weight:600;font-size:11px;margin:8px 0 4px 0;"
                + "text-transform:uppercase;letter-spacing:0.4px;}"
                + ".target{font-size:13px;margin:2px 0 0 0;}"
                + ".method{display:inline-block;padding:1px 8px;background:" + acc + ";color:#ffffff;"
                + "font-weight:600;border-radius:3px;margin-right:8px;}"
                + ".badges{display:block;margin:2px 0;}"
                + ".badge{display:inline-block;padding:3px 9px;border-radius:11px;"
                + "font-weight:600;font-size:11px;margin-right:6px;}"
                + ".badge.small{padding:1px 6px;font-size:10px;border-radius:8px;}"
                + ".muted{color:" + mut + ";}"
                + ".muted.small{font-size:11px;}"
                + ".footer{color:" + mut + ";font-size:11px;margin:14px 4px 0 4px;}"
                + "a{color:" + acc + ";text-decoration:none;}"
                + "a:hover{text-decoration:underline;}"
                + "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;}"
                + "ul.clean,ol.clean{margin:4px 0 0 18px;padding:0;}"
                + "ul.clean li,ol.clean li{margin:3px 0;}"
                + "</style></head><body>" + inner + "</body></html>";
    }

    // ---- Synthesis helpers --------------------------------------------------

    /**
     * Collect human-readable stack hints from the findings whose evidence/title carries
     * fingerprint info. Sources: tech-fingerprint, index-probe, error-fingerprint.
     */
    private static Set<String> collectStackHints(List<Finding> findings) {
        Set<String> hints = new LinkedHashSet<>();
        for (Finding f : findings) {
            String id = f.checkId();
            if (id.startsWith("tech-fingerprint")) {
                for (String line : f.evidence().split("\\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) hints.add(trimmed);
                }
            } else if (id.startsWith("index-probe")) {
                hints.add("Filesystem hints: " + f.title()
                        .replace("Index / default page enumeration revealed ", ""));
            } else if (id.startsWith("error-fingerprint.match")) {
                int colon = f.title().indexOf(':');
                if (colon > 0) hints.add("Error-page fingerprint: " + f.title().substring(colon + 1).trim());
            }
        }
        return hints;
    }

    /** Pull JS library names out of the tech-fingerprint evidence — those lines look like "jQuery 3.6.0". */
    private static Set<String> collectJsLibraries(List<Finding> findings) {
        Set<String> libs = new LinkedHashSet<>();
        for (Finding f : findings) {
            if (!f.checkId().startsWith("tech-fingerprint")) continue;
            for (String line : f.evidence().split("\\n")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) continue;
                // Heuristic: a library hint is "<Library>: <version>" or "<Library> <version>".
                // We keep anything that looks like it has a JS library name and a version-ish token.
                String lower = trimmed.toLowerCase();
                if (lower.contains("jquery") || lower.contains("angular") || lower.contains("react")
                        || lower.contains("vue") || lower.contains("bootstrap") || lower.contains("backbone")
                        || lower.contains("ember") || lower.contains("d3") || lower.contains("lodash")
                        || lower.contains("moment") || lower.contains("prototype.js") || lower.contains("mootools")
                        || lower.contains("dojo") || lower.contains("ext js") || lower.contains("svelte")
                        || lower.contains("next.js") || lower.contains("nuxt") || lower.contains("require.js")) {
                    libs.add(trimmed);
                }
            }
        }
        return libs;
    }

    /** Pull discovered URLs/paths from the link-extraction check (deduped, capped at the caller). */
    private static Set<String> collectLinkInventory(List<Finding> findings) {
        Set<String> links = new LinkedHashSet<>();
        for (Finding f : findings) {
            if (!f.checkId().startsWith("link-extract")) continue;
            for (String line : f.evidence().split("\\n")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;
                if (trimmed.length() > 240) trimmed = trimmed.substring(0, 240) + "…";
                links.add(trimmed);
            }
        }
        return links;
    }

    private static String toHex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    // ============================================================================================
    // Rule-based suggestion engine. Each rule is a (predicate, suggestion) pair.
    // Suggestions are emitted only when the predicate matches the current findings set.
    // ============================================================================================
    private static final class SuggestionRules {
        private record Rule(String label, Predicate<List<Finding>> when, String suggestion) {}

        private static final List<Rule> RULES = List.of(
                rule(".git exposed",
                        fs -> hasCheckId(fs, "sensitive-paths.hit") && evidenceContains(fs, "/.git/"),
                        "<b>Exposed .git/</b> — clone history with <code>git-dumper</code> or "
                                + "<a href='https://github.com/internetwache/GitTools'>GitTools/Dumper</a> "
                                + "to recover source code, commit messages, and pre-commit secrets."),
                rule(".env exposed",
                        fs -> hasCheckId(fs, "sensitive-paths.hit") && evidenceContains(fs, "/.env"),
                        "<b>Exposed .env</b> — read it for API keys, DB credentials, and JWT signing "
                                + "secrets. Rotate every secret it contains immediately if confirmed."),
                rule("Spring Boot Actuator",
                        fs -> evidenceContains(fs, "/actuator"),
                        "<b>Spring Boot Actuator</b> — try <code>/actuator/env</code>, "
                                + "<code>/actuator/heapdump</code>, <code>/actuator/loggers</code>, "
                                + "<code>/actuator/mappings</code>. The heap dump often contains live "
                                + "credentials and session tokens."),
                rule("Backup archive",
                        fs -> hasCheckId(fs, "sensitive-paths.hit")
                                && (evidenceContains(fs, "backup.zip") || evidenceContains(fs, "backup.tar")),
                        "<b>Backup archive exposed</b> — download and inspect for source code, "
                                + "database dumps, and credentials."),
                rule("WordPress",
                        fs -> stackContains(fs, "WordPress") || stackContains(fs, "wp-content")
                                || stackContains(fs, "wp-login"),
                        "<b>WordPress detected</b> — run "
                                + "<code>wpscan --url &lt;target&gt; --enumerate vp,vt,u</code> for vulnerable "
                                + "plugins, themes, and user enumeration."),
                rule("Drupal",
                        fs -> stackContains(fs, "Drupal"),
                        "<b>Drupal detected</b> — run <code>droopescan scan drupal -u &lt;target&gt;</code> "
                                + "and check for known SA-CORE advisories matching the version."),
                rule("Joomla",
                        fs -> stackContains(fs, "Joomla"),
                        "<b>Joomla detected</b> — try <code>joomscan -u &lt;target&gt;</code>; check for "
                                + "/administrator and known extension CVEs."),
                rule("Tomcat Manager",
                        fs -> evidenceContains(fs, "Tomcat") && evidenceContains(fs, "/manager"),
                        "<b>Tomcat Manager exposed</b> — try default credentials "
                                + "(<code>tomcat:tomcat</code>, <code>admin:admin</code>); a successful login "
                                + "allows WAR deployment for RCE."),
                rule("Jenkins login",
                        fs -> evidenceContains(fs, "Jenkins"),
                        "<b>Jenkins login page exposed</b> — try <code>/script</code> (Groovy console — RCE "
                                + "if reachable unauthenticated) and check for CVE-2024-23897 (file read)."),
                rule("PHP backend",
                        fs -> stackContains(fs, "PHP") || stackContains(fs, "phpsessid")
                                || stackContains(fs, "/index.php"),
                        "<b>PHP backend</b> — probe <code>/phpinfo.php</code>, <code>/info.php</code>, "
                                + "common admin paths (<code>/phpmyadmin</code>, <code>/adminer</code>, "
                                + "<code>/wp-admin</code>)."),
                rule("ASP.NET",
                        fs -> stackContains(fs, "ASP.NET") || stackContains(fs, "__VIEWSTATE"),
                        "<b>ASP.NET detected</b> — check <code>__VIEWSTATE</code> integrity "
                                + "(CVE-2017-9248 / unkeyed ViewState → RCE via ysoserial.net); look for "
                                + "<code>/trace.axd</code>, <code>/elmah.axd</code>."),
                rule("Swagger / OpenAPI",
                        fs -> hasCheckId(fs, "api-discovery.hit") && evidenceContains(fs, "swagger"),
                        "<b>Swagger / OpenAPI endpoint exposed</b> — pull <code>/swagger.json</code> or "
                                + "<code>/openapi.json</code>, generate a client (openapi-generator-cli), and "
                                + "audit every parameter for auth and IDOR."),
                rule("GraphQL endpoint",
                        fs -> hasCheckId(fs, "api-discovery.hit") && evidenceContains(fs, "graphql"),
                        "<b>GraphQL endpoint</b> — check introspection (<code>__schema</code>), batched query "
                                + "abuse, depth limits, and authorisation per-resolver."),
                rule("CORS reflective",
                        fs -> hasCheckId(fs, "cors.reflection"),
                        "<b>CORS Origin reflection</b> — test with a real attacker-controlled origin to "
                                + "confirm; if credentials flow, you have authenticated cross-origin read."),
                rule("Host header reflected",
                        fs -> hasCheckId(fs, "host-header.reflection"),
                        "<b>Host header reflected</b> — test password-reset endpoints next: a poisoned Host "
                                + "header in a password-reset email is a classic account-takeover primitive."),
                rule("HTTP methods PUT/DELETE/TRACE",
                        fs -> evidenceContains(fs, "PUT") && hasCheckId(fs, "http-methods"),
                        "<b>Risky HTTP methods enabled</b> — verify PUT actually writes (try uploading a "
                                + "small <code>.html</code>) and DELETE actually removes (against a benign "
                                + "resource you can recreate)."),
                rule("Authorization header present",
                        fs -> evidenceContains(fs, "Authorization: Bearer")
                                || evidenceContains(fs, "Authorization: bearer"),
                        "<b>Bearer token present</b> — decode the JWT (jwt.io) and probe: <code>alg=none</code>, "
                                + "weak HMAC secret (hashcat -m 16500), <code>kid</code> path traversal / SQLi, "
                                + "missing <code>aud</code> / <code>exp</code>."),
                rule("Subdomain in cookies / JS",
                        fs -> hasCheckId(fs, "js-grep.internal-hosts")
                                || hasCheckId(fs, "leak-inspector.internal-host"),
                        "<b>Internal/staging hostnames referenced</b> — enumerate the subdomains (subfinder, "
                                + "amass) and probe each for auth gaps."),
                rule("AWS keys in JS",
                        fs -> hasCheckId(fs, "js-grep.secret") && evidenceContains(fs, "AWS"),
                        "<b>AWS credentials in JS</b> — validate via <code>aws sts get-caller-identity</code>; "
                                + "rotate immediately. Don't dwell on the bucket — check IAM scope first."),
                rule("Form without CSRF",
                        fs -> hasCheckId(fs, "form-security.csrf-token-missing"),
                        "<b>POST form without CSRF token</b> — confirm with a cross-site exploit page; check "
                                + "whether the framework auto-validates SameSite cookies before declaring it "
                                + "exploitable."),
                rule("Open-redirect parameter",
                        fs -> hasCheckId(fs, "open-redirect.candidate"),
                        "<b>Open-redirect candidate parameter</b> — fuzz with attacker-controlled hosts "
                                + "(<code>//evil.com</code>, <code>https:evil.com</code>) and check whether "
                                + "the value lands in a <code>Location</code> header or client-side redirect."),
                rule("Missing security headers",
                        fs -> hasCheckId(fs, "headers.consolidated") || hasCheckId(fs, "csp.missing"),
                        "<b>Header hardening gaps</b> — these alone aren't usually exploitable but chain with "
                                + "any future XSS into full account takeover. Bundle them into the deliverable "
                                + "as a single 'security headers' recommendation.")
        );

        static Rule rule(String label, Predicate<List<Finding>> p, String s) { return new Rule(label, p, s); }

        static List<String> suggest(List<Finding> findings) {
            List<String> out = new ArrayList<>();
            for (Rule r : RULES) {
                try {
                    if (r.when().test(findings)) out.add(r.suggestion());
                } catch (Exception ignored) { /* defensive */ }
            }
            return out;
        }

        static boolean hasCheckId(List<Finding> fs, String prefix) {
            return fs.stream().anyMatch(f -> f.checkId().startsWith(prefix));
        }

        static boolean evidenceContains(List<Finding> fs, String needle) {
            String lower = needle.toLowerCase();
            return fs.stream().anyMatch(f -> {
                String e = f.evidence();
                String t = f.title();
                return (e != null && e.toLowerCase().contains(lower))
                        || (t != null && t.toLowerCase().contains(lower));
            });
        }

        static boolean stackContains(List<Finding> fs, String needle) {
            return collectStackHints(fs).stream().anyMatch(s -> s.toLowerCase().contains(needle.toLowerCase()));
        }
    }
}
