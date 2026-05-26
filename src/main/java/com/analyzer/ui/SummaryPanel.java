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
 * Read-only narrative summary of an analysis run. Updated after each run completes (and again
 * on load when state is restored). Synthesises the findings list + the loaded target into:
 *   • the target's method + URL,
 *   • severity counts,
 *   • the probable tech stack (compiled from tech-fingerprint, index-probe, error-fingerprint),
 *   • the highest-severity findings,
 *   • suggested follow-ups (rule-based — match check ids / finding titles → next-step hints).
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
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JLabel title = new JLabel("Target analysis");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        title.setForeground(palette.accent);
        title.setBorder(BorderFactory.createEmptyBorder(0, 4, 8, 0));
        add(title, BorderLayout.NORTH);

        content.setContentType("text/html");
        content.setEditable(false);
        content.setBackground(palette.panelBackground);
        content.setForeground(palette.foreground);
        content.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
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
        scroll.setBorder(BorderFactory.createLineBorder(palette.border));
        add(scroll, BorderLayout.CENTER);

        clear();
    }

    /** Render the empty-state when no analysis has run yet. */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            content.setText(html(
                    "<p class='muted'>No analysis run yet. Send a request to the Target tab and click <b>Run analysis</b> — "
                            + "a synthesis of the findings will appear here.</p>"));
            content.setCaretPosition(0);
        });
    }

    /** Build and render the summary for the latest analysis run. Safe to call from any thread. */
    public void updateSummary(HttpRequest target, List<Finding> findings) {
        SwingUtilities.invokeLater(() -> {
            StringBuilder body = new StringBuilder(8192);

            // Target
            body.append("<h3>Target</h3>");
            if (target != null) {
                body.append("<p><b>").append(esc(target.method())).append("</b> ")
                    .append("<code>").append(esc(target.url())).append("</code></p>");
            } else {
                body.append("<p class='muted'>(no target — restore state failed?)</p>");
            }

            // Severity counts
            EnumMap<Severity, Integer> counts = new EnumMap<>(Severity.class);
            for (Severity s : Severity.values()) counts.put(s, 0);
            for (Finding f : findings) counts.merge(f.severity(), 1, Integer::sum);
            body.append("<h3>Findings — ").append(findings.size()).append(" total</h3>");
            body.append("<p>");
            for (Severity s : Severity.values()) {
                String hex = toHex(palette.severityBg(s.label()));
                String fg = toHex(palette.severityFg(s.label()));
                body.append("<span style='background:").append(hex).append(";color:").append(fg)
                    .append(";padding:2px 8px;border-radius:10px;margin-right:6px;font-weight:600;'>")
                    .append(s.label()).append(": ").append(counts.get(s)).append("</span>");
            }
            body.append("</p>");

            // Probable stack
            Set<String> stackHints = collectStackHints(findings);
            body.append("<h3>Probable stack</h3>");
            if (stackHints.isEmpty()) {
                body.append("<p class='muted'>No stack-fingerprint hits in this run.</p>");
            } else {
                body.append("<ul>");
                for (String hint : stackHints) {
                    body.append("<li>").append(esc(hint)).append("</li>");
                }
                body.append("</ul>");
            }

            // Top findings (up to 7 highest severity)
            body.append("<h3>Highest-impact findings</h3>");
            List<Finding> top = findings.stream()
                    .sorted(Comparator.comparingInt((Finding f) -> f.severity().ordinal())
                            .thenComparing(Finding::title))
                    .limit(7)
                    .toList();
            if (top.isEmpty()) {
                body.append("<p class='muted'>(none)</p>");
            } else {
                body.append("<ol>");
                for (Finding f : top) {
                    String hex = toHex(palette.severityBg(f.severity().label()));
                    String fg  = toHex(palette.severityFg(f.severity().label()));
                    body.append("<li><span style='background:").append(hex)
                        .append(";color:").append(fg)
                        .append(";padding:1px 6px;border-radius:8px;font-weight:600;font-size:10px;margin-right:6px;'>")
                        .append(f.severity().label())
                        .append("</span> ").append(esc(f.title()))
                        .append("  <span class='muted'>(").append(esc(f.checkId())).append(")</span></li>");
                }
                body.append("</ol>");
            }

            // Suggested follow-ups
            List<String> suggestions = SuggestionRules.suggest(findings);
            body.append("<h3>Suggested follow-ups</h3>");
            if (suggestions.isEmpty()) {
                body.append("<p class='muted'>No rule-based suggestions for this run.</p>");
            } else {
                body.append("<ul>");
                for (String s : suggestions) body.append("<li>").append(s).append("</li>");
                body.append("</ul>");
            }

            // Footer note
            body.append("<p class='muted' style='font-size:11px;margin-top:24px'>")
                .append("This summary is synthesised by a small rule engine over the findings list — it doesn't see ")
                .append("anything you don't. Treat suggestions as ideas, not gospel.")
                .append("</p>");

            content.setText(html(body.toString()));
            content.setCaretPosition(0);
        });
    }

    private String html(String inner) {
        String fg  = toHex(palette.foreground);
        String bg  = toHex(palette.panelBackground);
        String mut = toHex(palette.mutedForeground);
        String acc = toHex(palette.accent);
        return "<html><head><style>"
                + "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;color:" + fg + ";background:" + bg + ";}"
                + "h3{color:" + acc + ";margin-top:18px;margin-bottom:6px;font-size:13px;text-transform:uppercase;letter-spacing:0.5px;}"
                + "a{color:" + acc + ";}"
                + "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:rgba(127,127,127,0.15);padding:1px 4px;border-radius:3px;}"
                + ".muted{color:" + mut + ";}"
                + "ul,ol{margin-top:4px;margin-bottom:8px;}"
                + "li{margin:3px 0;}"
                + "</style></head><body>" + inner + "</body></html>";
    }

    // ---- Stack synthesis ----

    /**
     * Collect human-readable stack hints from the findings whose evidence/title carries fingerprint info.
     * Source checks: tech-fingerprint.summary, index-probe.hits, error-fingerprint.match.
     */
    private static Set<String> collectStackHints(List<Finding> findings) {
        Set<String> hints = new LinkedHashSet<>();
        for (Finding f : findings) {
            String id = f.checkId();
            if (id.startsWith("tech-fingerprint")) {
                // Evidence is "label\nlabel\n…"
                for (String line : f.evidence().split("\\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) hints.add(trimmed);
                }
            } else if (id.startsWith("index-probe")) {
                hints.add("Filesystem hints: " + f.title().replace("Index / default page enumeration revealed ", ""));
            } else if (id.startsWith("error-fingerprint.match")) {
                // Title format: "Error page reveals stack: nginx, Spring Boot Whitelabel"
                int colon = f.title().indexOf(':');
                if (colon > 0) {
                    hints.add("Error-page fingerprint: " + f.title().substring(colon + 1).trim());
                }
            }
        }
        return hints;
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
    // Rule-based suggestion engine. Each rule is a (predicate, suggestion) pair. Suggestions are
    // emitted only when the predicate matches the current findings set. Add freely — order matters
    // for display but otherwise rules are independent.
    // ============================================================================================
    private static final class SuggestionRules {
        private record Rule(String label, Predicate<List<Finding>> when, String suggestion) {}

        private static final List<Rule> RULES = List.of(
                rule(".git exposed",
                        fs -> hasCheckId(fs, "sensitive-paths.hit") && evidenceContains(fs, "/.git/"),
                        "<b>Exposed .git/</b> — clone history with <code>git-dumper</code> or "
                                + "<a href='https://github.com/internetwache/GitTools'>GitTools/Dumper</a> to recover source code, commit messages, and pre-commit secrets."),
                rule(".env exposed",
                        fs -> hasCheckId(fs, "sensitive-paths.hit") && evidenceContains(fs, "/.env"),
                        "<b>Exposed .env</b> — read it for API keys, DB credentials, and JWT signing secrets. Rotate every secret it contains immediately if confirmed."),
                rule("Spring Boot Actuator",
                        fs -> evidenceContains(fs, "/actuator"),
                        "<b>Spring Boot Actuator</b> — try <code>/actuator/env</code>, <code>/actuator/heapdump</code>, "
                                + "<code>/actuator/loggers</code>, <code>/actuator/mappings</code>. The heap dump often contains live credentials and session tokens."),
                rule("Backup archive",
                        fs -> hasCheckId(fs, "sensitive-paths.hit") && (evidenceContains(fs, "backup.zip") || evidenceContains(fs, "backup.tar")),
                        "<b>Backup archive exposed</b> — download and inspect for source code, database dumps, and credentials."),
                rule("WordPress",
                        fs -> stackContains(fs, "WordPress") || stackContains(fs, "wp-content") || stackContains(fs, "wp-login"),
                        "<b>WordPress detected</b> — run <code>wpscan --url &lt;target&gt; --enumerate vp,vt,u</code> for vulnerable plugins, themes, and user enumeration."),
                rule("Drupal",
                        fs -> stackContains(fs, "Drupal"),
                        "<b>Drupal detected</b> — run <code>droopescan scan drupal -u &lt;target&gt;</code> and check for known SA-CORE advisories matching the version."),
                rule("Joomla",
                        fs -> stackContains(fs, "Joomla"),
                        "<b>Joomla detected</b> — try <code>joomscan -u &lt;target&gt;</code>; check for /administrator and known extension CVEs."),
                rule("Tomcat Manager",
                        fs -> evidenceContains(fs, "Tomcat") && evidenceContains(fs, "/manager"),
                        "<b>Tomcat Manager exposed</b> — try default credentials (<code>tomcat:tomcat</code>, <code>admin:admin</code>); a successful login allows WAR deployment for RCE."),
                rule("Jenkins login",
                        fs -> evidenceContains(fs, "Jenkins"),
                        "<b>Jenkins login page exposed</b> — try <code>/script</code> (Groovy console — RCE if reachable unauthenticated) and check for CVE-2024-23897 (file read)."),
                rule("PHP backend",
                        fs -> stackContains(fs, "PHP") || stackContains(fs, "phpsessid") || stackContains(fs, "/index.php"),
                        "<b>PHP backend</b> — probe <code>/phpinfo.php</code>, <code>/info.php</code>, common admin paths (<code>/phpmyadmin</code>, <code>/adminer</code>, <code>/wp-admin</code>)."),
                rule("ASP.NET",
                        fs -> stackContains(fs, "ASP.NET") || stackContains(fs, "__VIEWSTATE"),
                        "<b>ASP.NET detected</b> — check <code>__VIEWSTATE</code> integrity (CVE-2017-9248 / unkeyed ViewState → RCE via ysoserial.net); look for <code>/trace.axd</code>, <code>/elmah.axd</code>."),
                rule("CORS reflective",
                        fs -> hasCheckId(fs, "cors.reflection"),
                        "<b>CORS Origin reflection</b> — test with a real attacker-controlled origin to confirm; if credentials flow, you have authenticated cross-origin read."),
                rule("Host header reflected",
                        fs -> hasCheckId(fs, "host-header.reflection"),
                        "<b>Host header reflected</b> — test password-reset endpoints next: a poisoned Host header in a password-reset email is a classic account-takeover primitive."),
                rule("HTTP methods PUT/DELETE/TRACE",
                        fs -> evidenceContains(fs, "PUT") && hasCheckId(fs, "http-methods"),
                        "<b>Risky HTTP methods enabled</b> — verify PUT actually writes (try uploading a small <code>.html</code>) and DELETE actually removes (against a benign resource you can recreate)."),
                rule("Authorization header present",
                        fs -> evidenceContains(fs, "Authorization: Bearer") || evidenceContains(fs, "Authorization: bearer"),
                        "<b>Bearer token present</b> — decode the JWT (jwt.io) and probe: <code>alg=none</code>, weak HMAC secret (hashcat -m 16500), <code>kid</code> path traversal / SQLi, missing <code>aud</code> / <code>exp</code>."),
                rule("Subdomain in cookies / JS",
                        fs -> hasCheckId(fs, "js-grep.internal-hosts"),
                        "<b>Internal/staging hostnames referenced</b> — enumerate the subdomains (subfinder, amass) and probe each for auth gaps."),
                rule("AWS keys in JS",
                        fs -> hasCheckId(fs, "js-grep.secret") && evidenceContains(fs, "AWS"),
                        "<b>AWS credentials in JS</b> — validate via <code>aws sts get-caller-identity</code>; rotate immediately. Don't dwell on the bucket — check IAM scope first."),
                rule("Form without CSRF",
                        fs -> hasCheckId(fs, "form-security.csrf-token-missing"),
                        "<b>POST form without CSRF token</b> — confirm with a cross-site exploit page; check whether the framework auto-validates SameSite cookies before declaring it exploitable."),
                rule("Missing security headers",
                        fs -> hasCheckId(fs, "headers.consolidated") || hasCheckId(fs, "csp.missing"),
                        "<b>Header hardening gaps</b> — these alone aren't usually exploitable but chain with any future XSS into full account takeover. Bundle them into the deliverable as a single 'security headers' recommendation.")
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
