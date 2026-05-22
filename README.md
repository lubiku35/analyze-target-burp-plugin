# Analyze Target - Burp Suite extension

A right-click "Analyze Target" action for Burp that runs a battery of common web-pentesting recon
checks against the selected request, presents findings in a theme-aware UI, shows every HTTP
request the plugin sends in a Burp-history-style traffic tab, and exports a standalone HTML report.

Built on the modern Burp Montoya API (Java 17). Aligned with OWASP WSTG.

![tabs: Findings · HTTP traffic · About]

## Features

- **One-click recon** - right-click any request → Extensions → Analyze Target. Fans out 13 checks
  in parallel.
- **Findings tab** - sortable table, severity-coloured badges, click any row for description /
  remediation / evidence / request / response (in Burp's native editors) / references.
- **HTTP traffic tab** - every request the plugin sends shows up here in real time: time, check,
  method, URL, status, length, duration. Click for the underlying request / response in Burp's
  native editors.
- **Theme-aware UI** - detects Burp's light/dark theme and adapts colours, padding, and typography.
  No "kinda oldish" Swing default.
- **Header redaction** - toggle in the toolbar redacts `Authorization`, `Cookie`, `Set-Cookie`,
  `X-Api-Key` etc. from all finding snippets and exported reports. ON by default to make client
  deliverables safe.
- **Self-contained HTML report** - single-file output grouped by URL, ordered by severity, full
  evidence + collapsible request/response. Suitable for client deliverables.
- **Per-check timeouts** - a slow check can't stall the run (60s per check, 180s overall ceiling).

## Checks

Each check is independently selectable in code (`AnalysisEngine.defaultChecks()`).

**Passive - read the seed response, no extra traffic** (except JS grep / robots / sitemap)

| Check | What it covers | WSTG |
|---|---|---|
| `tech-fingerprint` | Server/X-Powered-By, CDN/WAF (Cloudflare, CloudFront, Fastly, Akamai, Sucuri), backend stack from cookies (PHPSESSID, JSESSIONID, Laravel, Rails, Django, …), HTML meta generator, frontend framework (React, Vue, Angular, Next, Nuxt, Svelte) | INFO-02/08/09 |
| `headers` | CSP (incl. `unsafe-inline`, wildcards, missing `frame-ancestors`/`object-src`), HSTS (max-age, includeSubDomains, preload), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP | CONF-07 |
| `cookies` | Secure, HttpOnly, SameSite, `__Host-` / `__Secure-` prefix invariants | SESS-02 |
| `info-disclosure` | Server fingerprinting headers, verbose error pages, source-map references in production JS | INFO-04 |
| `html-comments` | HTML / JS comments flagged for TODO/FIXME/password/admin/debug, internal RFC1918 IPs | INFO-05 |
| `form-security` | Login form posts password over `http://`, POST forms without obvious CSRF token, password fields without autocomplete | SESS-05 |
| `robots-sitemap` | `/robots.txt` Disallow paths + sitemap references; `/sitemap.xml` URL inventory | INFO-03 |
| `js-grep` | Scrapes every linked `<script src>`, greps for AWS/Google/GitHub/Slack/Stripe keys, JWTs, private-key blocks, bearer tokens, API endpoints, internal hostnames | INFO-05 |

**Active - sends additional traffic**

| Check | What it covers |
|---|---|
| `host-header` | Replaces Host, adds X-Forwarded-Host / X-Host / X-Forwarded-Server; checks reflection in body / Location / Set-Cookie |
| `cors` | Reflective `Origin`, `null` origin, suffix-bypass (`target.com.attacker.test`), prefix-bypass (reserved-TLD canary), wildcard + credentials |
| `http-methods` | OPTIONS allow-list, TRACE enabled, `X-HTTP-Method-Override` smuggling |
| `sensitive-paths` | ~30 curated probes: `.git/HEAD`, `.env`, `.svn/entries`, `.DS_Store`, `web.config`, `phpinfo.php`, `/server-status`, Spring Boot Actuator, Swagger/OpenAPI, Tomcat Manager, Jenkins, H2 console, Symfony profiler, backup archives, etc. Each probe requires both 200 status AND a content fingerprint to reduce false positives. |

**TLS - out-of-band probe**

| Check | What it covers |
|---|---|
| `tls` | Enumerates protocol versions supported by the server (SSLv3, TLS 1.0/1.1/1.2/1.3), flags weak ones; reads leaf certificate for validity window + hostname/SAN match. Trust-all factory is scoped per-call (does not affect Burp's HTTP stack). |

## Build

Requires Java 17. The project's Gradle build uses the foojay toolchain resolver, so Gradle will
auto-download a matching JDK if you don't have one.

```sh
gradle shadowJar
```

The loadable JAR is `build/libs/analyze-target-0.2.0.jar`.

## Load in Burp

1. Burp → Extensions → Installed → Add
2. Extension type: Java
3. Extension file: select `build/libs/analyze-target-0.2.0.jar`
4. Next - you should see `[analyze-target] ready (13 checks).` in the Output log.

## Use

1. Find a request to analyze in Proxy / Site map / Repeater.
2. Right-click → Extensions → Analyze Target.
3. Watch the **Findings** tab - entries stream in as each check finishes. Click a row to inspect.
4. Watch the **HTTP traffic** tab to see every request the plugin sent, with method, status, length,
   and duration. Click any row to see request / response in Burp's editors.
5. Toggle **Redact auth headers** in the toolbar (default ON) before exporting if the target uses
   authentication - keeps cookies / bearer tokens out of the report.
6. Click **Export HTML report…** to save a single self-contained file.

## Architecture in 30 seconds

```
AnalyzeTargetExtension  (BurpExtension entry point)
├── HttpTrafficLog       (observable list of all plugin-sent requests)
├── AnalysisEngine       (fans out Checks on a worker pool, per-check timeouts)
│   └── Check[] {        each gets a per-check AnalysisContext, calls ctx.sendRequest(req)
│       passive/*        - read seed response, optional follow-ups
│       active/*         - send crafted variants
│       tls/*            - raw SSLSocket probes
│   }
└── AnalyzerTab          (JTabbedPane: Findings / HTTP traffic / About)
    ├── Palette          (light/dark, derived from api.userInterface().currentTheme())
    ├── FindingDetailPanel    (Burp HttpRequestEditor / HttpResponseEditor)
    ├── HttpTrafficTab        (table → editor split)
    └── HtmlReportWriter      (self-contained HTML export)
```

## Repository layout

```
analyze-target-burp-plugin/
├── build.gradle / settings.gradle / gradle.properties
├── README.md            (this file)
├── GIT_SETUP.md         (how to push to GitHub + collaborate)
├── CONTRIBUTING.md      (how to add a new check)
├── LICENSE              (MIT)
├── .github/
│   ├── workflows/ci.yml         (build on push/PR, attach JAR to releases)
│   ├── ISSUE_TEMPLATE/*.md
│   └── pull_request_template.md
└── src/main/
    ├── java/com/analyzer/      (~25 files, ~3500 lines)
    └── resources/META-INF/services/burp.api.montoya.BurpExtension
```

## Caveats and trade-offs

- **Traffic volume.** A typical run is ~40 requests. Don't point it at production unless your
  engagement scope allows it. Active probes go to the same scheme/host/port as the seed request.
- **TLS thoroughness.** The TLS check uses the local JDK's TLS stack - older protocols (SSLv3,
  TLS 1.0) may be disabled at the JVM level and won't be detected even if the server supports them.
  For definitive cipher coverage, run `testssl.sh` alongside.
- **Secret-pattern false positives.** Regex hits in `js-grep` are intentionally permissive; verify
  each before including in a deliverable.
- **Burp scope.** The plugin does not currently consult Burp's scope rules - every active probe
  goes to the request you right-clicked on. This is intentional (you decided to analyze this
  request), but means active checks may hit out-of-scope third-party CDNs referenced from the seed
  response. Pull requests welcome.

## Roadmap

- Burp scope integration toggle for active probes
- JSON / SARIF report formats
- WebSocket / GraphQL specific checks (introspection, mutation auth)
- HTTP/2 specific issues (smuggling primitives)
- Per-check enable/disable in the UI

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) - adding a new check is one class + one line.

## License

[MIT](LICENSE). Build, fork, extend.
