# Analyze Target

Hello - and if you're reading this, thanks for taking a look. Pull requests, issues, ideas, and "this thing is busted on my target" reports are all welcome. This is a small project that I'd love to grow into something the wider pentest community finds useful, so jump in.

The goal is simple and hasn't changed: **automate the checks every web pentest and bug-hunting engagement has to do anyway**, the ones that don't depend on knowing anything specific about the application - missing security headers, weak cookie flags, host-header injection, CORS misconfigurations, exposed `.git` and `.env` files, TLS oddities, JavaScript that leaks secrets, and so on. The boring-but-mandatory layer. Get that out of the way in 30 seconds, then spend your time on the interesting stuff that actually requires brain.

It's a Burp Suite extension, written in Java 17 against Burp's modern Montoya API, aligned with the OWASP Web Security Testing Guide.

## How it works

You point it at one HTTP request. Right-click any request in Proxy, Repeater, or Target → Extensions → **Send to Analyze Target**. The plugin loads that request into its own tab; nothing runs yet. You review it (and edit it if you like - change a header, swap a parameter), then click **Run analysis**.

Behind the scenes, an engine fans out a dozen-plus checks in parallel. Each check is a small Java class that either reads the seed response (passive) or sends some additional crafted requests (active). A progress bar shows how many checks have finished, and findings stream into the **Findings** tab as they appear - severity-coloured (green INFO, yellow LOW, orange MEDIUM, red HIGH, dark-red CRITICAL), sortable, click any row for the full description, remediation, evidence, and the underlying request/response in Burp's native editor. The **Summary** tab synthesises everything into a quick narrative — what the target is, what was found, what the stack probably is, the highest-impact issues, and rule-based follow-up suggestions ("WordPress detected → wpscan", "Spring Actuator exposed → try /actuator/env", "Bearer token present → JWT alg=none and weak HMAC checks", etc.). Every request the plugin itself sends shows up live in the **HTTP traffic** tab so you can see exactly what's going out.

State persists with the Burp project — close Burp and re-open a saved project file, and the loaded target plus the findings from your last run are still there. Useful for multi-day engagements where you'd otherwise have to re-run from scratch. (The HTTP traffic log is intentionally ephemeral — it can be large and only really matters within a single run.)

Active probes that need a canary host or path use a self-explanatory name (`surethisdoesnotexist.xyz` for Host / Origin reflection, `/surethisdoesnotexist-<random>` for forced 404s). If a defender sees one in their logs, the intent is obvious — these are fingerprint probes, not live attack attempts.

Want to stay quiet? Tick **Passive only** on the Target tab before running. It runs just the read-only checks and sends no extra traffic at all - no active probes, no TLS connect, no follow-up fetches - so it's safe to point at production without an engagement scope.

When you're done, **Export HTML report...** dumps a single self-contained file you can send to a client. There's a redaction toggle on by default that scrubs `Authorization`, `Cookie`, `Set-Cookie`, and `X-Api-Key` headers from the report so authenticated-session findings don't leak credentials.

That's pretty much it.

## Build

You'll need Java 17. The Gradle setup uses the foojay toolchain resolver, so if you don't have a JDK 17 already, Gradle will fetch one on first build.

```sh
gradle shadowJar
```

The loadable JAR ends up in `build/libs/analyze-target-0.6.0.jar`.

Load it in Burp via **Extensions → Installed → Add → Java**, point at the JAR, click Next. You'll see `[analyze-target] ready` in the Output log if it loaded cleanly.

## Project structure

```
analyze-target-burp-plugin/
├── build.gradle / settings.gradle / gradle.properties
├── README.md            ← you are here
├── GIT_SETUP.md         ← pushing to GitHub & collaborating
├── CONTRIBUTING.md      ← how to add a new check
├── LICENSE              ← MIT
├── .github/             ← CI workflow, issue + PR templates
└── src/main/java/com/analyzer/
    ├── AnalyzeTargetExtension     ← entry point
    ├── AnalyzeContextMenuProvider ← right-click action
    ├── engine/                    ← AnalysisEngine, AnalysisContext
    ├── checks/
    │   ├── passive/    ← read the response, no extra traffic
    │   ├── active/     ← send crafted variants
    │   └── tls/        ← TLS protocol/cert probe
    ├── model/          ← Finding, Severity, Confidence
    ├── traffic/        ← HTTP traffic log
    ├── ui/             ← Tabs, palette, table models, detail pane
    └── report/         ← HTML report writer
```

The interesting folder for contributors is `checks/`. Each check is one Java file implementing the `Check` interface - `id()`, `category()`, `isActive()`, `run(ctx)`. Adding a new one is a single class plus a single line in `AnalysisEngine.defaultChecks()`. See `CONTRIBUTING.md` for the details.

## What's currently checked

Without going through the long list (browse `checks/` for the full set), the categories are:

- CSP — standalone finding for missing or weak Content-Security-Policy (descriptions aligned with the OWASP CSP Cheat Sheet)
- HSTS — standalone finding for missing or weak Strict-Transport-Security
- Other security headers — ONE consolidated finding listing all gaps among X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP (aggregated to keep the table readable)
- Cookie attributes — Secure, HttpOnly, SameSite, `__Host-`/`__Secure-` prefix invariants
- Technology fingerprinting — server/framework/CDN/WAF/cloud identification from headers, cookies, and HTML, including the full OWASP WSTG INFO-08 catalogue (Zope, CakePHP, Kohana, phpBB, BITRIX, Django CMS, DotNetNuke, e107, EPiServer, TYPO3, MODx, LEPTON, Wix, VIVVO, Zenphoto, Indico, Kentico, Dynamicweb, ImpressCMS, Hotaru, Graffiti, InstantCMS, AMPcms, etc.), specific framework markers (ColdFusion headerTags, ASP.NET __VIEWSTATE, ZK, Business Catalyst, Indexhibit, phpBB body id, DNN Platform), plus client-library version extraction (jQuery, Bootstrap, Angular, …)
- Index / default page enumeration — probes `/index.{html,php,jsp,do,action,aspx,asp,cfm,cgi,pl,py,rb}`, `Default.aspx`, `Main.aspx`, `home.*` variants; each hit doubles as a stack hint
- Error page fingerprinting — forces a 404 on a random path, then matches the response against a catalogue from 0xdf's 404 cheatsheet (Apache, nginx, IIS, Tomcat, Jetty, Express, Django, Flask, Rails, Spring Boot Whitelabel, Laravel Whoops, Symfony, PHP, S3, API Gateway, Cloudflare edge, etc.)
- Information disclosure — Server/X-Powered-By, verbose errors, source maps in production JS
- HTML/JS comments leaking TODO/FIXME/credentials/internal hostnames
- Form security — login forms posting over HTTP, missing CSRF tokens, autocomplete hygiene
- Sensitive-content caching — authenticated/personalised responses missing `Cache-Control: no-store`
- robots.txt + sitemap.xml inventory
- JavaScript grep — fetches linked scripts, hunts for API keys, JWTs, internal endpoints
- Host header attacks — injection, X-Forwarded-Host, reflection checks
- CORS misconfigurations — reflective Origin, null, subdomain bypass tricks
- HTTP methods — full verb enumeration (HEAD/POST/PUT/DELETE/PATCH/CONNECT plus an unknown method), OPTIONS allow-list, TRACE / Cross-Site-Tracing, X-HTTP-Method-Override smuggling
- Cross-domain policy — crossdomain.xml / clientaccesspolicy.xml permissiveness
- Sensitive paths — ~30 curated probes (.git, .env, .DS_Store, web.config, Spring Actuator, Tomcat Manager, backup archives, etc.)
- Backup / leftover files — editor backups (`*.bak`, `*~`, `*.old`, `*.swp`), VCS metadata directories (`.svn/`, `.hg/`, `.bzr/`, `CVS/`), OS cruft (`.DS_Store`, `Thumbs.db`), DB dumps (`dump.sql`, `backup.sql`), framework configs (`wp-config.php.bak`, `local_settings.py`), and the worst-case `.ssh/id_rsa`
- Admin interfaces — `/admin`, `/wp-admin`, `/administrator`, `/phpmyadmin`, `/adminer`, `/manager/html`, `/jenkins`, `/actuator/*`, `/trace.axd`, `/elmah.axd`, `/server-status`, `/sidekiq`, `/rails/info/routes`, and the rest of the WSTG-CONF-05 catalogue
- API surface discovery — `/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/swagger-ui*`, `/graphql`, `/graphiql`, `/playground`, ReDoc, Postman/RAML descriptors (feeds Summary suggestions for OpenAPI / GraphQL targets)
- Well-known descriptors — `/.well-known/security.txt`, OpenID Connect discovery, OAuth 2.0 AS metadata, JWKS, assetlinks.json, apple-app-site-association, host-meta, webfinger, etc.
- Link & path inventory — crawls the HTML for `href`/`src`/`action`/`data-*`, recursively fetches each referenced JS file, and inventories every same-origin path it sees (aligned with WSTG-INFO-04 and WSTG-INFO-07). Third-party hosts get bucketed separately as a CSP signal
- Mixed content — HTTPS pages referencing plaintext `http://` resources (WSTG-CRYP-03)
- Subresource Integrity — cross-origin `<script>` / `<link rel="stylesheet">` without `integrity=`
- Open-redirect parameter candidates — passive flag of parameter / form-input names that match common redirect conventions (`return`, `redirect_uri`, `next`, `url`, `dest`, …) — WSTG-CLNT-04
- Information leak grep — emails, RFC 1918 IPs, and internal/staging hostnames in the response body
- JWT / tokens — decodes JSON Web Tokens already present in the exchange (Bearer header, request `Cookie`, response `Set-Cookie`) and flags `alg=none`, HMAC signing, missing/expired `exp`, and sensitive claims exposed in the (readable) payload — WSTG-SESS-10
- Input reflection — request parameter values echoed verbatim in the response body, flagged as reflected-XSS / HTML-injection leads (passive; confirm context manually) — WSTG-INPV-01
- Insecure deserialization markers — Java serialized streams (`rO0AB…` / raw `0xACED`), ASP.NET `__VIEWSTATE`, and PHP serialized data in cookies, parameters, or the body — WSTG-INPV-13
- CORS (passive) — reads `Access-Control-Allow-Origin` / `-Allow-Credentials` on the seed response and flags wildcard-with-credentials, `null`, and origin-reflection (complements the active CORS probe)
- Cookie scope — overly broad `Domain` (shared across all subdomains) and session identifiers carried in the URL (session fixation / Referer leakage), complementing the cookie-flags check
- Content-Type hygiene — missing Content-Type on a body, text responses with no charset (UTF-7 XSS class), and HTML-looking bodies served under a non-HTML type without `nosniff`
- HTTPS redirect (active) — one request to the plaintext `http://` origin to confirm it force-redirects to HTTPS, and notes a redirect that ships no HSTS
- Directory listing (active) — probes the seed resource's directory for an auto-generated index (Apache/nginx/IIS/Python) — WSTG-CONF-03 / forced browsing
- TLS — protocol versions, weak suites, cert validity/SAN match

If there's a category you'd add, open an issue or send a PR - the bar to entry is low.

## A few things to know

**Traffic volume.** A full run is roughly 50 requests. Checks share a per-run response cache, so resources referenced by more than one check (e.g. the same linked JavaScript pulled by both the JS-grep and link-extraction crawlers) are fetched only once — fewer requests, faster runs, and a quieter footprint. The **Passive only** checkbox on the Target tab skips everything noisy if you want to run against production without an engagement scope.

**Active probes use a neutral canary.** The host-header and CORS probes inject `pentesting.test` - a reserved-TLD name (RFC 6761) that can never resolve to a real host. It reads clearly in logs and is less likely to trip aggressive WAFs than an obviously hostile value, while still being unmistakably not the target.

**False positives happen.** The JavaScript secret-grep is intentionally generous to catch real things - verify each hit before it goes in a deliverable. The same applies to the dangerous-HTTP-method finding: confirm a write verb actually does something before you report it.

**TLS thoroughness.** The TLS probe uses the local JDK's TLS stack, so protocols your JVM has disabled (often SSLv3 / TLS 1.0) won't be reported even if the server supports them. Run `testssl.sh` alongside if you need cipher-level coverage.

**Burp scope.** The plugin currently doesn't consult Burp's scope rules - when you click Run, it goes after whatever you loaded. Adding scope-respect for active probes is on the roadmap; PR welcome. Until then, **Passive only** is the safe default for unscoped targets.

## Roadmap

Rough ideas, in no particular order:

- Per-check enable/disable in a settings panel (persisted across restarts)
- Burp scope integration for active probes
- JSON / SARIF / Markdown report formats alongside HTML
- Diff mode for re-analysis - show new vs resolved findings between runs
- JWT analysis — passive decoding (alg=none, weak HMAC, missing exp, sensitive claims) now shipped; still want active `kid` injection and alg-confusion confirmation
- GraphQL-specific checks (introspection, depth limits, batched query bypass)
- Burp Collaborator integration for blind SSRF / out-of-band probes
- Authenticated vs unauthenticated differential - same probes both ways, flag the diff

If any of these speak to you, the contribution path is open.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: fork, branch, add a check or fix a bug, open a PR. Manual testing instructions are in the PR template. There's a CI workflow that builds the JAR on every push and attaches it to GitHub releases - see [GIT_SETUP.md](GIT_SETUP.md) for the publishing flow.

If you've never built a Burp extension before but want to learn, this is a friendly first project. The Check interface is three methods, and there are plenty of existing examples to copy.

## License

[MIT](LICENSE) - build, fork, ship, sell, whatever. No warranty, no obligation. If it saves you an hour on an engagement, that's enough.

Thanks for stopping by.
