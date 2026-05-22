# Analyze Target

Hello — and if you're reading this, thanks for taking a look. Pull requests, issues, ideas, and "this thing is busted on my target" reports are all welcome. This is a small project that I'd love to grow into something the wider pentest community finds useful, so jump in.

The goal is simple and hasn't changed: **automate the checks every web pentest and bug-hunting engagement has to do anyway**, the ones that don't depend on knowing anything specific about the application — missing security headers, weak cookie flags, host-header injection, CORS misconfigurations, exposed `.git` and `.env` files, TLS oddities, JavaScript that leaks secrets, and so on. The boring-but-mandatory layer. Get that out of the way in 30 seconds, then spend your time on the interesting stuff that actually requires brain.

It's a Burp Suite extension, written in Java 17 against Burp's modern Montoya API, aligned with the OWASP Web Security Testing Guide.

## How it works

You point it at one HTTP request. Right-click any request in Proxy, Repeater, or Target → Extensions → **Send to Analyze Target**. The plugin loads that request into its own tab; nothing runs yet. You review it (and edit it if you like — change a header, swap a parameter), then click **Run analysis**.

Behind the scenes, an engine fans out a dozen-ish checks in parallel. Each check is a small Java class that either reads the seed response (passive) or sends some additional crafted requests (active). Findings stream into the **Findings** tab as they appear — severity-coloured, sortable, click any row for the full description, remediation, evidence, and the underlying request/response in Burp's native editor. Every request the plugin itself sends shows up live in the **HTTP traffic** tab so you can see exactly what's going out.

When you're done, **Export HTML report…** dumps a single self-contained file you can send to a client. There's a redaction toggle on by default that scrubs `Authorization`, `Cookie`, `Set-Cookie`, and `X-Api-Key` headers from the report so authenticated-session findings don't leak credentials.

That's pretty much it.

## Build

You'll need Java 17. The Gradle setup uses the foojay toolchain resolver, so if you don't have a JDK 17 already, Gradle will fetch one on first build.

```sh
gradle shadowJar
```

The loadable JAR ends up in `build/libs/analyze-target-0.3.0.jar`.

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

The interesting folder for contributors is `checks/`. Each check is one Java file implementing the `Check` interface — `id()`, `category()`, `isActive()`, `run(ctx)`. Adding a new one is a single class plus a single line in `AnalysisEngine.defaultChecks()`. See `CONTRIBUTING.md` for the details.

## What's currently checked

Without going through the long list (browse `checks/` for the full set), the categories are:

- Security headers — CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP
- Cookie attributes — Secure, HttpOnly, SameSite, `__Host-`/`__Secure-` prefix invariants
- Technology fingerprinting — server/framework/CDN/WAF identification from headers, cookies, and HTML
- Information disclosure — Server/X-Powered-By, verbose errors, source maps in production JS
- HTML/JS comments leaking TODO/FIXME/credentials/internal hostnames
- Form security — login forms posting over HTTP, missing CSRF tokens, autocomplete hygiene
- robots.txt + sitemap.xml inventory
- JavaScript grep — fetches linked scripts, hunts for API keys, JWTs, internal endpoints
- Host header attacks — injection, X-Forwarded-Host, reflection checks
- CORS misconfigurations — reflective Origin, null, subdomain bypass tricks
- HTTP methods — OPTIONS, TRACE, X-HTTP-Method-Override smuggling
- Sensitive paths — ~30 curated probes (.git, .env, .DS_Store, web.config, Spring Actuator, Tomcat Manager, backup archives, etc.)
- TLS — protocol versions, weak suites, cert validity/SAN match

If there's a category you'd add, open an issue or send a PR — the bar to entry is low.

## A few things to know

**Traffic volume.** A full run is around 40 requests. There's a "Passive only" checkbox on the Target tab that skips everything noisy if you want to run against production without an engagement scope.

**False positives happen.** The JavaScript secret-grep is intentionally generous to catch real things — verify each hit before it goes in a deliverable.

**TLS thoroughness.** The TLS probe uses the local JDK's TLS stack, so protocols your JVM has disabled (often SSLv3 / TLS 1.0) won't be reported even if the server supports them. Run `testssl.sh` alongside if you need cipher-level coverage.

**Burp scope.** The plugin currently doesn't consult Burp's scope rules — when you click Run, it goes after whatever you loaded. Adding scope-respect for active probes is on the roadmap; PR welcome.

## Roadmap

Rough ideas, in no particular order:

- Per-check enable/disable in a settings panel (persisted across restarts)
- JSON / SARIF / Markdown report formats alongside HTTP
- Diff mode for re-analysis — show new vs resolved findings between runs
- JWT analysis when `Authorization: Bearer` is present (alg none, weak HMAC, kid injection)
- GraphQL-specific checks (introspection, depth limits, batched query bypass)
- Burp Collaborator integration for blind SSRF / out-of-band probes
- Authenticated vs unauthenticated differential — same probes both ways, flag the diff

If any of these speak to you, the contribution path is open.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: fork, branch, add a check or fix a bug, open a PR. Manual testing instructions are in the PR template. There's a CI workflow that builds the JAR on every push and attaches it to GitHub releases — see [GIT_SETUP.md](GIT_SETUP.md) for the publishing flow.

If you've never built a Burp extension before but want to learn, this is a friendly first project. The Check interface is three methods, and there are plenty of existing examples to copy.

## License

[MIT](LICENSE) — build, fork, ship, sell, whatever. No warranty, no obligation. If it saves you an hour on an engagement, that's enough.

Thanks for stopping by.
