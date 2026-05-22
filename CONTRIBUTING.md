# Contributing

Thanks for thinking about contributing. The codebase is small and opinionated; this guide should get you to a useful PR quickly.

## What to contribute

Most contributions land in one of three places:

- **New checks** — additional reconnaissance probes (passive or active) under `src/main/java/com/analyzer/checks/`.
- **New report formats** — alternative output (JSON, Markdown, SARIF) in `src/main/java/com/analyzer/report/`.
- **UI improvements** — tab refinements, filters, search, exporters in `src/main/java/com/analyzer/ui/`.

For bigger architectural changes (new tracking surfaces, new APIs, etc.), open an issue first to align on the approach.

## Setting up

```sh
git clone https://github.com/<your-fork>/analyze-target-burp-plugin.git
cd analyze-target-burp-plugin
gradle shadowJar          # build/libs/analyze-target-<version>.jar
```

Requirements:
- JDK 17 (Gradle will auto-download via the foojay toolchain resolver if you don't have it).
- Burp Suite Community or Pro for manual testing — load the JAR via Extensions → Add → Java.

## Adding a check — the 60-second version

1. Create a class under `checks/passive/`, `checks/active/`, or `checks/tls/` that implements `Check`.
2. Implement `id()`, `category()`, `isActive()`, and `run(AnalysisContext)`.
3. Use `ctx.sendRequest(req)` (not `ctx.api().http().sendRequest`) so the HTTP traffic tab captures your requests.
4. Return `List<Finding>` — use `Finding.builder()` to construct them.
5. Append `new YourCheck()` to `AnalysisEngine.defaultChecks()`.

```java
public class MyCheck implements Check {
    @Override public String id() { return "my-check"; }
    @Override public String category() { return "My category"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return List.of();
        // ... logic ...
        return List.of(Finding.builder()
                .checkId(id() + ".sub-id")
                .title("Short, scanable title")
                .severity(Severity.LOW)
                .confidence(Confidence.FIRM)
                .url(ctx.targetUrl())
                .description("What this means and why it matters.")
                .remediation("How to fix it in concrete terms.")
                .evidence("Truncated proof.")
                .references(List.of("https://owasp.org/..."))
                .requestSnippet(HttpUtil.requestSnippet(ctx.seedRequest()))
                .responseSnippet(HttpUtil.responseSnippet(resp, 0))
                .build());
    }
}
```

## Conventions

- **Java 17 only.** Use records, switch expressions, text blocks, pattern matching freely.
- **Severities** — use `INFO` for fingerprinting / discovery, `LOW` for hardening gaps with no direct exploit, `MEDIUM` for real misconfigurations, `HIGH` for verified exposure, `CRITICAL` for active exploitation paths.
- **Confidence** — `CERTAIN` only when a regex / status check unambiguously says yes. Use `FIRM` for high-confidence signals, `TENTATIVE` when manual verification is needed.
- **No network outside `ctx.sendRequest`** — every HTTP request must flow through it so the traffic tab captures it. The one exception is `TlsCheck`, which connects directly to host:443 because it needs raw `SSLSocket` access.
- **Cap body scans.** Anything that runs regex over response bodies must cap at 1 MiB. See `HtmlCommentsCheck` for the pattern.
- **Honour `Redaction`.** When building snippets, use `HttpUtil.requestSnippet` / `responseSnippet` — they already redact auth headers when the toggle is on.

## Style

- Imports sorted, no wildcard imports.
- Public APIs documented; package-private helpers explained inline where non-obvious.
- Tests not yet enforced — small PRs may skip them; substantial logic should have at least a sanity test.

## Pull request flow

1. Fork → branch off `main`.
2. One logical change per PR. Small is good.
3. Open the PR with: what changed, why, manual test steps (which target you hit, what findings appeared).
4. CI must be green (`gradle shadowJar` builds without warnings).
5. A reviewer will look within a few days. Be patient with rebases.

## Issue templates

When opening an issue:

- **Bug:** what you did, what happened, what you expected, Burp version, Java version, plugin version.
- **New check:** the WSTG section it covers (if any), the trigger condition, an example evidence string, suggested severity.
- **UI/UX:** describe the friction, ideally with a screenshot.

## Code of conduct

Be civil. Disagree on the technical merits. Assume good faith.

## License

By contributing, you agree your contributions are licensed under the MIT License — see `LICENSE`.
