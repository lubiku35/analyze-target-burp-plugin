package com.analyzer.checks.passive;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.analyzer.checks.Check;
import com.analyzer.checks.HttpUtil;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WSTG-INFO-02/08/09 - fingerprint web server, application platform, and frontend tech from
 * what is observable in the seed response. Always informational; helps the operator pick the
 * right next-step exploits.
 */
public class TechFingerprintCheck implements Check {
    private static final String ID = "tech-fingerprint";

    /** Header → label mapping for vendor/CDN/WAF identification. */
    private static final Map<String, String> HEADER_HINTS = new LinkedHashMap<>();
    static {
        HEADER_HINTS.put("cf-ray", "Cloudflare CDN");
        HEADER_HINTS.put("cf-cache-status", "Cloudflare CDN");
        HEADER_HINTS.put("x-amz-cf-id", "AWS CloudFront CDN");
        HEADER_HINTS.put("x-amz-cf-pop", "AWS CloudFront CDN");
        HEADER_HINTS.put("x-fastly-request-id", "Fastly CDN");
        HEADER_HINTS.put("x-served-by", "Fastly/Varnish");
        HEADER_HINTS.put("x-cache", "Varnish/CDN cache");
        HEADER_HINTS.put("x-akamai-transformed", "Akamai CDN");
        HEADER_HINTS.put("x-sucuri-id", "Sucuri WAF");
        HEADER_HINTS.put("x-sucuri-cache", "Sucuri WAF");
        HEADER_HINTS.put("x-cdn", "Generic CDN");
        HEADER_HINTS.put("via", "Proxy/CDN chain");
        HEADER_HINTS.put("x-aspnet-version", "ASP.NET");
        HEADER_HINTS.put("x-aspnetmvc-version", "ASP.NET MVC");
        HEADER_HINTS.put("x-drupal-cache", "Drupal CMS");
        HEADER_HINTS.put("x-drupal-dynamic-cache", "Drupal CMS");
        HEADER_HINTS.put("x-generator", "Generic generator hint");
        HEADER_HINTS.put("x-page-speed", "Google PageSpeed module");
        HEADER_HINTS.put("liferay-portal", "Liferay portal");
        HEADER_HINTS.put("x-shopify-stage", "Shopify");
        HEADER_HINTS.put("x-vercel-id", "Vercel");
        HEADER_HINTS.put("x-vercel-cache", "Vercel");
        HEADER_HINTS.put("server-timing", "Server-Timing diagnostics (may leak backend names)");
        // Cloud / load balancers
        HEADER_HINTS.put("x-azure-ref", "Azure Front Door / CDN");
        HEADER_HINTS.put("x-msedge-ref", "Azure CDN (Microsoft)");
        HEADER_HINTS.put("x-amz-request-id", "AWS S3 / service");
        HEADER_HINTS.put("x-amzn-requestid", "AWS API Gateway / Lambda");
        HEADER_HINTS.put("x-amzn-trace-id", "AWS ALB / X-Ray");
        HEADER_HINTS.put("x-amz-apigw-id", "AWS API Gateway");
        HEADER_HINTS.put("x-cloud-trace-context", "Google Cloud (GCP)");
        HEADER_HINTS.put("x-goog-generation", "Google Cloud Storage");
        HEADER_HINTS.put("x-nf-request-id", "Netlify");
        HEADER_HINTS.put("x-render-origin-server", "Render");
        HEADER_HINTS.put("fly-request-id", "Fly.io");
        // Proxies / gateways / WAF
        HEADER_HINTS.put("x-envoy-upstream-service-time", "Envoy proxy");
        HEADER_HINTS.put("x-kong-upstream-latency", "Kong API Gateway");
        HEADER_HINTS.put("x-kong-proxy-latency", "Kong API Gateway");
        HEADER_HINTS.put("x-varnish", "Varnish cache");
        HEADER_HINTS.put("x-proxy-cache", "Nginx proxy cache");
        HEADER_HINTS.put("x-iinfo", "Imperva Incapsula WAF");
        HEADER_HINTS.put("x-litespeed-cache", "LiteSpeed server");
        HEADER_HINTS.put("x-turbo-charged-by", "LiteSpeed server");
        // Backend / framework leaks
        HEADER_HINTS.put("x-runtime", "Rails/Rack (X-Runtime timing)");
        HEADER_HINTS.put("x-rack-cache", "Rack cache (Ruby)");
        HEADER_HINTS.put("x-redirect-by", "WordPress");
        HEADER_HINTS.put("x-pingback", "WordPress XML-RPC");
        HEADER_HINTS.put("x-jenkins", "Jenkins");
        HEADER_HINTS.put("x-b3-traceid", "Zipkin/B3 distributed tracing");
        HEADER_HINTS.put("x-github-request-id", "GitHub Pages");
        HEADER_HINTS.put("x-wix-request-id", "Wix");
    }

    /** Cookie name → backend hint. */
    private static final Map<String, String> COOKIE_HINTS = new LinkedHashMap<>();
    static {
        COOKIE_HINTS.put("phpsessid", "PHP backend");
        COOKIE_HINTS.put("jsessionid", "Java servlet container (Tomcat/Jetty/JBoss/etc.)");
        COOKIE_HINTS.put("asp.net_sessionid", "ASP.NET backend");
        COOKIE_HINTS.put("aspsessionid", "Classic ASP backend");
        COOKIE_HINTS.put("ci_session", "CodeIgniter");
        COOKIE_HINTS.put("laravel_session", "Laravel");
        COOKIE_HINTS.put("xsrf-token", "Laravel/Angular CSRF token");
        COOKIE_HINTS.put("_session_id", "Rails/Sinatra");
        COOKIE_HINTS.put("_csrf-token", "Rails CSRF token");
        COOKIE_HINTS.put("sessionid", "Django/generic");
        COOKIE_HINTS.put("csrftoken", "Django CSRF token");
        COOKIE_HINTS.put("connect.sid", "Express/Node");
        COOKIE_HINTS.put("flask-session", "Flask");
        COOKIE_HINTS.put("symfony", "Symfony");
        COOKIE_HINTS.put("cfid", "ColdFusion");
        COOKIE_HINTS.put("cftoken", "ColdFusion");
        COOKIE_HINTS.put("__cfduid", "Cloudflare (legacy)");
        COOKIE_HINTS.put("__cf_bm", "Cloudflare bot management");
        COOKIE_HINTS.put("ak_bmsc", "Akamai Bot Manager");
        COOKIE_HINTS.put("bm_sz", "Akamai Bot Manager");
        COOKIE_HINTS.put("_abck", "Akamai Bot Manager");
        COOKIE_HINTS.put("awsalb", "AWS Application Load Balancer");
        COOKIE_HINTS.put("awsalbcors", "AWS Application Load Balancer");
        COOKIE_HINTS.put("aws-waf-token", "AWS WAF");
        COOKIE_HINTS.put("arraffinity", "Azure App Service (ARR affinity)");
        COOKIE_HINTS.put("arraffinitysamesite", "Azure App Service");
        COOKIE_HINTS.put("wordpress_test_cookie", "WordPress");
    }

    /** Cookie name prefix -> backend hint (for cookies with dynamic suffixes). */
    private static final Map<String, String> COOKIE_PREFIX_HINTS = new LinkedHashMap<>();
    static {
        COOKIE_PREFIX_HINTS.put("bigipserver", "F5 BIG-IP load balancer");
        COOKIE_PREFIX_HINTS.put("incap_ses_", "Imperva Incapsula WAF");
        COOKIE_PREFIX_HINTS.put("visid_incap_", "Imperva Incapsula WAF");
        COOKIE_PREFIX_HINTS.put("wp-settings-", "WordPress");
        COOKIE_PREFIX_HINTS.put("wordpress_logged_in_", "WordPress (authenticated session)");
    }

    /** HTML pattern → label. Patterns are checked against the first ~32 KB of body. */
    private static final Map<String, Pattern> HTML_HINTS = new LinkedHashMap<>();
    static {
        HTML_HINTS.put("WordPress", Pattern.compile("(?i)(/wp-content/|<meta name=[\"']generator[\"'] content=[\"']WordPress)"));
        HTML_HINTS.put("Drupal",    Pattern.compile("(?i)(Drupal\\.settings|/sites/default/files/)"));
        HTML_HINTS.put("Joomla",    Pattern.compile("(?i)(/media/system/js/|Joomla!)"));
        HTML_HINTS.put("Magento",   Pattern.compile("(?i)(/skin/frontend/|Mage\\.Cookies|var BLANK_URL)"));
        HTML_HINTS.put("Shopify",   Pattern.compile("(?i)cdn\\.shopify\\.com"));
        HTML_HINTS.put("React",     Pattern.compile("(?i)(react(\\.production)?\\.min\\.js|__REACT_DEVTOOLS_GLOBAL_HOOK__|data-reactroot)"));
        HTML_HINTS.put("Next.js",   Pattern.compile("(?i)(_next/static/|__NEXT_DATA__)"));
        HTML_HINTS.put("Vue.js",    Pattern.compile("(?i)(__VUE_HMR_RUNTIME__|vue(\\.runtime)?\\.global\\.js|v-bind:)"));
        HTML_HINTS.put("Angular",   Pattern.compile("(?i)(ng-version=|angular\\.js|@angular/core)"));
        HTML_HINTS.put("Nuxt",      Pattern.compile("(?i)(__NUXT__|_nuxt/)"));
        HTML_HINTS.put("Svelte",    Pattern.compile("(?i)svelte-[a-z0-9]{6}"));
        HTML_HINTS.put("jQuery",    Pattern.compile("(?i)jquery(\\.min)?\\.js"));
        HTML_HINTS.put("Bootstrap", Pattern.compile("(?i)bootstrap(\\.min)?\\.(css|js)"));
        HTML_HINTS.put("Tailwind",  Pattern.compile("(?i)(tailwindcss|tailwind\\.min\\.css)"));
        HTML_HINTS.put("Django admin", Pattern.compile("(?i)/static/admin/"));
        HTML_HINTS.put("Rails error page", Pattern.compile("(?i)Action Controller|Ruby on Rails"));
        HTML_HINTS.put("Gatsby",    Pattern.compile("(?i)(id=[\"']___gatsby[\"']|/page-data/)"));
        HTML_HINTS.put("Remix",     Pattern.compile("(?i)(__remixContext|window\\.__remixManifest)"));
        HTML_HINTS.put("Astro",     Pattern.compile("(?i)(<astro-island|astro-island )"));
        HTML_HINTS.put("SvelteKit", Pattern.compile("(?i)(data-sveltekit|__sveltekit)"));
        HTML_HINTS.put("Ember.js",  Pattern.compile("(?i)(id=[\"']ember[0-9]+[\"']|ember-application)"));
        HTML_HINTS.put("Alpine.js", Pattern.compile("(?i)(\\sx-data=|alpinejs)"));
        HTML_HINTS.put("htmx",      Pattern.compile("(?i)(\\shx-(get|post|target)=|htmx(\\.min)?\\.js)"));
        HTML_HINTS.put("Vite",      Pattern.compile("(?i)(/@vite/client|__vite__)"));
        HTML_HINTS.put("Webpack",   Pattern.compile("(?i)(webpackJsonp|__webpack_require__)"));
        HTML_HINTS.put("Wix",       Pattern.compile("(?i)static\\.wixstatic\\.com"));
        HTML_HINTS.put("Squarespace", Pattern.compile("(?i)static1\\.squarespace\\.com"));
        HTML_HINTS.put("Webflow",   Pattern.compile("(?i)(data-wf-page|\\.webflow\\.io)"));
        HTML_HINTS.put("Ghost CMS", Pattern.compile("(?i)content=[\"']Ghost"));
        HTML_HINTS.put("TYPO3",     Pattern.compile("(?i)/typo3(conf|temp)/"));
        HTML_HINTS.put("reCAPTCHA", Pattern.compile("(?i)google\\.com/recaptcha"));
        HTML_HINTS.put("hCaptcha",  Pattern.compile("(?i)\\bhcaptcha\\.com"));
        HTML_HINTS.put("Cloudflare Turnstile", Pattern.compile("(?i)challenges\\.cloudflare\\.com/turnstile"));
        HTML_HINTS.put("Stripe.js", Pattern.compile("(?i)js\\.stripe\\.com"));
    }

    /** Library label -> pattern whose group(1) captures a version string from markup (script/link hrefs). */
    private static final Map<String, Pattern> LIB_VERSION_HINTS = new LinkedHashMap<>();
    static {
        LIB_VERSION_HINTS.put("jQuery",    Pattern.compile("(?i)jquery[.-]([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"));
        LIB_VERSION_HINTS.put("jQuery UI", Pattern.compile("(?i)jquery-ui[.-]([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"));
        LIB_VERSION_HINTS.put("Bootstrap", Pattern.compile("(?i)bootstrap[.-]([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"));
        LIB_VERSION_HINTS.put("AngularJS", Pattern.compile("(?i)angular[.-]([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"));
        LIB_VERSION_HINTS.put("Vue.js",    Pattern.compile("(?i)vue[@.-]([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"));
        LIB_VERSION_HINTS.put("Lodash",    Pattern.compile("(?i)lodash[@.-]([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"));
        LIB_VERSION_HINTS.put("Moment.js", Pattern.compile("(?i)moment[@.-]([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"));
        LIB_VERSION_HINTS.put("D3.js",     Pattern.compile("(?i)d3[@.-]v?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"));
    }

    @Override public String id() { return ID; }
    @Override public String category() { return "Technology fingerprint"; }
    @Override public boolean isActive() { return false; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        HttpResponse resp = ctx.seedResponse();
        if (resp == null) return out;

        Set<String> hits = new LinkedHashSet<>();

        // Server header
        String server = HttpUtil.headerValue(resp, "Server");
        if (server != null && !server.isBlank()) hits.add("Server: " + server);

        // Powered-by
        String poweredBy = HttpUtil.headerValue(resp, "X-Powered-By");
        if (poweredBy != null && !poweredBy.isBlank()) hits.add("X-Powered-By: " + poweredBy);

        // Header hints
        for (Map.Entry<String, String> h : HEADER_HINTS.entrySet()) {
            String v = HttpUtil.headerValue(resp, h.getKey());
            if (v != null) hits.add(h.getValue() + " (" + h.getKey() + ": " + HttpUtil.truncate(v, 80) + ")");
        }

        // Cookie hints
        for (String cookieHeader : HttpUtil.headerValues(resp, "Set-Cookie")) {
            int eq = cookieHeader.indexOf('=');
            if (eq < 0) continue;
            String name = cookieHeader.substring(0, eq).trim().toLowerCase();
            String hint = COOKIE_HINTS.get(name);
            if (hint != null) {
                hits.add(hint + " (cookie: " + name + ")");
            } else {
                for (Map.Entry<String, String> p : COOKIE_PREFIX_HINTS.entrySet()) {
                    if (name.startsWith(p.getKey())) {
                        hits.add(p.getValue() + " (cookie: " + name + ")");
                        break;
                    }
                }
            }
        }

        // HTML meta generator
        String body = resp.bodyToString();
        if (body != null && !body.isEmpty()) {
            String head = body.length() > 32_768 ? body.substring(0, 32_768) : body;
            Matcher gen = Pattern.compile(
                    "(?i)<meta\\s+name=[\"']generator[\"']\\s+content=[\"']([^\"']+)[\"']").matcher(head);
            if (gen.find()) hits.add("HTML <meta generator>: " + gen.group(1));

            for (Map.Entry<String, Pattern> entry : HTML_HINTS.entrySet()) {
                if (entry.getValue().matcher(head).find()) hits.add(entry.getKey() + " (HTML pattern)");
            }

            // Best-effort client-library version extraction from script/link hrefs (e.g. jquery-3.6.0.min.js).
            for (Map.Entry<String, Pattern> entry : LIB_VERSION_HINTS.entrySet()) {
                Matcher m = entry.getValue().matcher(head);
                if (m.find()) hits.add(entry.getKey() + " " + m.group(1) + " (version from markup)");
            }
        }

        if (!hits.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".summary")
                    .title("Technology stack fingerprint (" + hits.size() + " hint(s))")
                    .severity(Severity.INFO)
                    .confidence(Confidence.FIRM)
                    .url(ctx.targetUrl())
                    .description("Headers, cookies, and HTML markers indicate the following technologies. Use this to "
                            + "narrow the attack surface (which CVEs apply, which payloads, which auth model).")
                    .remediation("Reduce fingerprinting by stripping `Server`/`X-Powered-By`/version headers, "
                            + "renaming default session-cookie names, and removing generator meta tags from production HTML.")
                    .evidence(String.join("\n", hits))
                    .references(List.of(
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"))
                    .request(ctx.seedRequest())
                    .response(resp)
                    .build());
        }
        return out;
    }
}
