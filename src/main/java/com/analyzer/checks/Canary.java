package com.analyzer.checks;

import java.util.UUID;

/**
 * Centralised "obviously a probe" canary values. All host-header, CORS, and forced-404 probes
 * use these so the values are immediately recognisable in target access logs — both to the
 * analyst (who can grep their own findings) and to the operator on the receiving end (who should
 * not mistake them for a real attack).
 *
 * <p>The host is a plain English phrase under {@code .xyz}: even a non-technical log reviewer can
 * tell at a glance the request is a fingerprint probe rather than a live attempt. {@code .test}
 * (RFC 6761 reserved) would be safer against canary-domain takeover, but the descriptive form
 * was the user's explicit preference for legibility.</p>
 *
 * <p>If you need a stricter guarantee that the canary host can never resolve to a real server,
 * swap {@link #HOST} for {@code surethisdoesnotexist.test} — the rest of the helpers remain
 * unchanged.</p>
 */
public final class Canary {
    private Canary() {}

    /** Canonical canary host. Used as a Host-header / Origin value. */
    public static final String HOST = "surethisdoesnotexist.xyz";

    /** Canonical canary path prefix (no extension). The forced-404 probe appends randomness. */
    public static final String PATH_PREFIX = "/surethisdoesnotexist";

    /** A `https://` origin form of the canary, used by CORS reflection probes. */
    public static String corsOrigin() {
        return "https://" + HOST;
    }

    /**
     * Build a "suffix-bypass" origin — e.g. {@code https://target.com.surethisdoesnotexist.xyz}.
     * Tests whether the server's Origin allow-list is implemented with naive prefix-matching
     * (a common bug — the server splits on `.` and trusts anything ending in the expected
     * domain, regardless of what precedes it).
     */
    public static String suffixBypassOrigin(String targetHost) {
        return "https://" + targetHost + "." + HOST;
    }

    /**
     * Build a "prefix-bypass" origin — e.g. {@code https://surethisdoesnotexist-target-com.xyz}.
     * Tests whether the server's Origin allow-list uses naive suffix-matching.
     */
    public static String prefixBypassOrigin(String targetHost) {
        return "https://surethisdoesnotexist-" + targetHost.replace('.', '-') + ".xyz";
    }

    /**
     * A guaranteed-non-existent path on the target — for forcing a 404 to fingerprint the
     * server / framework error page. We append randomness because an admin could conceivably
     * create the static `surethisdoesnotexist` URL and break our probe.
     *
     * @param extension optional extension (e.g. ".php", ".aspx"); pass empty string for no extension
     */
    public static String randomNotFoundPath(String extension) {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        return PATH_PREFIX + "-" + suffix + (extension == null ? "" : extension);
    }

    /** Convenience: random not-found path with no extension. */
    public static String randomNotFoundPath() {
        return randomNotFoundPath("");
    }
}
