package com.analyzer.checks.tls;

import com.analyzer.checks.Check;
import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Lightweight pure-Java TLS probe. For each protocol Java still understands, we attempt a handshake
 * and record what the server negotiated; we also pull the leaf certificate to check validity window
 * and SAN/CN match against the target hostname.
 *
 * Trade-off: this is intentionally less thorough than testssl.sh - it only sees what the local JDK
 * is willing to offer. It will not enumerate weak ciphers the JDK has removed. For a definitive
 * cipher audit, run testssl.sh out-of-band.
 */
public class TlsCheck implements Check {
    private static final String ID = "tls";

    private static final List<String> PROTOCOLS = Arrays.asList(
            "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3");

    @Override public String id() { return ID; }
    @Override public String category() { return "TLS/SSL"; }
    @Override public boolean isActive() { return true; }

    @Override
    public List<Finding> run(AnalysisContext ctx) {
        List<Finding> out = new ArrayList<>();
        URI uri;
        try {
            uri = new URI(ctx.targetUrl());
        } catch (Exception e) {
            return out;
        }
        if (uri.getScheme() == null || !uri.getScheme().equalsIgnoreCase("https")) return out;

        String host = uri.getHost();
        int port = uri.getPort() == -1 ? 443 : uri.getPort();
        if (host == null) return out;

        Set<String> supported = new LinkedHashSet<>();
        Set<String> weakSupported = new LinkedHashSet<>();
        X509Certificate leaf = null;
        String negotiatedCipher = null;

        for (String proto : PROTOCOLS) {
            try {
                SSLSocketFactory sf = trustAllFactory(proto);
                try (SSLSocket sock = (SSLSocket) sf.createSocket()) {
                    sock.connect(new java.net.InetSocketAddress(host, port), 5000);
                    sock.setSoTimeout(5000);
                    SSLParameters params = sock.getSSLParameters();
                    params.setServerNames(List.of(new javax.net.ssl.SNIHostName(host)));
                    sock.setSSLParameters(params);
                    sock.setEnabledProtocols(new String[]{proto});
                    sock.startHandshake();
                    supported.add(proto);
                    if (proto.equals("SSLv3") || proto.equals("TLSv1") || proto.equals("TLSv1.1")) {
                        weakSupported.add(proto);
                    }
                    if (leaf == null) {
                        java.security.cert.Certificate[] chain = sock.getSession().getPeerCertificates();
                        if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate xc) {
                            leaf = xc;
                            negotiatedCipher = sock.getSession().getCipherSuite();
                        }
                    }
                }
            } catch (Exception ignored) {
                // protocol not supported on this JDK or server rejected - that's the signal we want
            }
        }

        if (!weakSupported.isEmpty()) {
            out.add(Finding.builder()
                    .checkId(ID + ".weak-protocols")
                    .title("Weak/deprecated TLS protocols supported: " + String.join(", ", weakSupported))
                    .severity(Severity.MEDIUM)
                    .confidence(Confidence.FIRM)
                    .url(ctx.targetUrl())
                    .description("Server completed handshakes for: " + String.join(", ", weakSupported)
                            + ". SSLv3, TLS 1.0 and TLS 1.1 contain known cryptographic weaknesses (POODLE, BEAST) and have been "
                            + "deprecated by all major browsers.")
                    .remediation("Disable everything below TLS 1.2 at the web server / load balancer layer. Prefer TLS 1.3.")
                    .evidence("Supported: " + supported + "\nWeak: " + weakSupported
                            + (negotiatedCipher != null ? "\nSample cipher: " + negotiatedCipher : ""))
                    .references(List.of("https://www.ssllabs.com/ssltest/", "https://ciphersuite.info/"))
                    .build());
        }

        if (leaf != null) {
            Instant now = Instant.now();
            Instant notAfter  = leaf.getNotAfter().toInstant();
            Instant notBefore = leaf.getNotBefore().toInstant();
            Duration left = Duration.between(now, notAfter);

            if (now.isAfter(notAfter)) {
                out.add(Finding.builder()
                        .checkId(ID + ".cert-expired")
                        .title("TLS certificate expired")
                        .severity(Severity.HIGH)
                        .confidence(Confidence.CERTAIN)
                        .url(ctx.targetUrl())
                        .description("Leaf certificate expired on " + fmt(notAfter) + ".")
                        .remediation("Renew the certificate and ensure your renewal automation (ACME/cert-manager) is running.")
                        .evidence("Subject: " + leaf.getSubjectX500Principal()
                                + "\nNotBefore: " + fmt(notBefore)
                                + "\nNotAfter:  " + fmt(notAfter))
                        .build());
            } else if (left.toDays() <= 30) {
                out.add(Finding.builder()
                        .checkId(ID + ".cert-expiring")
                        .title("TLS certificate expiring soon (" + left.toDays() + " days)")
                        .severity(Severity.LOW)
                        .confidence(Confidence.CERTAIN)
                        .url(ctx.targetUrl())
                        .description("Leaf certificate expires on " + fmt(notAfter) + ".")
                        .remediation("Renew the certificate. Confirm renewal automation runs at least 14 days before expiry.")
                        .evidence("Subject: " + leaf.getSubjectX500Principal()
                                + "\nNotAfter: " + fmt(notAfter)
                                + "\nDays left: " + left.toDays())
                        .build());
            }

            // SAN / CN match
            Set<String> names = new LinkedHashSet<>();
            try {
                if (leaf.getSubjectAlternativeNames() != null) {
                    for (List<?> entry : leaf.getSubjectAlternativeNames()) {
                        if (entry.size() >= 2 && entry.get(1) instanceof String s) names.add(s.toLowerCase());
                    }
                }
            } catch (Exception ignored) {}
            String cn = leaf.getSubjectX500Principal().getName();
            boolean match = names.stream().anyMatch(n -> hostMatches(n, host)) || cn.toLowerCase().contains("cn=" + host.toLowerCase());
            if (!match) {
                out.add(Finding.builder()
                        .checkId(ID + ".cert-hostname-mismatch")
                        .title("TLS certificate hostname does not match target")
                        .severity(Severity.HIGH)
                        .confidence(Confidence.FIRM)
                        .url(ctx.targetUrl())
                        .description("Neither the certificate SANs nor CN match the requested host `" + host + "`.")
                        .remediation("Reissue the certificate with a SAN list that includes every hostname this endpoint serves.")
                        .evidence("Host: " + host + "\nCN: " + cn + "\nSANs: " + names)
                        .build());
            }
        } else {
            out.add(Finding.builder()
                    .checkId(ID + ".handshake-failed")
                    .title("TLS handshake failed for all attempted protocols")
                    .severity(Severity.INFO)
                    .confidence(Confidence.TENTATIVE)
                    .url(ctx.targetUrl())
                    .description("The local JDK could not complete a TLS handshake with " + host + ":" + port + ". This may indicate "
                            + "the server only supports protocols/ciphers this JVM disabled, or a network/firewall issue.")
                    .remediation("Re-test with `openssl s_client` or `testssl.sh " + host + ":" + port + "` for a definitive answer.")
                    .build());
        }

        return out;
    }

    private static String fmt(Instant i) {
        return DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(i);
    }

    /** Simple wildcard match used in cert SAN comparisons (only single leftmost label). */
    private static boolean hostMatches(String pattern, String host) {
        pattern = pattern.toLowerCase();
        host = host.toLowerCase();
        if (pattern.equals(host)) return true;
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // ".example.com"
            int dot = host.indexOf('.');
            return dot > 0 && host.substring(dot).equals(suffix);
        }
        return false;
    }

    /** Trust-all factory: we're probing the server's TLS stack, not validating against truststores. */
    private static SSLSocketFactory trustAllFactory(String protocol) throws Exception {
        TrustManager[] trustAll = {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance(protocol);
        ctx.init(null, trustAll, new SecureRandom());
        return ctx.getSocketFactory();
    }

}
