package com.analyzer.checks.passive;

import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;
import com.analyzer.testutil.TestHttp;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CspCheckTest {

    private final CspCheck check = new CspCheck();

    @Test
    void missingCspIsLow() {
        AnalysisContext ctx = TestHttp.ctx(
                TestHttp.get("https://t/"),
                TestHttp.response(200, "OK", List.of(), "<html></html>"));
        List<Finding> out = check.run(ctx);
        assertEquals(1, out.size());
        assertEquals("csp.missing", out.get(0).checkId());
        // Downgraded MEDIUM -> LOW: missing CSP is defence-in-depth, not a confirmed vuln.
        assertEquals(Severity.LOW, out.get(0).severity());
    }

    @Test
    void strongCspProducesNoFinding() {
        String strong = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
                + "base-uri 'self'; form-action 'self'";
        AnalysisContext ctx = TestHttp.ctx(
                TestHttp.get("https://t/"),
                TestHttp.response(200, "OK",
                        List.of(TestHttp.header("Content-Security-Policy", strong)), "<html></html>"));
        assertTrue(check.run(ctx).isEmpty(), "a strong CSP should yield no finding");
    }

    @Test
    void unsafeInlineCspIsWeakAndLow() {
        String weak = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; "
                + "frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
        AnalysisContext ctx = TestHttp.ctx(
                TestHttp.get("https://t/"),
                TestHttp.response(200, "OK",
                        List.of(TestHttp.header("Content-Security-Policy", weak)), "<html></html>"));
        List<Finding> out = check.run(ctx);
        assertEquals(1, out.size());
        assertEquals("csp.weak", out.get(0).checkId());
        assertEquals(Severity.LOW, out.get(0).severity());
        assertTrue(out.get(0).description().contains("unsafe-inline"));
    }
}
