package com.analyzer.checks.passive;

import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;
import com.analyzer.testutil.TestHttp;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CookieFlagsCheckTest {

    private final CookieFlagsCheck check = new CookieFlagsCheck();

    private AnalysisContext ctxWithSetCookie(String setCookie, String url) {
        return TestHttp.ctx(
                TestHttp.get(url),
                TestHttp.response(200, "OK", List.of(TestHttp.header("Set-Cookie", setCookie)), ""));
    }

    @Test
    void sessionCookieMissingAllFlagsOnHttpsIsMedium() {
        AnalysisContext ctx = ctxWithSetCookie("sid=abc123", "https://t/");
        List<Finding> out = check.run(ctx);
        assertEquals(1, out.size());
        Finding f = out.get(0);
        assertTrue(f.title().contains("sid"), "title names the cookie");
        assertEquals(Severity.MEDIUM, f.severity(), "session cookie without Secure/HttpOnly on HTTPS is MEDIUM");
        assertTrue(f.description().contains("HttpOnly"));
    }

    @Test
    void hardenedCookieProducesNoFinding() {
        AnalysisContext ctx = ctxWithSetCookie(
                "__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/", "https://t/");
        assertTrue(check.run(ctx).isEmpty(), "a fully-hardened __Host- cookie should be clean");
    }

    @Test
    void noSetCookieHeaderMeansNoFinding() {
        AnalysisContext ctx = TestHttp.ctx(TestHttp.get("https://t/"),
                TestHttp.response(200, "OK", List.of(), ""));
        assertTrue(check.run(ctx).isEmpty());
    }
}
