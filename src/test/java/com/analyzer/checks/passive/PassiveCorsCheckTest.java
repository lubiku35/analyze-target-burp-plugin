package com.analyzer.checks.passive;

import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;
import com.analyzer.testutil.TestHttp;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PassiveCorsCheckTest {

    private final PassiveCorsCheck check = new PassiveCorsCheck();

    private AnalysisContext ctx(List<HttpHeader> reqHeaders, List<HttpHeader> respHeaders) {
        HttpRequest req = TestHttp.request("GET", "https://t/", "/", reqHeaders, "", List.of());
        HttpResponse resp = TestHttp.response(200, "OK", respHeaders, "");
        return TestHttp.ctx(req, resp);
    }

    @Test
    void reflectedOriginWithCredentialsIsMedium() {
        AnalysisContext ctx = ctx(
                List.of(TestHttp.header("Origin", "https://evil.example")),
                List.of(TestHttp.header("Access-Control-Allow-Origin", "https://evil.example"),
                        TestHttp.header("Access-Control-Allow-Credentials", "true")));
        List<Finding> out = check.run(ctx);
        assertEquals(1, out.size());
        // Downgraded from HIGH to MEDIUM under the confirmed-impact model (passive, unconfirmed).
        assertEquals(Severity.MEDIUM, out.get(0).severity());
        assertTrue(out.get(0).title().contains("Access-Control-Allow-Origin"));
    }

    @Test
    void wildcardWithoutCredentialsIsLow() {
        AnalysisContext ctx = ctx(List.of(),
                List.of(TestHttp.header("Access-Control-Allow-Origin", "*")));
        List<Finding> out = check.run(ctx);
        assertEquals(1, out.size());
        assertEquals(Severity.LOW, out.get(0).severity());
    }

    @Test
    void noAcaoHeaderMeansNoFinding() {
        AnalysisContext ctx = ctx(List.of(), List.of(TestHttp.header("Content-Type", "text/html")));
        assertTrue(check.run(ctx).isEmpty());
    }
}
