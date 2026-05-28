package com.analyzer.checks.passive;

import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;
import com.analyzer.testutil.TestHttp;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtAnalysisCheckTest {

    // {"alg":"none","typ":"JWT"} . {"sub":"1","email":"a@b.com","role":"admin"} . (empty sig)
    private static final String ALG_NONE_JWT =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
          + "eyJzdWIiOiIxIiwiZW1haWwiOiJhQGIuY29tIiwicm9sZSI6ImFkbWluIn0.";

    private final JwtAnalysisCheck check = new JwtAnalysisCheck();

    @Test
    void detectsAlgNoneFromBearerHeaderAndCapsToLow() {
        AnalysisContext ctx = TestHttp.ctx(
                TestHttp.get("https://t/", TestHttp.header("Authorization", "Bearer " + ALG_NONE_JWT)),
                TestHttp.response(200, "OK", List.of(), ""));

        List<Finding> out = check.run(ctx);

        assertEquals(1, out.size(), "one JWT should be reported");
        Finding f = out.get(0);
        assertTrue(f.title().contains("alg=none"), "title should call out alg=none, was: " + f.title());
        assertTrue(f.checkId().startsWith("jwt"), "checkId should be in the jwt namespace");
        // alg=none is requested HIGH but confidence is TENTATIVE, so it is capped to LOW.
        assertEquals(Severity.LOW, f.severity(), "tentative alg=none lead must be capped to LOW");
        assertTrue(f.description().contains("email") || f.description().contains("role"),
                "sensitive claims should be surfaced");
    }

    @Test
    void noTokenProducesNoFindings() {
        AnalysisContext ctx = TestHttp.ctx(
                TestHttp.get("https://t/", TestHttp.header("User-Agent", "x")),
                TestHttp.response(200, "OK", List.of(), "<html>nothing here</html>"));
        assertTrue(check.run(ctx).isEmpty());
    }

    @Test
    void isPassive() {
        assertFalse(check.isActive());
    }
}
