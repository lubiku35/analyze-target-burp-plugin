package com.analyzer.checks.passive;

import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;
import com.analyzer.testutil.TestHttp;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SerializedObjectCheckTest {

    private final SerializedObjectCheck check = new SerializedObjectCheck();

    @Test
    void javaSerializedBlobIsDetectedAndCappedToLow() {
        // base64 Java serialized stream marker (rO0AB...) embedded in a cookie.
        AnalysisContext ctx = TestHttp.ctx(
                TestHttp.get("https://t/", TestHttp.header("Cookie", "state=rO0ABXNyABFqYXZhLnV0aWwu")),
                TestHttp.response(200, "OK", List.of(), ""));
        List<Finding> out = check.run(ctx);
        assertEquals(1, out.size());
        Finding f = out.get(0);
        assertTrue(f.checkId().contains("java"));
        // Requested HIGH but TENTATIVE -> capped to LOW.
        assertEquals(Severity.LOW, f.severity());
    }

    @Test
    void cleanResponseProducesNoFinding() {
        AnalysisContext ctx = TestHttp.ctx(
                TestHttp.get("https://t/"),
                TestHttp.response(200, "OK", List.of(), "<html><body>hello</body></html>"));
        assertTrue(check.run(ctx).isEmpty());
    }
}
