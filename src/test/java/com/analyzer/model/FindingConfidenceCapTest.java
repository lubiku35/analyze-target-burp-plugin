package com.analyzer.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The Finding constructor caps any TENTATIVE-confidence finding at LOW, so an unconfirmed lead can
 * never be displayed as HIGH/MEDIUM. CERTAIN/FIRM findings keep their requested severity.
 */
class FindingConfidenceCapTest {

    private static Finding f(Severity sev, Confidence conf) {
        return Finding.builder().checkId("t").title("t").severity(sev).confidence(conf).build();
    }

    @Test
    void tentativeHighIsCappedToLow() {
        assertEquals(Severity.LOW, f(Severity.HIGH, Confidence.TENTATIVE).severity());
    }

    @Test
    void tentativeMediumIsCappedToLow() {
        assertEquals(Severity.LOW, f(Severity.MEDIUM, Confidence.TENTATIVE).severity());
    }

    @Test
    void tentativeCriticalIsCappedToLow() {
        assertEquals(Severity.LOW, f(Severity.CRITICAL, Confidence.TENTATIVE).severity());
    }

    @Test
    void tentativeLowStaysLow() {
        assertEquals(Severity.LOW, f(Severity.LOW, Confidence.TENTATIVE).severity());
    }

    @Test
    void tentativeInfoStaysInfo() {
        assertEquals(Severity.INFO, f(Severity.INFO, Confidence.TENTATIVE).severity());
    }

    @Test
    void confirmedHighIsPreserved() {
        assertEquals(Severity.HIGH, f(Severity.HIGH, Confidence.CERTAIN).severity());
        assertEquals(Severity.HIGH, f(Severity.HIGH, Confidence.FIRM).severity());
    }

    @Test
    void defaultConfidenceIsFirmAndUncapped() {
        Finding f = Finding.builder().checkId("t").title("t").severity(Severity.HIGH).build();
        assertEquals(Confidence.FIRM, f.confidence());
        assertEquals(Severity.HIGH, f.severity());
    }
}
