package com.analyzer.ui;

import com.analyzer.model.Confidence;
import com.analyzer.model.Finding;
import com.analyzer.model.Severity;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * FindingsTableModel de-duplicates by content signature, so a check that emits the same finding
 * twice — or a project restore overlapping a fresh run — never produces duplicate rows.
 */
class FindingsTableModelTest {

    private static Finding finding(String checkId, String title, String url, String evidence) {
        return Finding.builder()
                .checkId(checkId).title(title).url(url).evidence(evidence)
                .severity(Severity.LOW).confidence(Confidence.FIRM)
                .build();
    }

    /** addFinding schedules work on the EDT; flush it so assertions see the result. */
    private static void flushEdt() throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(() -> { });
    }

    @Test
    void identicalFindingsAreDeduplicated() throws Exception {
        FindingsTableModel model = new FindingsTableModel();
        Finding a = finding("cookies.flags", "Cookie x weak", "https://t/", "Set-Cookie: x=1");
        model.addFinding(a);
        model.addFinding(finding("cookies.flags", "Cookie x weak", "https://t/", "Set-Cookie: x=1"));
        flushEdt();
        assertEquals(1, model.getRowCount(), "exact duplicate should not add a second row");
    }

    @Test
    void differentEvidenceIsKept() throws Exception {
        FindingsTableModel model = new FindingsTableModel();
        model.addFinding(finding("js-grep.secret", "Possible secret", "https://t/a.js", "AKIA....1"));
        model.addFinding(finding("js-grep.secret", "Possible secret", "https://t/a.js", "AKIA....2"));
        flushEdt();
        assertEquals(2, model.getRowCount(), "different evidence means a distinct finding");
    }

    @Test
    void differentUrlIsKept() throws Exception {
        FindingsTableModel model = new FindingsTableModel();
        model.addFinding(finding("headers.csp", "Missing CSP", "https://t/a", "no CSP"));
        model.addFinding(finding("headers.csp", "Missing CSP", "https://t/b", "no CSP"));
        flushEdt();
        assertEquals(2, model.getRowCount());
    }

    @Test
    void clearResetsDeduplicationState() throws Exception {
        FindingsTableModel model = new FindingsTableModel();
        Finding a = finding("x", "t", "u", "e");
        model.addFinding(a);
        flushEdt();
        model.clear();
        flushEdt();
        assertEquals(0, model.getRowCount());
        // Same finding can be added again after a clear (e.g. a fresh run of the same target).
        model.addFinding(finding("x", "t", "u", "e"));
        flushEdt();
        assertEquals(1, model.getRowCount());
    }

    @Test
    void nullIsIgnored() throws Exception {
        FindingsTableModel model = new FindingsTableModel();
        model.addFinding(null);
        flushEdt();
        assertEquals(0, model.getRowCount());
    }
}
