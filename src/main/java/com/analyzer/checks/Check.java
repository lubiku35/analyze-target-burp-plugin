package com.analyzer.checks;

import com.analyzer.engine.AnalysisContext;
import com.analyzer.model.Finding;

import java.util.List;

/**
 * A single recon check. Implementations should be self-contained and idempotent.
 *
 * Passive checks read context.seedResponse() and never call out.
 * Active checks may use context.api().http().sendRequest(...).
 *
 * Long-running checks should respect interruption (Thread.currentThread().isInterrupted()).
 */
public interface Check {
    /** Stable identifier, e.g. "headers.csp". Used for grouping and report linking. */
    String id();

    /** Short human-friendly category label, e.g. "Security Headers". */
    String category();

    /** True if this check sends additional HTTP traffic to the target. */
    boolean isActive();

    /** Run the check; return zero or more findings. Implementations must not throw. */
    List<Finding> run(AnalysisContext context);
}
