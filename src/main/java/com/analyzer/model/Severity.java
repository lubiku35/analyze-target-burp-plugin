package com.analyzer.model;

/**
 * Finding severity. Order matters: ordinal() is used for sorting (CRITICAL first).
 */
public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO;

    public String label() {
        String n = name();
        return n.charAt(0) + n.substring(1).toLowerCase();
    }
}
