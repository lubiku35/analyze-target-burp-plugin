package com.analyzer.model;

public enum Confidence {
    CERTAIN,
    FIRM,
    TENTATIVE;

    public String label() {
        String n = name();
        return n.charAt(0) + n.substring(1).toLowerCase();
    }
}
