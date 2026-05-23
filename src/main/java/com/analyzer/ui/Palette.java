package com.analyzer.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.UIManager;
import java.awt.Color;

/**
 * Theme-aware colour palette. We try a few signals in order:
 *   1. {@code api.userInterface().currentTheme().name()} - defensively, so unknown enum names don't crash.
 *   2. Swing's {@code Panel.background} brightness - works even if Burp hasn't set its theme on us yet.
 *
 * Severity colours are tuned for AA contrast against both backgrounds.
 */
public final class Palette {
    public final boolean dark;
    public final Color background;
    public final Color panelBackground;
    public final Color rowEven;
    public final Color rowOdd;
    public final Color rowSelectedBg;
    public final Color rowSelectedFg;
    public final Color foreground;
    public final Color mutedForeground;
    public final Color border;
    public final Color accent;

    public final Color sevCriticalFg, sevCriticalBg;
    public final Color sevHighFg,     sevHighBg;
    public final Color sevMediumFg,   sevMediumBg;
    public final Color sevLowFg,      sevLowBg;
    public final Color sevInfoFg,     sevInfoBg;

    private Palette(boolean dark) {
        this.dark = dark;
        if (dark) {
            background        = new Color(0x1F2127);
            panelBackground   = new Color(0x262932);
            rowEven           = new Color(0x262932);
            rowOdd            = new Color(0x2C303B);
            rowSelectedBg     = new Color(0x3E4451);
            rowSelectedFg     = new Color(0xF8F8F2);
            foreground        = new Color(0xE6E6E6);
            mutedForeground   = new Color(0x9AA0A6);
            border            = new Color(0x3C404B);
            accent            = new Color(0xFF6633); // Burp orange

            // info=green, low=yellow, medium=orange, high=red, critical=dark red/near-black
            sevCriticalBg = new Color(0x180404); sevCriticalFg = new Color(0xFF8A8A);
            sevHighBg     = new Color(0x5C1F1F); sevHighFg     = new Color(0xFF9F9F);
            sevMediumBg   = new Color(0x5C3A1F); sevMediumFg   = new Color(0xFFC08A);
            sevLowBg      = new Color(0x5C551F); sevLowFg      = new Color(0xFFE680);
            sevInfoBg     = new Color(0x1F4D2A); sevInfoFg     = new Color(0x9FE0AF);
        } else {
            background        = new Color(0xFAFAFA);
            panelBackground   = new Color(0xFFFFFF);
            rowEven           = new Color(0xFFFFFF);
            rowOdd            = new Color(0xF6F8FA);
            rowSelectedBg     = new Color(0xDDE8FF);
            rowSelectedFg     = new Color(0x101010);
            foreground        = new Color(0x1F2933);
            mutedForeground   = new Color(0x52606D);
            border            = new Color(0xDCE1E8);
            accent            = new Color(0xE25A1F); // Burp orange (slightly darker for contrast)

            // info=green, low=yellow, medium=orange, high=red, critical=dark red/near-black
            sevCriticalBg = new Color(0x330000); sevCriticalFg = new Color(0xFFC2C2);
            sevHighBg     = new Color(0xFFD4D4); sevHighFg     = new Color(0xB11212);
            sevMediumBg   = new Color(0xFFE2C2); sevMediumFg   = new Color(0x9A4E00);
            sevLowBg      = new Color(0xFBF3C0); sevLowFg      = new Color(0x6E5A00);
            sevInfoBg     = new Color(0xDCF1E1); sevInfoFg     = new Color(0x1F6B33);
        }
    }

    public static Palette detect(MontoyaApi api) {
        Boolean isDark = null;
        try {
            Object theme = api.userInterface().currentTheme();
            if (theme != null) isDark = theme.toString().toUpperCase().contains("DARK");
        } catch (Throwable ignored) {
            // older API or unexpected runtime - fall through
        }
        if (isDark == null) {
            // Fall back to Swing's reported panel background brightness.
            Color bg = UIManager.getColor("Panel.background");
            if (bg != null) {
                double brightness = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue());
                isDark = brightness < 128;
            } else {
                isDark = false;
            }
        }
        return new Palette(isDark);
    }

    public Color severityBg(String label) {
        return switch (label.toLowerCase()) {
            case "critical" -> sevCriticalBg;
            case "high"     -> sevHighBg;
            case "medium"   -> sevMediumBg;
            case "low"      -> sevLowBg;
            case "info"     -> sevInfoBg;
            default          -> panelBackground;
        };
    }

    public Color severityFg(String label) {
        return switch (label.toLowerCase()) {
            case "critical" -> sevCriticalFg;
            case "high"     -> sevHighFg;
            case "medium"   -> sevMediumFg;
            case "low"      -> sevLowFg;
            case "info"     -> sevInfoFg;
            default          -> foreground;
        };
    }
}
