package com.analyzer.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.UIManager;
import java.awt.Color;

/**
 * Theme-aware colour palette. We borrow as much as we can <em>directly from Burp's Look &amp; Feel</em>
 * via {@link UIManager} so panels render in the same neutral grays Burp uses (no extra blue tint).
 * Only the accent (Burp orange) and the severity buckets are hardcoded — those carry semantic meaning
 * that must stay stable across themes.
 *
 * <p>Detection order:
 *   <ol>
 *     <li>{@code api.userInterface().currentTheme()} — Burp's own report, when available.</li>
 *     <li>Brightness of {@code Panel.background} — fallback when the API doesn't expose a theme.</li>
 *   </ol>
 */
public final class Palette {
    public final boolean dark;

    /** Outer chrome / page background — matches Burp's own panel background exactly. */
    public final Color background;
    /** Inset content background (text panes, detail panes). One shade off from the outer page. */
    public final Color panelBackground;
    /** Even/odd row colours for tables — derived from the L&F to stay native. */
    public final Color rowEven;
    public final Color rowOdd;
    public final Color rowSelectedBg;
    public final Color rowSelectedFg;
    public final Color foreground;
    public final Color mutedForeground;
    public final Color border;
    /** Burp orange — same accent both themes, tweaked slightly for contrast against the light bg. */
    public final Color accent;

    public final Color sevCriticalFg, sevCriticalBg;
    public final Color sevHighFg,     sevHighBg;
    public final Color sevMediumFg,   sevMediumBg;
    public final Color sevLowFg,      sevLowBg;
    public final Color sevInfoFg,     sevInfoBg;

    private Palette(boolean dark) {
        this.dark = dark;

        // Pull as much as we can from the active L&F so we look identical to Burp's chrome.
        Color uiPanel  = uiColor("Panel.background");
        Color uiText   = uiColor("Table.background");
        Color uiFg     = uiColor("Label.foreground");
        Color uiSelBg  = uiColor("Table.selectionBackground");
        Color uiSelFg  = uiColor("Table.selectionForeground");
        Color uiBorder = uiColor("Component.borderColor");

        if (dark) {
            // Burp's native dark theme (FlatLaf Darcula-style) sits around #3C3F41 — neutral gray.
            background        = firstNonNull(uiPanel, new Color(0x3C3F41));
            panelBackground   = firstNonNull(uiText,  new Color(0x313335));
            rowEven           = panelBackground;
            rowOdd            = shift(panelBackground, +6);    // very subtle stripe
            rowSelectedBg     = firstNonNull(uiSelBg, new Color(0x4B6EAF));
            rowSelectedFg     = firstNonNull(uiSelFg, new Color(0xFFFFFF));
            foreground        = firstNonNull(uiFg,    new Color(0xDCDCDC));
            mutedForeground   = mix(foreground, background, 0.55f);
            border            = firstNonNull(uiBorder, new Color(0x55585A));
            accent            = new Color(0xFF6633); // Burp orange

            // info=green, low=yellow, medium=orange, high=red, critical=dark red/near-black
            sevCriticalBg = new Color(0x2A0808); sevCriticalFg = new Color(0xFF9A9A);
            sevHighBg     = new Color(0x5C1F1F); sevHighFg     = new Color(0xFFB3B3);
            sevMediumBg   = new Color(0x5C3A1F); sevMediumFg   = new Color(0xFFC58E);
            sevLowBg      = new Color(0x55501F); sevLowFg      = new Color(0xFFE680);
            sevInfoBg     = new Color(0x1F4D2A); sevInfoFg     = new Color(0xA8E4B8);
        } else {
            // Burp's native light theme: near-white chrome, slightly darker content background.
            background        = firstNonNull(uiPanel, new Color(0xF2F2F2));
            panelBackground   = firstNonNull(uiText,  new Color(0xFFFFFF));
            rowEven           = panelBackground;
            rowOdd            = shift(panelBackground, -6);
            rowSelectedBg     = firstNonNull(uiSelBg, new Color(0xCDE2FB));
            rowSelectedFg     = firstNonNull(uiSelFg, new Color(0x000000));
            foreground        = firstNonNull(uiFg,    new Color(0x1F1F1F));
            mutedForeground   = mix(foreground, background, 0.55f);
            border            = firstNonNull(uiBorder, new Color(0xC8C8C8));
            accent            = new Color(0xE25A1F);

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
            // older API or unexpected runtime — fall through
        }
        if (isDark == null) {
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
        return switch (label == null ? "" : label.toLowerCase()) {
            case "critical" -> sevCriticalBg;
            case "high"     -> sevHighBg;
            case "medium"   -> sevMediumBg;
            case "low"      -> sevLowBg;
            case "info"     -> sevInfoBg;
            default          -> panelBackground;
        };
    }

    public Color severityFg(String label) {
        return switch (label == null ? "" : label.toLowerCase()) {
            case "critical" -> sevCriticalFg;
            case "high"     -> sevHighFg;
            case "medium"   -> sevMediumFg;
            case "low"      -> sevLowFg;
            case "info"     -> sevInfoFg;
            default          -> foreground;
        };
    }

    // ---- internals ----------------------------------------------------------

    private static Color uiColor(String key) {
        try {
            Color c = UIManager.getColor(key);
            // Some L&Fs return ColorUIResource; copy to a plain Color so equals/hash is predictable.
            return c == null ? null : new Color(c.getRGB(), true);
        } catch (Exception e) {
            return null;
        }
    }

    private static Color firstNonNull(Color a, Color b) {
        return a != null ? a : b;
    }

    /** Nudge an RGB colour by `delta` on every channel; clamps to [0, 255]. */
    private static Color shift(Color c, int delta) {
        return new Color(
                clamp(c.getRed()   + delta),
                clamp(c.getGreen() + delta),
                clamp(c.getBlue()  + delta));
    }

    /** Linear mix between two colours, weight in [0..1] for `a`. */
    private static Color mix(Color a, Color b, float w) {
        float wb = 1f - w;
        return new Color(
                clamp(Math.round(a.getRed()   * w + b.getRed()   * wb)),
                clamp(Math.round(a.getGreen() * w + b.getGreen() * wb)),
                clamp(Math.round(a.getBlue()  * w + b.getBlue()  * wb)));
    }

    private static int clamp(int v) { return Math.max(0, Math.min(255, v)); }
}
