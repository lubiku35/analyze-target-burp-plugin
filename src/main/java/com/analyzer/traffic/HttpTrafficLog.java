package com.analyzer.traffic;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Thread-safe append-only log of every HTTP request issued by the plugin during analysis.
 * Listeners (the HTTP traffic tab) are notified on Swing's EDT via the supplied callback.
 */
public final class HttpTrafficLog {
    private final List<HttpTrafficEntry> entries = new CopyOnWriteArrayList<>();
    private final List<Consumer<HttpTrafficEntry>> listeners = new CopyOnWriteArrayList<>();
    private final List<Runnable> clearListeners = new CopyOnWriteArrayList<>();
    private final AtomicLong sequence = new AtomicLong(0);

    public long nextSequence() { return sequence.incrementAndGet(); }

    public void add(HttpTrafficEntry entry) {
        entries.add(entry);
        for (Consumer<HttpTrafficEntry> l : listeners) {
            try { l.accept(entry); } catch (Exception ignored) {}
        }
    }

    public void clear() {
        entries.clear();
        sequence.set(0);
        for (Runnable r : clearListeners) {
            try { r.run(); } catch (Exception ignored) {}
        }
    }

    public List<HttpTrafficEntry> snapshot() {
        return Collections.unmodifiableList(new ArrayList<>(entries));
    }

    public int size() { return entries.size(); }

    public void addListener(Consumer<HttpTrafficEntry> onAdded) {
        listeners.add(onAdded);
    }

    public void addClearListener(Runnable onClear) {
        clearListeners.add(onClear);
    }
}
