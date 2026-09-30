package org.rustsync.android;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public final class ManagedProcess {
    public final String id = UUID.randomUUID().toString();
    public final String label;
    public final List<String> command;
    public final File logFile;
    public final long startedAt = System.currentTimeMillis();
    public volatile Process process;
    public volatile boolean stopRequested;

    ManagedProcess(String label, List<String> command, File logFile, Process process) {
        this.label = label;
        this.command = Collections.unmodifiableList(new ArrayList<>(command));
        this.logFile = logFile;
        this.process = process;
    }

    public boolean alive() {
        Process current = process;
        return current != null && current.isAlive();
    }

    public int exitValue() {
        Process current = process;
        if (current == null || current.isAlive()) {
            return Integer.MIN_VALUE;
        }
        return current.exitValue();
    }
}
