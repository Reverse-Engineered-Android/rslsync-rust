package org.rustsync.android;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ProcessSupervisor {
    private final Context context;
    private final BinaryManager binaryManager;
    private final Map<String, ManagedProcess> processes =
            Collections.synchronizedMap(new LinkedHashMap<>());
    private final ExecutorService executor = Executors.newCachedThreadPool();

    public ProcessSupervisor(Context context, BinaryManager binaryManager) {
        this.context = context.getApplicationContext();
        this.binaryManager = binaryManager;
    }

    public ManagedProcess start(String label, List<String> arguments, File workingDirectory)
            throws IOException {
        File binary = binaryManager.executable();
        File logs = new File(context.getFilesDir(), "process-logs");
        if (!logs.exists() && !logs.mkdirs()) {
            throw new IOException("cannot create process log directory");
        }
        File log = new File(logs, UUID.randomUUID() + ".log");
        List<String> command = new ArrayList<>();
        command.add(binary.getAbsolutePath());
        command.addAll(arguments);

        ProcessBuilder builder = new ProcessBuilder(command);
        if (workingDirectory != null) {
            builder.directory(workingDirectory);
        }
        builder.environment().put("HOME", context.getFilesDir().getAbsolutePath());
        builder.environment().put("TMPDIR", context.getCacheDir().getAbsolutePath());
        Process process = builder.start();
        ManagedProcess managed = new ManagedProcess(label, command, log, process);
        processes.put(managed.id, managed);
        executor.execute(() -> collectOutput(managed, process));
        return managed;
    }

    public CommandResult runOnce(String label, List<String> arguments, File workingDirectory)
            throws IOException, InterruptedException {
        ManagedProcess managed = start(label, arguments, workingDirectory);
        Process process = managed.process;
        if (!process.waitFor(15, java.util.concurrent.TimeUnit.MINUTES)) {
            managed.stopRequested = true;
            process.destroy();
            throw new IOException("command timed out: " + label);
        }
        processes.remove(managed.id);
        return new CommandResult(process.exitValue(), tail(managed.logFile, 256 * 1024));
    }

    public Collection<ManagedProcess> snapshot() {
        synchronized (processes) {
            return new ArrayList<>(processes.values());
        }
    }

    public ManagedProcess find(String id) {
        return processes.get(id);
    }

    public void stop(String id) {
        ManagedProcess managed = processes.get(id);
        if (managed != null) {
            managed.stopRequested = true;
            Process process = managed.process;
            if (process != null) {
                process.destroy();
            }
        }
    }

    public void stopAll() {
        for (ManagedProcess managed : snapshot()) {
            stop(managed.id);
        }
    }

    private void collectOutput(ManagedProcess managed, Process process) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                process.getInputStream(), StandardCharsets.UTF_8));
             BufferedReader errors = new BufferedReader(new InputStreamReader(
                     process.getErrorStream(), StandardCharsets.UTF_8));
             OutputStream output = new FileOutputStream(managed.logFile)) {
            Thread errorThread = new Thread(() -> copy(errors, output));
            errorThread.start();
            copy(reader, output);
            errorThread.join();
        } catch (IOException | InterruptedException ignored) {
        }
    }

    private static void copy(BufferedReader reader, OutputStream output) {
        byte[] buffer = new byte[16 * 1024];
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
                synchronized (output) {
                    output.write(bytes);
                    output.flush();
                }
            }
        } catch (IOException ignored) {
        }
    }

    public static String tail(File file, int limit) throws IOException {
        byte[] bytes = java.nio.file.Files.readAllBytes(file.toPath());
        int start = Math.max(0, bytes.length - limit);
        return new String(bytes, start, bytes.length - start, StandardCharsets.UTF_8);
    }

    public static final class CommandResult {
        public final int exitCode;
        public final String output;

        CommandResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }

        public boolean successful() {
            return exitCode == 0;
        }
    }
}
