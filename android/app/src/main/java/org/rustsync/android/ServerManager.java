package org.rustsync.android;

import android.content.Context;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.Arrays;

public final class ServerManager {
    private static final String PROCESS_LABEL = "rustsync serve-ui";
    private final Context context;
    private final RustSyncApplication application;

    public ServerManager(RustSyncApplication application) {
        this.application = application;
        this.context = application.getApplicationContext();
    }

    public synchronized ManagedProcess start() throws IOException, InterruptedException {
        ManagedProcess existing = findServer();
        if (existing != null && existing.alive()) {
            return existing;
        }
        File stateDirectory = new File(context.getFilesDir(), "server-state");
        if (!stateDirectory.exists() && !stateDirectory.mkdirs()) {
            throw new IOException("cannot create rustsync state directory");
        }
        int port = availableLoopbackPort();
        ManagedProcess process = application.processSupervisor().start(
                PROCESS_LABEL,
                Arrays.asList(
                        "serve-ui",
                        "--listen",
                        "127.0.0.1:" + port,
                        "--state",
                        new File(stateDirectory, "state.json").getAbsolutePath()),
                application.workDirectory());
        application.api().setBaseUrl("http://127.0.0.1:" + port);
        waitForHealth();
        return process;
    }

    public synchronized void stop() {
        ManagedProcess process = findServer();
        if (process != null) {
            application.processSupervisor().stop(process.id);
        }
    }

    public ManagedProcess findServer() {
        for (ManagedProcess process : application.processSupervisor().snapshot()) {
            if (PROCESS_LABEL.equals(process.label)) {
                return process;
            }
        }
        return null;
    }

    public boolean isRunning() {
        ManagedProcess process = findServer();
        return process != null && process.alive();
    }

    private void waitForHealth() throws IOException, InterruptedException {
        long deadline = System.currentTimeMillis() + 15_000;
        IOException last = null;
        while (System.currentTimeMillis() < deadline) {
            try {
                JSONObject health = application.api().get("/api/v1/health");
                if (health.optBoolean("ok", true)) {
                    return;
                }
            } catch (IOException | JSONException error) {
                last = error instanceof IOException ? (IOException) error : new IOException(error);
            }
            Thread.sleep(100);
        }
        ManagedProcess process = findServer();
        String tail = "";
        if (process != null) {
            try {
                tail = ProcessSupervisor.tail(process.logFile, 8 * 1024);
            } catch (IOException ignored) {
            }
        }
        throw new IOException("rustsync server did not become healthy: " + tail, last);
    }

    private static int availableLoopbackPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }
}
