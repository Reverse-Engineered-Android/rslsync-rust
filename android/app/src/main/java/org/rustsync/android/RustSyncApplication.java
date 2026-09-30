package org.rustsync.android;

import android.app.Application;

import java.io.File;

public final class RustSyncApplication extends Application {
    private BinaryManager binaryManager;
    private RustsyncApi api;
    private ProcessSupervisor processSupervisor;
    private StorageBridge storageBridge;
    private ServerManager serverManager;

    @Override
    public void onCreate() {
        super.onCreate();
        binaryManager = new BinaryManager(this);
        api = new RustsyncApi(this);
        processSupervisor = new ProcessSupervisor(this, binaryManager);
        storageBridge = new StorageBridge(this);
        serverManager = new ServerManager(this);
    }

    public BinaryManager binaryManager() {
        return binaryManager;
    }

    public RustsyncApi api() {
        return api;
    }

    public ProcessSupervisor processSupervisor() {
        return processSupervisor;
    }

    public StorageBridge storageBridge() {
        return storageBridge;
    }

    public ServerManager serverManager() {
        return serverManager;
    }

    public File workDirectory() {
        File directory = new File(getFilesDir(), "rustsync-work");
        if (!directory.exists() && !directory.mkdirs()) {
            throw new IllegalStateException("cannot create work directory " + directory);
        }
        return directory;
    }
}
