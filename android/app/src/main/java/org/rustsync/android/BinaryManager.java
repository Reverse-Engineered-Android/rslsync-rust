package org.rustsync.android;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class BinaryManager {
    private final Context context;

    public BinaryManager(Context context) {
        this.context = context.getApplicationContext();
    }

    public synchronized File executable() throws IOException {
        File installed = installedExecutable();
        if (installed.isFile()) {
            makeExecutable(installed);
            return installed;
        }
        File extracted = new File(context.getFilesDir(), "bin/rustsync");
        if (!extracted.getParentFile().exists() && !extracted.getParentFile().mkdirs()) {
            throw new IOException("cannot create native binary directory");
        }
        String assetName = "native/" + preferredAndroidAbi() + "/rustsync";
        try (InputStream input = context.getAssets().open(assetName);
             OutputStream output = new FileOutputStream(extracted)) {
            byte[] buffer = new byte[128 * 1024];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                output.write(buffer, 0, count);
            }
            output.flush();
        } catch (IOException missingFromAssets) {
            throw new IOException(
                    "bundled rustsync is missing for ABI " + preferredAndroidAbi()
                            + "; expected librustsync.so in native libraries or " + assetName,
                    missingFromAssets);
        }
        makeExecutable(extracted);
        return extracted;
    }

    public boolean isInstalled() {
        return installedExecutable().isFile();
    }

    public String preferredAndroidAbi() {
        for (String abi : Build.SUPPORTED_ABIS) {
            if (isSupported(abi)) {
                return abi;
            }
        }
        throw new IllegalStateException("unsupported Android ABI");
    }

    private File installedExecutable() {
        ApplicationInfo info = context.getApplicationInfo();
        return new File(info.nativeLibraryDir, "librustsync.so");
    }

    private static boolean isSupported(String abi) {
        return abi.equals("arm64-v8a")
                || abi.equals("armeabi-v7a")
                || abi.equals("x86")
                || abi.equals("x86_64");
    }

    private static void makeExecutable(File file) throws IOException {
        if (!file.setExecutable(true, false) && !file.canExecute()) {
            throw new IOException("cannot mark rustsync executable: " + file);
        }
    }
}
