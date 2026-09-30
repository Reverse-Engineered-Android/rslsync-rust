package org.rustsync.android;

import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class StorageBridge {
    private static final String PREFS = "storage_bridges";
    private static final String KEY = "bridges";
    private final Context context;
    private final SharedPreferences preferences;

    public StorageBridge(Context context) {
        this.context = context.getApplicationContext();
        preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public synchronized void put(BridgeConfig config) throws JSONException {
        JSONObject all = readAll();
        all.put(config.folderId, config.toJson());
        writeAll(all);
    }

    public synchronized BridgeConfig get(String folderId) throws JSONException {
        JSONObject value = readAll().optJSONObject(folderId);
        return value == null ? null : BridgeConfig.fromJson(value);
    }

    public synchronized void remove(String folderId) throws JSONException {
        JSONObject all = readAll();
        all.remove(folderId);
        writeAll(all);
    }

    public synchronized List<BridgeConfig> list() throws JSONException {
        JSONObject all = readAll();
        List<BridgeConfig> result = new ArrayList<>();
        JSONArray names = all.names();
        if (names == null) {
            return result;
        }
        for (int index = 0; index < names.length(); index++) {
            result.add(BridgeConfig.fromJson(all.getJSONObject(names.getString(index))));
        }
        return result;
    }

    public SyncResult syncAll() throws IOException {
        SyncResult result = new SyncResult();
        try {
            for (BridgeConfig config : list()) {
                if (config.enabled) {
                    sync(config, result.messages);
                }
            }
        } catch (JSONException error) {
            throw new IOException("read SAF bridge configuration", error);
        }
        return result;
    }

    public void sync(BridgeConfig config, List<String> messages) throws IOException {
        if (config == null || config.treeUri == null || config.treeUri.isEmpty()) {
            throw new IOException("SAF bridge has no persisted document tree");
        }
        File localRoot = new File(config.mirrorPath);
        if (!localRoot.exists() && !localRoot.mkdirs()) {
            throw new IOException("cannot create SAF mirror " + localRoot);
        }
        Uri tree = Uri.parse(config.treeUri);
        String rootId = DocumentsContract.getTreeDocumentId(tree);
        Uri rootDocument = DocumentsContract.buildDocumentUriUsingTree(tree, rootId);
        syncDirectory(tree, rootDocument, rootId, localRoot, messages);
    }

    private void syncDirectory(
            Uri tree,
            Uri parentDocument,
            String parentId,
            File localDirectory,
            List<String> messages) throws IOException {
        Map<String, RemoteEntry> remote = listRemote(tree, parentId);
        Map<String, File> local = new LinkedHashMap<>();
        File[] files = localDirectory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.getName().contains(".rustsync-conflict-")) {
                    continue;
                }
                local.put(file.getName(), file);
            }
        }

        for (Map.Entry<String, RemoteEntry> entry : remote.entrySet()) {
            String name = entry.getKey();
            RemoteEntry document = entry.getValue();
            File localFile = local.get(name);
            if (document.directory) {
                if (localFile == null) {
                    localFile = new File(localDirectory, name);
                    if (!localFile.mkdirs()) {
                        throw new IOException("cannot create mirror directory " + localFile);
                    }
                    messages.add("导入目录：" + relative(context, localFile));
                } else if (!localFile.isDirectory()) {
                    backupConflict(localFile, messages);
                    if (!localFile.mkdirs()) {
                        throw new IOException("cannot replace file with directory " + localFile);
                    }
                }
                syncDirectory(tree, document.uri, document.documentId, localFile, messages);
            } else {
                if (localFile == null) {
                    localFile = new File(localDirectory, name);
                    copyRemoteToFile(document.uri, localFile);
                    localFile.setLastModified(document.lastModified);
                    messages.add("导入文件：" + relative(context, localFile));
                } else if (localFile.isDirectory()) {
                    backupConflict(localFile, messages);
                    copyRemoteToFile(document.uri, localFile);
                    localFile.setLastModified(document.lastModified);
                    messages.add("以 SAF 文件替换冲突目录：" + relative(context, localFile));
                } else if (!sameContent(document.uri, localFile)) {
                    if (document.lastModified > localFile.lastModified()) {
                        File backup = backupFile(localFile, messages);
                        copyRemoteToFile(document.uri, localFile);
                        localFile.setLastModified(document.lastModified);
                        messages.add("SAF 更新：" + relative(context, localFile) + "；旧版本 " + backup.getName());
                    } else {
                        copyFileToRemote(localFile, document.uri);
                        messages.add("导出更新：" + relative(context, localFile));
                    }
                }
            }
        }

        for (Map.Entry<String, File> entry : local.entrySet()) {
            if (remote.containsKey(entry.getKey())) {
                continue;
            }
            File source = entry.getValue();
            String mimeType = source.isDirectory()
                    ? DocumentsContract.Document.MIME_TYPE_DIR
                    : mimeTypeFor(source.getName());
            Uri created = DocumentsContract.createDocument(
                    context.getContentResolver(), parentDocument, mimeType, source.getName());
            if (created == null) {
                throw new IOException("cannot create SAF document " + source.getName());
            }
            if (source.isDirectory()) {
                syncDirectory(tree, created, DocumentsContract.getDocumentId(created), source, messages);
            } else {
                copyFileToRemote(source, created);
            }
            messages.add("导出到 SAF：" + relative(context, source));
        }
    }

    private Map<String, RemoteEntry> listRemote(Uri tree, String parentId) throws IOException {
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentId);
        ContentResolver resolver = context.getContentResolver();
        Map<String, RemoteEntry> result = new LinkedHashMap<>();
        try (Cursor cursor = resolver.query(children, null, null, null, null)) {
            if (cursor == null) {
                throw new IOException("SAF provider returned no child cursor");
            }
            int idIndex = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID);
            int nameIndex = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME);
            int mimeIndex = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE);
            int modifiedIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED);
            while (cursor.moveToNext()) {
                String documentId = cursor.getString(idIndex);
                String name = cursor.getString(nameIndex);
                if (name == null || name.isEmpty() || name.equals(".") || name.equals("..")
                        || name.contains(File.separator) || name.contains("/")) {
                    continue;
                }
                String mime = cursor.getString(mimeIndex);
                long modified = modifiedIndex >= 0 ? cursor.getLong(modifiedIndex) : 0L;
                Uri uri = DocumentsContract.buildDocumentUriUsingTree(tree, documentId);
                result.put(name, new RemoteEntry(
                        documentId, uri, name, mime, modified,
                        DocumentsContract.Document.MIME_TYPE_DIR.equals(mime)));
            }
        }
        return result;
    }

    private boolean sameContent(Uri remote, File local) throws IOException {
        long remoteSize = remoteSize(remote);
        if (remoteSize >= 0 && local.length() != remoteSize) {
            return false;
        }
        try (InputStream remoteStream = new BufferedInputStream(
                context.getContentResolver().openInputStream(remote));
             InputStream localStream = new BufferedInputStream(new FileInputStream(local))) {
            byte[] remoteBuffer = new byte[128 * 1024];
            byte[] localBuffer = new byte[128 * 1024];
            while (true) {
                int remoteCount = readChunk(remoteStream, remoteBuffer);
                int localCount = readChunk(localStream, localBuffer);
                if (remoteCount != localCount
                        || !java.util.Arrays.equals(
                                java.util.Arrays.copyOf(remoteBuffer, Math.max(remoteCount, 0)),
                                java.util.Arrays.copyOf(localBuffer, Math.max(localCount, 0)))) {
                    return false;
                }
                if (remoteCount < 0) {
                    return true;
                }
            }
        }
    }

    private long remoteSize(Uri uri) {
        try (Cursor cursor = context.getContentResolver().query(
                uri,
                new String[] {DocumentsContract.Document.COLUMN_SIZE},
                null, null, null)) {
            return cursor != null && cursor.moveToFirst() && !cursor.isNull(0)
                    ? cursor.getLong(0)
                    : -1L;
        }
    }

    private static int readChunk(InputStream input, byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int count = input.read(buffer, offset, buffer.length - offset);
            if (count < 0) {
                return offset == 0 ? -1 : offset;
            }
            offset += count;
        }
        return offset;
    }

    private void copyRemoteToFile(Uri remote, File local) throws IOException {
        File parent = local.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("cannot create local parent " + parent);
        }
        try (InputStream input = new BufferedInputStream(
                context.getContentResolver().openInputStream(remote));
             OutputStream output = new BufferedOutputStream(new FileOutputStream(local))) {
            copy(input, output);
        }
    }

    private void copyFileToRemote(File local, Uri remote) throws IOException {
        try (InputStream input = new BufferedInputStream(new FileInputStream(local));
             OutputStream output = new BufferedOutputStream(
                     context.getContentResolver().openOutputStream(remote, "wt"))) {
            if (output == null) {
                throw new IOException("SAF provider returned no output stream");
            }
            copy(input, output);
        }
    }

    private static void copy(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[128 * 1024];
        int count;
        while ((count = input.read(buffer)) >= 0) {
            output.write(buffer, 0, count);
        }
        output.flush();
    }

    private File backupFile(File file, List<String> messages) throws IOException {
        String suffix = ".rustsync-conflict-" + System.currentTimeMillis();
        File backup = new File(file.getParentFile(), file.getName() + suffix);
        rename(file, backup);
        messages.add("保留本地冲突副本：" + relative(context, backup));
        return backup;
    }

    private File backupConflict(File file, List<String> messages) throws IOException {
        if (file.isDirectory()) {
            String suffix = ".rustsync-conflict-" + System.currentTimeMillis();
            File backup = new File(file.getParentFile(), file.getName() + suffix);
            rename(file, backup);
            messages.add("保留本地冲突目录：" + relative(context, backup));
            return backup;
        }
        return backupFile(file, messages);
    }

    private static void rename(File source, File target) throws IOException {
        if (!source.renameTo(target)) {
            throw new IOException("cannot move " + source + " to " + target);
        }
    }

    private static String mimeTypeFor(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".zip")) return "application/zip";
        if (lower.endsWith(".json")) return "application/json";
        if (lower.endsWith(".txt") || lower.endsWith(".log")) return "text/plain";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        return "application/octet-stream";
    }

    private static String relative(Context context, File file) {
        String root = context.getFilesDir().getAbsolutePath() + File.separator;
        String path = file.getAbsolutePath();
        return path.startsWith(root) ? path.substring(root.length()) : path;
    }

    private JSONObject readAll() throws JSONException {
        String value = preferences.getString(KEY, "{}");
        return new JSONObject(value == null ? "{}" : value);
    }

    private void writeAll(JSONObject value) {
        preferences.edit().putString(KEY, value.toString()).apply();
    }

    public static final class BridgeConfig {
        public final String folderId;
        public final String treeUri;
        public final String displayName;
        public final String mirrorPath;
        public final boolean enabled;

        public BridgeConfig(
                String folderId,
                String treeUri,
                String displayName,
                String mirrorPath,
                boolean enabled) {
            this.folderId = folderId;
            this.treeUri = treeUri;
            this.displayName = displayName;
            this.mirrorPath = mirrorPath;
            this.enabled = enabled;
        }

        JSONObject toJson() throws JSONException {
            return new JSONObject()
                    .put("folderId", folderId)
                    .put("treeUri", treeUri)
                    .put("displayName", displayName)
                    .put("mirrorPath", mirrorPath)
                    .put("enabled", enabled);
        }

        static BridgeConfig fromJson(JSONObject value) throws JSONException {
            return new BridgeConfig(
                    value.getString("folderId"),
                    value.getString("treeUri"),
                    value.optString("displayName", "SAF"),
                    value.getString("mirrorPath"),
                    value.optBoolean("enabled", true));
        }
    }

    public static final class SyncResult {
        public final List<String> messages = new ArrayList<>();
    }

    private static final class RemoteEntry {
        final String documentId;
        final Uri uri;
        final String name;
        final String mimeType;
        final long lastModified;
        final boolean directory;

        RemoteEntry(
                String documentId,
                Uri uri,
                String name,
                String mimeType,
                long lastModified,
                boolean directory) {
            this.documentId = documentId;
            this.uri = uri;
            this.name = name;
            this.mimeType = mimeType;
            this.lastModified = lastModified;
            this.directory = directory;
        }
    }
}
