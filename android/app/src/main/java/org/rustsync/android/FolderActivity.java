package org.rustsync.android;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class FolderActivity extends Activity {
    private static final int PICK_TREE = 4101;
    private static final String[] TYPES = {
            "应用内部文件目录",
            "外部应用专属目录",
            "应用缓存目录（易失）",
            "外部缓存目录（易失）",
            "原生绝对路径（root/Termux/挂载）",
            "系统文件/云文档（SAF 双向桥接）"
    };

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private RustSyncApplication app;
    private EditText name;
    private Spinner storageType;
    private EditText path;
    private EditText include;
    private EditText exclude;
    private CheckBox enabled;
    private TextView storageDetail;
    private Button selectTree;
    private JSONObject existing;
    private String treeUri;
    private String treeName;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_folder);
        app = (RustSyncApplication) getApplication();
        name = findViewById(R.id.name);
        storageType = findViewById(R.id.storage_type);
        path = findViewById(R.id.path);
        include = findViewById(R.id.include);
        exclude = findViewById(R.id.exclude);
        enabled = findViewById(R.id.enabled);
        storageDetail = findViewById(R.id.storage_detail);
        selectTree = findViewById(R.id.select_tree);

        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, TYPES);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        storageType.setAdapter(adapter);
        storageType.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                updateTypeUi();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
        selectTree.setOnClickListener(view -> pickTree());
        findViewById(R.id.save).setOnClickListener(view -> executor.execute(this::save));
        loadExisting();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_TREE && resultCode == RESULT_OK && data != null
                && data.getData() != null) {
            Uri uri = data.getData();
            int flags = data.getFlags()
                    & (Intent.FLAG_GRANT_READ_URI_PERMISSION
                    | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            try {
                getContentResolver().takePersistableUriPermission(uri, flags);
            } catch (SecurityException error) {
                Ui.error(this, error);
                return;
            }
            treeUri = uri.toString();
            treeName = queryDisplayName(uri);
            updateTypeUi();
        }
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private void loadExisting() {
        String serialized = getIntent().getStringExtra("folder");
        if (serialized == null) return;
        try {
            existing = new JSONObject(serialized);
            name.setText(existing.optString("name"));
            include.setText(existing.optString("include"));
            exclude.setText(existing.optString("exclude"));
            enabled.setChecked(existing.optBoolean("enabled", true));
            path.setText(existing.optString("path"));
            String folderId = existing.optString("id");
            StorageBridge.BridgeConfig bridge = app.storageBridge().get(folderId);
            if (bridge != null) {
                treeUri = bridge.treeUri;
                treeName = bridge.displayName;
                storageType.setSelection(5);
            } else {
                storageType.setSelection(4);
            }
        } catch (Exception error) {
            Ui.error(this, error);
        }
        updateTypeUi();
    }

    private void pickTree() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION
                        | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, PICK_TREE);
    }

    private void updateTypeUi() {
        int type = storageType.getSelectedItemPosition();
        selectTree.setVisibility(type == 5 ? View.VISIBLE : View.GONE);
        path.setVisibility(type == 4 ? View.VISIBLE : View.GONE);
        if (type == 5) {
            storageDetail.setText(treeUri == null
                    ? "尚未选择目录。SAF 内容会镜像到应用私有目录，rustsync 直接操作该目录。"
                    : "已选择：" + treeName + "\n" + treeUri);
        } else if (type == 4) {
            storageDetail.setText("适用于已 root、Termux、su 挂载点或应用可直接访问的绝对路径。");
        } else {
            storageDetail.setText("目录由应用创建并交给 rustsync 原生文件系统访问。");
        }
    }

    private void save() {
        try {
            String folderName = name.getText().toString().trim();
            if (folderName.isEmpty()) {
                throw new IOException("请输入文件夹名称");
            }
            int type = storageType.getSelectedItemPosition();
            String nativePath;
            if (type == 4) {
                nativePath = path.getText().toString().trim();
            } else if (type == 5) {
                if (treeUri == null) {
                    throw new IOException("请先选择系统文件/云文档目录");
                }
                nativePath = safMirror(treeUri).getAbsolutePath();
            } else {
                nativePath = createAppDirectory(type, folderName).getAbsolutePath();
            }
            File directory = new File(nativePath);
            if (!directory.isAbsolute()) {
                throw new IOException("目录必须是绝对路径");
            }
            if (!directory.exists() && !directory.mkdirs()) {
                throw new IOException("无法创建目录：" + directory);
            }
            if (!directory.isDirectory()) {
                throw new IOException("路径不是目录：" + directory);
            }

            JSONObject payload = new JSONObject()
                    .put("name", folderName)
                    .put("path", directory.getAbsolutePath())
                    .put("include", emptyToNull(include.getText().toString()))
                    .put("exclude", emptyToNull(exclude.getText().toString()))
                    .put("enabled", enabled.isChecked());
            JSONObject response;
            String folderId;
            if (existing == null) {
                response = app.api().post("/api/v1/folders", payload);
                folderId = response.getJSONObject("folder").getString("id");
            } else {
                folderId = existing.getString("id");
                response = app.api().put("/api/v1/folders/" + folderId, payload);
            }
            if (type == 5) {
                app.storageBridge().put(new StorageBridge.BridgeConfig(
                        folderId,
                        treeUri,
                        treeName == null ? folderName : treeName,
                        directory.getAbsolutePath(),
                        enabled.isChecked()));
            } else {
                app.storageBridge().remove(folderId);
            }
            runOnUiThread(() -> {
                Ui.toast(this, "文件夹已保存");
                setResult(RESULT_OK);
                finish();
            });
        } catch (Exception error) {
            runOnUiThread(() -> Ui.error(this, error));
        }
    }

    private File createAppDirectory(int type, String folderName) throws IOException {
        File base;
        switch (type) {
            case 0:
                base = getFilesDir();
                break;
            case 1:
                base = getExternalFilesDir(null);
                break;
            case 2:
                base = getCacheDir();
                break;
            case 3:
                base = getExternalCacheDir();
                break;
            default:
                throw new IOException("未知目录类型");
        }
        if (base == null) {
            throw new IOException("此设备没有对应的存储卷");
        }
        return new File(base, "rustsync-folders/" + safeName(folderName));
    }

    private File safMirror(String uri) {
        return new File(getFilesDir(), "saf-mirror/" + safeName(uri));
    }

    private String queryDisplayName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(
                uri,
                new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME},
                null, null, null)) {
            return cursor != null && cursor.moveToFirst()
                    ? cursor.getString(0)
                    : uri.getLastPathSegment();
        } catch (Exception ignored) {
            return uri.getLastPathSegment();
        }
    }

    private static String safeName(String value) {
        String safe = value.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9._-]+", "-")
                .replaceAll("^-+|-+$", "");
        return safe.isEmpty() ? "folder-" + UUID.randomUUID() : safe.substring(0, Math.min(48, safe.length()));
    }

    private static Object emptyToNull(String value) throws JSONException {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.isEmpty() ? JSONObject.NULL : trimmed;
    }
}
