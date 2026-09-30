package org.rustsync.android;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class MainActivity extends Activity {
    private final ScheduledExecutorService executor =
            Executors.newSingleThreadScheduledExecutor();
    private final AtomicBoolean syncing = new AtomicBoolean();
    private RustSyncApplication app;
    private TextView serverStatus;
    private TextView bridgeStatus;
    private Button toggleServer;
    private LinearLayout folderList;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        app = (RustSyncApplication) getApplication();
        serverStatus = findViewById(R.id.server_status);
        bridgeStatus = findViewById(R.id.bridge_status);
        toggleServer = findViewById(R.id.toggle_server);
        folderList = findViewById(R.id.folder_list);

        toggleServer.setOnClickListener(view -> executor.execute(this::toggleServer));
        findViewById(R.id.open_processes).setOnClickListener(
                view -> startActivity(new Intent(this, ProcessesActivity.class)));
        findViewById(R.id.open_tools).setOnClickListener(
                view -> startActivity(new Intent(this, ToolsActivity.class)));
        findViewById(R.id.open_settings).setOnClickListener(
                view -> startActivity(new Intent(this, SettingsActivity.class)));
        findViewById(R.id.add_folder).setOnClickListener(
                view -> startActivity(new Intent(this, FolderActivity.class)));
        findViewById(R.id.sync_saf).setOnClickListener(view -> executor.execute(this::syncSaf));

        executor.scheduleWithFixedDelay(
                this::syncSaf, 2, 15, TimeUnit.MINUTES);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private void refresh() {
        executor.execute(() -> {
            try {
                JSONObject status = app.api().get("/api/v1/status");
                JSONObject health = app.api().get("/api/v1/health");
                JSONArray folders = RustsyncApi.folders(app.api().get("/api/v1/folders"));
                runOnUiThread(() -> renderStatus(status, health, folders));
            } catch (Exception error) {
                runOnUiThread(() -> {
                    serverStatus.setText("服务未连接：" + Ui.message(error)
                            + "\n内置二进制：" + (app.binaryManager().isInstalled() ? "已安装" : "待构建"));
                    toggleServer.setText("启动服务");
                });
            }
        });
    }

    private void renderStatus(JSONObject status, JSONObject health, JSONArray folders) {
        boolean running = app.serverManager().isRunning();
        toggleServer.setText(running ? "停止服务" : "启动服务");
        serverStatus.setText("服务：" + (running ? "运行中" : "已连接/未托管")
                + " · " + app.api().baseUrl()
                + "\n健康：" + health.optBoolean("ok", false)
                + " · 密码：" + (status.optBoolean("password_configured") ? "已设置" : "未设置")
                + " · ABI：" + app.binaryManager().preferredAndroidAbi());
        renderFolders(folders);
    }

    private void renderFolders(JSONArray folders) {
        folderList.removeAllViews();
        for (int index = 0; index < folders.length(); index++) {
            JSONObject folder = folders.optJSONObject(index);
            if (folder == null) continue;
            LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setPadding(24, 20, 24, 20);
            card.setBackgroundColor(0xFFFFFFFF);

            TextView title = new TextView(this);
            title.setText(folder.optString("name", "未命名"));
            title.setTextSize(18);
            title.setTypeface(Typeface.DEFAULT_BOLD);
            card.addView(title, matchWrap());

            TextView path = new TextView(this);
            path.setText(folder.optString("path"));
            path.setTextSize(12);
            path.setGravity(Gravity.START);
            card.addView(path, matchWrap());

            JSONObject scan = folder.optJSONObject("last_scan");
            TextView meta = new TextView(this);
            meta.setText((folder.optBoolean("enabled", true) ? "已启用" : "已停用")
                    + (scan == null ? "" : "\n上次扫描：" + scan.optLong("completed_at")));
            meta.setTextSize(12);
            card.addView(meta, matchWrap());

            LinearLayout actions = new LinearLayout(this);
            actions.setOrientation(LinearLayout.HORIZONTAL);
            actions.addView(actionButton("扫描", view -> executor.execute(() -> scan(folder))), wrapWrap());
            actions.addView(actionButton("编辑", view -> edit(folder)), wrapWrap());
            actions.addView(actionButton("删除", view -> confirmDelete(folder)), wrapWrap());
            card.addView(actions, matchWrap());
            folderList.addView(card, spacedWrap());
        }
    }

    private void toggleServer() {
        try {
            if (app.serverManager().isRunning()) {
                app.serverManager().stop();
                runOnUiThread(() -> Ui.toast(this, "rustsync 服务已停止"));
            } else {
                app.serverManager().start();
                runOnUiThread(() -> Ui.toast(this, "rustsync 服务已启动"));
            }
        } catch (Exception error) {
            runOnUiThread(() -> Ui.error(this, error));
        } finally {
            refresh();
        }
    }

    private void scan(JSONObject folder) {
        try {
            bridgeFor(folder);
            JSONObject result = app.api().post(
                    "/api/v1/folders/" + folder.optString("id") + "/scan", null);
            runOnUiThread(() -> Ui.output(
                    this, "扫描完成", Ui.pretty(result.optJSONObject("scan"))));
        } catch (Exception error) {
            runOnUiThread(() -> Ui.error(this, error));
        }
    }

    private void bridgeFor(JSONObject folder) throws Exception {
        StorageBridge.BridgeConfig bridge =
                app.storageBridge().get(folder.optString("id"));
        if (bridge != null && bridge.enabled) {
            app.storageBridge().sync(bridge, new java.util.ArrayList<>());
        }
    }

    private void syncSaf() {
        if (!syncing.compareAndSet(false, true)) {
            return;
        }
        try {
            StorageBridge.SyncResult result = app.storageBridge().syncAll();
            int count = result.messages.size();
            runOnUiThread(() -> bridgeStatus.setText("SAF 存储桥接：刚同步，"
                    + count + " 项变化"));
            if (count > 0) {
                refresh();
            }
        } catch (Exception error) {
            runOnUiThread(() -> {
                bridgeStatus.setText("SAF 存储桥接失败：" + Ui.message(error));
                Ui.error(this, error);
            });
        } finally {
            syncing.set(false);
        }
    }

    private void edit(JSONObject folder) {
        Intent intent = new Intent(this, FolderActivity.class);
        intent.putExtra("folder", folder.toString());
        startActivity(intent);
    }

    private void confirmDelete(JSONObject folder) {
        new AlertDialog.Builder(this)
                .setTitle("删除文件夹")
                .setMessage("仅移除 rustsync 注册项，不删除文件：" + folder.optString("name"))
                .setNegativeButton("取消", null)
                .setPositiveButton("删除", (dialog, which) -> executor.execute(() -> {
                    try {
                        app.api().delete("/api/v1/folders/" + folder.optString("id"));
                        app.storageBridge().remove(folder.optString("id"));
                        runOnUiThread(() -> {
                            Ui.toast(this, "文件夹注册已删除");
                            refresh();
                        });
                    } catch (Exception error) {
                        runOnUiThread(() -> Ui.error(this, error));
                    }
                }))
                .show();
    }

    private Button actionButton(String label, android.view.View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(12);
        button.setAllCaps(false);
        button.setOnClickListener(listener);
        return button;
    }

    private static ViewGroup.LayoutParams matchWrap() {
        return new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private static LinearLayout.LayoutParams wrapWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private static LinearLayout.LayoutParams spacedWrap() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = 12;
        return params;
    }
}
