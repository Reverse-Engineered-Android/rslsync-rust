package org.rustsync.android;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class SettingsActivity extends Activity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private RustsyncApi api;
    private EditText baseUrl;
    private EditText token;
    private EditText password;
    private EditText exemptIps;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);
        RustSyncApplication app = (RustSyncApplication) getApplication();
        api = app.api();
        baseUrl = findViewById(R.id.base_url);
        token = findViewById(R.id.token);
        password = findViewById(R.id.password);
        exemptIps = findViewById(R.id.exempt_ips);
        baseUrl.setText(api.baseUrl());
        token.setText(api.token());

        Button saveClient = findViewById(R.id.save_client);
        saveClient.setOnClickListener(view -> {
            api.setBaseUrl(baseUrl.getText().toString());
            api.setToken(token.getText().toString());
            Ui.toast(this, "客户端连接已保存");
        });
        findViewById(R.id.login).setOnClickListener(view -> executor.execute(this::login));
        findViewById(R.id.logout).setOnClickListener(view -> executor.execute(this::logout));
        findViewById(R.id.save_server).setOnClickListener(view -> executor.execute(this::saveServer));
        findViewById(R.id.clear_password).setOnClickListener(view -> executor.execute(this::clearPassword));
        executor.execute(this::load);
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private void load() {
        try {
            JSONObject settings = api.get("/api/v1/settings");
            runOnUiThread(() -> {
                JSONArray values = settings.optJSONArray("password_exempt_ips");
                if (values != null) {
                    StringBuilder text = new StringBuilder();
                    for (int index = 0; index < values.length(); index++) {
                        if (index > 0) text.append(", ");
                        text.append(values.optString(index));
                    }
                    exemptIps.setText(text);
                }
            });
        } catch (Exception error) {
            runOnUiThread(() -> Ui.error(this, error));
        }
    }

    private void login() {
        try {
            JSONObject body = new JSONObject().put("password", password.getText().toString());
            JSONObject result = api.post("/api/v1/auth/login", body);
            String session = result.optString("token", "");
            if (!session.isEmpty()) {
                api.setToken(session);
            }
            runOnUiThread(() -> Ui.toast(this, "登录成功"));
        } catch (Exception error) {
            runOnUiThread(() -> Ui.error(this, error));
        }
    }

    private void logout() {
        try {
            api.post("/api/v1/auth/logout", null);
            api.setToken("");
            runOnUiThread(() -> Ui.toast(this, "已退出登录"));
        } catch (Exception error) {
            runOnUiThread(() -> Ui.error(this, error));
        }
    }

    private void saveServer() {
        try {
            JSONObject body = new JSONObject();
            String newPassword = password.getText().toString();
            if (!newPassword.isEmpty()) {
                body.put("password", newPassword);
            }
            String ips = exemptIps.getText().toString().trim();
            if (!ips.isEmpty()) {
                JSONArray values = new JSONArray();
                for (String value : ips.split(",")) {
                    if (!value.trim().isEmpty()) values.put(value.trim());
                }
                body.put("password_exempt_ips", values);
            }
            api.put("/api/v1/settings", body);
            runOnUiThread(() -> Ui.toast(this, "服务器设置已保存"));
        } catch (Exception error) {
            runOnUiThread(() -> Ui.error(this, error));
        }
    }

    private void clearPassword() {
        try {
            api.delete("/api/v1/password");
            runOnUiThread(() -> Ui.toast(this, "服务器密码已清除"));
        } catch (Exception error) {
            runOnUiThread(() -> Ui.error(this, error));
        }
    }
}
