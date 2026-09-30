package org.rustsync.android;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ToolsActivity extends Activity {
    private static final String[] OPERATIONS = {
            "扫描目录（scan）",
            "应用清单（apply）",
            "拉取目录（pull）",
            "生成分享密钥（generate-key）",
            "检查分享密钥（inspect-key）",
            "编码 LAN 发现 Ping（encode-ping）",
            "加密目录（encrypt-tree）",
            "解密保险库（decrypt-tree）",
            "Tracker announce",
            "启动原生协议服务（serve）",
            "启动上游 3.1.2 服务（serve-upstream）",
            "持续连接上游（connect-upstream）",
            "启动独立 Tracker（tracker-serve）"
    };

    private static final String[] HELP = {
            "生成确定性 JSON 清单；可在服务端 REST 核心直接执行。",
            "校验清单并原子复制；支持覆盖/保留冲突与 POSIX 权限策略。",
            "通过 rustsync 原生 manifest/piece 协议拉取目录。",
            "生成兼容上游的只读 B 或读写 A 分享密钥。",
            "只显示密钥类型、share ID 和 TLS 兼容信息，不打印秘密。",
            "生成上游 LAN discovery 的十六进制 Ping 数据包。",
            "将目录打包成经过认证的加密 vault。",
            "验证口令并从加密 vault 恢复目录。",
            "向 HTTP tracker announce 并显示紧凑 peer 列表。",
            "直接启动内置二进制的原生协议监听进程。",
            "直接启动 SRPEH/Bencode、TLS-PSK、发现和 tracker 监听进程。",
            "直接启动持续重连并双向同步的上游连接进程。",
            "直接启动独立 HTTP tracker 监听进程。"
    };

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private RustSyncApplication app;
    private Spinner operation;
    private TextView help;
    private LinearLayout form;
    private final List<Field> fields = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_tools);
        app = (RustSyncApplication) getApplication();
        operation = findViewById(R.id.operation);
        help = findViewById(R.id.operation_help);
        form = findViewById(R.id.form);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, OPERATIONS);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        operation.setAdapter(adapter);
        operation.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                renderForm(position);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
        Button run = findViewById(R.id.run);
        run.setOnClickListener(view -> {
            run.setEnabled(false);
            executor.execute(() -> {
                try {
                    runOperation(operation.getSelectedItemPosition());
                } catch (Exception error) {
                    runOnUiThread(() -> Ui.error(this, error));
                } finally {
                    runOnUiThread(() -> run.setEnabled(true));
                }
            });
        });
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private void renderForm(int operationIndex) {
        fields.clear();
        form.removeAllViews();
        help.setText(HELP[operationIndex]);
        switch (operationIndex) {
            case 0:
                addText("root", "根目录绝对路径", true);
                addText("output", "清单输出（可选）", false);
                addText("include", "包含规则（可选）", false);
                addText("exclude", "排除规则（可选）", false);
                break;
            case 1:
                addText("source", "源目录", true);
                addText("target", "目标目录", true);
                addText("manifest", "清单路径（可选）", false);
                addText("conflict", "冲突策略 overwrite/preserve", true, "overwrite");
                addText("permissions", "权限策略 preserve/ignore/check", true, "preserve");
                break;
            case 2:
                addText("address", "对端 host:port", true);
                addText("target", "目标目录", true);
                addPassword("key", "分享密钥", true);
                break;
            case 3:
                addBoolean("read_write", "生成读写 A 密钥", true);
                break;
            case 4:
                addPassword("key", "分享密钥", true);
                break;
            case 5:
                addText("peer_id", "20 字节 peer ID（40 hex）", true);
                addInteger("port", "监听端口", true);
                addCsv("share_ids", "20 字节 share ID 列表", true);
                break;
            case 6:
            case 7:
                addText("source", "源目录/vault", true);
                addText("destination", "目标 vault/目录", true);
                addPassword("passphrase", "口令", true);
                break;
            case 8:
                addText("url", "Tracker URL", true);
                addText("info_hash", "20 字节 info hash（40 hex）", true);
                addText("peer_id", "20 字节 peer ID（40 hex）", true);
                addInteger("port", "监听端口", true);
                addInteger("uploaded", "uploaded 字节", true, "0");
                addInteger("downloaded", "downloaded 字节", true, "0");
                addInteger("left", "left 字节", true, "0");
                addText("event", "event（可选）", false);
                break;
            case 9:
                addText("root", "共享根目录", true);
                addText("listen", "监听地址", true, "127.0.0.1:0");
                addPassword("key", "分享密钥", true);
                break;
            case 10:
            case 11:
                addText("root", "同步根目录", true);
                if (operationIndex == 10) {
                    addText("listen", "监听地址", true, "0.0.0.0:57301");
                } else {
                    addText("address", "对端 host:port", true);
                }
                addPassword("key", "分享密钥", true);
                addText("device_name", "设备名称", true, "rustsync-android");
                addText("peer_id", "20 字节 peer ID（可选）", false);
                if (operationIndex == 10) {
                    addBoolean("no_discovery", "禁用 LAN discovery", false);
                }
                addText("include", "包含规则（可选）", false);
                addText("exclude", "排除规则（可选）", false);
                addCsv("trackers", "Tracker URL 列表（可选）", false);
                break;
            case 12:
                addText("listen", "监听地址", true, "0.0.0.0:8000");
                break;
            default:
                throw new IllegalStateException("unknown operation");
        }
    }

    private void addText(String key, String hint, boolean required) {
        addText(key, hint, required, "");
    }

    private void addText(String key, String hint, boolean required, String defaultValue) {
        addEdit(key, hint, required, defaultValue, InputType.TYPE_CLASS_TEXT, false);
    }

    private void addPassword(String key, String hint, boolean required) {
        addEdit(key, hint, required, "", InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_PASSWORD, false);
    }

    private void addInteger(String key, String hint, boolean required) {
        addInteger(key, hint, required, "");
    }

    private void addInteger(String key, String hint, boolean required, String defaultValue) {
        addEdit(key, hint, required, defaultValue,
                InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_SIGNED, false);
    }

    private void addCsv(String key, String hint, boolean required) {
        addEdit(key, hint, required, "", InputType.TYPE_CLASS_TEXT, true);
    }

    private void addEdit(
            String key,
            String hint,
            boolean required,
            String defaultValue,
            int inputType,
            boolean csv) {
        EditText edit = new EditText(this);
        edit.setHint(hint);
        edit.setInputType(inputType);
        edit.setText(defaultValue);
        edit.setGravity(Gravity.START);
        form.addView(edit, matchWrap());
        fields.add(new Field(key, required, csv ? FieldKind.CSV : FieldKind.TEXT, edit, null));
    }

    private void addBoolean(String key, String hint, boolean defaultValue) {
        CheckBox check = new CheckBox(this);
        check.setText(hint);
        check.setChecked(defaultValue);
        form.addView(check, matchWrap());
        fields.add(new Field(key, false, FieldKind.BOOLEAN, null, check));
    }

    private void runOperation(int index) throws Exception {
        if (index <= 8) {
            JSONObject payload = collectJson();
            String path;
            switch (index) {
                case 0: path = "/api/v1/operations/scan"; break;
                case 1: path = "/api/v1/operations/apply"; break;
                case 2: path = "/api/v1/operations/pull"; break;
                case 3: path = "/api/v1/operations/keys/generate"; break;
                case 4: path = "/api/v1/operations/keys/inspect"; break;
                case 5: path = "/api/v1/operations/ping/encode"; break;
                case 6: path = "/api/v1/operations/vault/encrypt"; break;
                case 7: path = "/api/v1/operations/vault/decrypt"; break;
                case 8: path = "/api/v1/operations/tracker/announce"; break;
                default: throw new IllegalStateException("unknown REST operation");
            }
            if (!app.serverManager().isRunning()) {
                app.serverManager().start();
            }
            JSONObject result = app.api().post(path, payload);
            runOnUiThread(() -> Ui.output(this, "执行成功", Ui.pretty(result)));
            return;
        }

        JSONObject values = collectJson();
        List<String> args = new ArrayList<>();
        String label;
        switch (index) {
            case 9:
                label = "rustsync serve";
                args.addAll(Arrays.asList("serve", values.getString("root"),
                        "--listen", values.getString("listen"), "--key", values.getString("key")));
                break;
            case 10:
                label = "rustsync serve-upstream";
                args.add("serve-upstream");
                addUpstreamArgs(args, values, true);
                break;
            case 11:
                label = "rustsync connect-upstream";
                args.add("connect-upstream");
                addUpstreamArgs(args, values, false);
                break;
            case 12:
                label = "rustsync tracker-serve";
                args.addAll(Arrays.asList("tracker-serve", "--listen", values.getString("listen")));
                break;
            default:
                throw new IllegalStateException("unknown process operation");
        }
        ManagedProcess process = app.processSupervisor().start(
                label, args, app.workDirectory());
        runOnUiThread(() -> Ui.output(this, "进程已启动",
                "ID: " + process.id + "\n\n" + String.join(" ", process.command)
                        + "\n\n可在“进程”页面停止并查看实时日志。"));
    }

    private static void addUpstreamArgs(List<String> args, JSONObject values, boolean server)
            throws JSONException {
        args.add(values.getString("root"));
        if (server) {
            args.addAll(Arrays.asList("--listen", values.getString("listen")));
        } else {
            args.add(values.getString("address"));
        }
        args.addAll(Arrays.asList("--key", values.getString("key")));
        args.addAll(Arrays.asList("--device-name", values.getString("device_name")));
        if (values.has("peer_id")) {
            args.addAll(Arrays.asList("--peer-id", values.getString("peer_id")));
        }
        if (server && values.optBoolean("no_discovery")) {
            args.add("--no-discovery");
        }
        if (values.has("include")) {
            args.addAll(Arrays.asList("--include", values.getString("include")));
        }
        if (values.has("exclude")) {
            args.addAll(Arrays.asList("--exclude", values.getString("exclude")));
        }
        if (values.has("trackers")) {
            JSONArray trackers = values.getJSONArray("trackers");
            for (int index = 0; index < trackers.length(); index++) {
                String tracker = trackers.getString(index).trim();
                if (!tracker.isEmpty()) {
                    args.addAll(Arrays.asList("--tracker", tracker));
                }
            }
        }
    }

    private JSONObject collectJson() throws Exception {
        JSONObject values = new JSONObject();
        for (Field field : fields) {
            Object value;
            if (field.kind == FieldKind.BOOLEAN) {
                value = field.check.isChecked();
            } else {
                String text = field.edit.getText().toString().trim();
                if (text.isEmpty()) {
                    if (field.required) {
                        throw new IllegalArgumentException("请填写：" + field.edit.getHint());
                    }
                    continue;
                }
                if (field.kind == FieldKind.CSV) {
                    JSONArray array = new JSONArray();
                    for (String item : text.split(",")) {
                        if (!item.trim().isEmpty()) array.put(item.trim());
                    }
                    value = array;
                } else if (isIntegerKey(field.key)) {
                    try {
                        value = Long.parseLong(text);
                    } catch (NumberFormatException error) {
                        throw new IllegalArgumentException("数字格式错误：" + field.edit.getHint());
                    }
                } else {
                    value = text;
                }
            }
            values.put(field.key, value);
        }
        return values;
    }

    private static boolean isIntegerKey(String key) {
        return key.equals("port")
                || key.equals("uploaded")
                || key.equals("downloaded")
                || key.equals("left");
    }

    private static ViewGroup.LayoutParams matchWrap() {
        return new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private enum FieldKind {
        TEXT,
        CSV,
        BOOLEAN
    }

    private static final class Field {
        final String key;
        final boolean required;
        final FieldKind kind;
        final EditText edit;
        final CheckBox check;

        Field(String key, boolean required, FieldKind kind, EditText edit, CheckBox check) {
            this.key = key;
            this.required = required;
            this.kind = kind;
            this.edit = edit;
            this.check = check;
        }
    }
}
