package org.rustsync.android;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ProcessesActivity extends Activity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private ProcessSupervisor supervisor;
    private LinearLayout list;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_processes);
        supervisor = ((RustSyncApplication) getApplication()).processSupervisor();
        list = findViewById(R.id.process_list);
        findViewById(R.id.refresh).setOnClickListener(view -> render());
        render();
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }

    private void render() {
        list.removeAllViews();
        for (ManagedProcess process : supervisor.snapshot()) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(0, 24, 0, 24);

            TextView title = new TextView(this);
            title.setText(process.label + "\n" + process.process
                    + (process.alive() ? " · 运行中" : " · 已退出 " + process.exitValue()));
            title.setTextSize(16);
            row.addView(title, matchWrap());

            TextView command = new TextView(this);
            command.setText(String.join(" ", process.command));
            command.setTextSize(11);
            command.setGravity(Gravity.START);
            row.addView(command, matchWrap());

            LinearLayout actions = new LinearLayout(this);
            actions.setOrientation(LinearLayout.HORIZONTAL);
            Button logs = new Button(this);
            logs.setText("日志");
            logs.setOnClickListener(view -> executor.execute(() -> showLogs(process)));
            actions.addView(logs, wrapWrap());
            if (process.alive()) {
                Button stop = new Button(this);
                stop.setText("停止");
                stop.setOnClickListener(view -> {
                    supervisor.stop(process.id);
                    render();
                });
                actions.addView(stop, wrapWrap());
            }
            row.addView(actions, matchWrap());
            list.addView(row, matchWrap());
        }
    }

    private void showLogs(ManagedProcess process) {
        try {
            String text = ProcessSupervisor.tail(process.logFile, 256 * 1024);
            runOnUiThread(() -> Ui.output(this, process.label, text));
        } catch (Exception error) {
            runOnUiThread(() -> Ui.error(this, error));
        }
    }

    private static ViewGroup.LayoutParams matchWrap() {
        return new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private static LinearLayout.LayoutParams wrapWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }
}
