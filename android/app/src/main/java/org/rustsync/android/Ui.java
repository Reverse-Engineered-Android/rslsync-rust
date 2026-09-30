package org.rustsync.android;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;

final class Ui {
    private Ui() {
    }

    static void toast(Context context, String message) {
        Toast.makeText(context, message, Toast.LENGTH_LONG).show();
    }

    static void error(Context context, Throwable error) {
        toast(context, message(error));
    }

    static String message(Throwable error) {
        if (error == null) {
            return "未知错误";
        }
        String message = error.getMessage();
        return message == null || message.trim().isEmpty()
                ? error.getClass().getSimpleName()
                : message;
    }

    static void output(Activity activity, String title, String text) {
        TextView view = new TextView(activity);
        view.setText(text);
        view.setTextSize(12);
        view.setPadding(32, 24, 32, 24);
        view.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(activity);
        scroll.addView(view);
        new AlertDialog.Builder(activity)
                .setTitle(title)
                .setView(scroll)
                .setPositiveButton("关闭", null)
                .show();
    }

    static String pretty(Object value) {
        try {
            if (value instanceof JSONObject) {
                return ((JSONObject) value).toString(2);
            }
            if (value instanceof JSONArray) {
                return ((JSONArray) value).toString(2);
            }
        } catch (JSONException ignored) {
        }
        return String.valueOf(value);
    }

    static String stack(Throwable error) {
        StringWriter writer = new StringWriter();
        error.printStackTrace(new PrintWriter(writer));
        return writer.toString();
    }
}
