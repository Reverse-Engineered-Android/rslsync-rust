package org.rustsync.android;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public final class RustsyncApi {
    private static final String PREFS = "rustsync_api";
    private final SharedPreferences preferences;

    public RustsyncApi(Context context) {
        preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public String baseUrl() {
        return preferences.getString("base_url", "http://127.0.0.1:8787");
    }

    public void setBaseUrl(String value) {
        preferences.edit().putString("base_url", trimTrailingSlash(value)).apply();
    }

    public String token() {
        return preferences.getString("token", "");
    }

    public void setToken(String value) {
        preferences.edit().putString("token", value == null ? "" : value.trim()).apply();
    }

    public JSONObject get(String path) throws IOException, JSONException {
        return request("GET", path, null);
    }

    public JSONObject post(String path, JSONObject body) throws IOException, JSONException {
        return request("POST", path, body == null ? new JSONObject() : body);
    }

    public JSONObject put(String path, JSONObject body) throws IOException, JSONException {
        return request("PUT", path, body == null ? new JSONObject() : body);
    }

    public JSONObject delete(String path) throws IOException, JSONException {
        return request("DELETE", path, null);
    }

    private JSONObject request(String method, String path, JSONObject body)
            throws IOException, JSONException {
        URL url = new URL(baseUrl() + path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method);
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(600_000);
        connection.setRequestProperty("Accept", "application/json");
        if (!token().isEmpty()) {
            connection.setRequestProperty("Authorization", "Bearer " + token());
        }
        if (body != null) {
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setFixedLengthStreamingMode(bytes.length);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(bytes);
            }
        }
        int status = connection.getResponseCode();
        InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
        String responseText = readAll(stream);
        JSONObject response = parseObject(responseText);
        if (status < 200 || status >= 300) {
            throw new ApiException(status, response);
        }
        return response;
    }

    private static String readAll(InputStream stream) throws IOException {
        if (stream == null) {
            return "{}";
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }
            return output.toString();
        }
    }

    private static JSONObject parseObject(String text) throws JSONException {
        String trimmed = text.trim();
        if (trimmed.isEmpty()) {
            return new JSONObject();
        }
        return new JSONObject(trimmed);
    }

    private static String trimTrailingSlash(String value) {
        String result = value == null ? "" : value.trim();
        while (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    public static final class ApiException extends IOException {
        public final int status;
        public final JSONObject response;

        private ApiException(int status, JSONObject response) {
            super(errorMessage(status, response));
            this.status = status;
            this.response = response;
        }

        private static String errorMessage(int status, JSONObject response) {
            try {
                JSONObject error = response.optJSONObject("error");
                if (error != null && error.has("message")) {
                    return status + ": " + error.getString("message");
                }
            } catch (JSONException ignored) {
            }
            return "HTTP " + status;
        }
    }

    public static JSONArray folders(JSONObject response) {
        JSONArray folders = response.optJSONArray("folders");
        return folders == null ? new JSONArray() : folders;
    }
}
