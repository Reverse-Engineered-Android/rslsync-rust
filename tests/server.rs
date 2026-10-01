use rustsync::client::RemoteClient;
use rustsync::server::{ServerOptions, WebServer};
use serde_json::{json, Value};
use std::fs;
use tempfile::tempdir;

#[test]
fn serves_authenticated_folder_management() {
    let temp = tempdir().unwrap();
    let folder = temp.path().join("documents");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("readme.md"), b"rustsync server").unwrap();

    let server = WebServer::bind(ServerOptions::new(
        "127.0.0.1:0",
        temp.path().join("state.json"),
    ))
    .unwrap();
    let address = server.local_addr().unwrap();
    server.spawn();

    let base_url = format!("http://{address}");
    let mut bootstrap = RemoteClient::new(&base_url, None, None).unwrap();
    let status: Value = bootstrap
        .call("GET", "/api/v1/status", None::<&Value>)
        .unwrap();
    assert_eq!(status["authenticated"], json!(true));

    bootstrap
        .call::<Value>(
            "PUT",
            "/api/v1/settings",
            Some(&json!({
                "password": "server-pass",
                "password_exempt_ips": ["192.0.2.10/32"],
            })),
        )
        .unwrap();

    let mut unauthenticated = RemoteClient::new(&base_url, None, None).unwrap();
    assert!(unauthenticated
        .call::<Value>("GET", "/api/v1/settings", None::<&Value>)
        .is_err());

    let mut authenticated = RemoteClient::new(&base_url, None, Some("server-pass".into())).unwrap();
    let created: Value = authenticated
        .call(
            "POST",
            "/api/v1/folders",
            Some(&json!({
                "name": "Documents",
                "path": folder,
                "include": "*.md",
                "exclude": "private/**",
                "enabled": true,
                "sync": {
                    "access": "read-write",
                    "peers": ["127.0.0.1:22000"],
                    "auto_sync": false,
                    "sync_interval_seconds": 60
                }
            })),
        )
        .unwrap();
    assert_eq!(created["name"], json!("Documents"));
    assert_eq!(created["folder"]["name"], json!("Documents"));
    assert!(created["link"].as_str().unwrap().starts_with("rustsync://"));
    assert!(created["folder"]["sync"]["share_id"].is_string());
    assert!(created["folder"]["sync"].get("key").is_none());

    let scanned: Value = authenticated
        .call(
            "POST",
            &format!("/api/v1/folders/{}/scan", created["id"].as_str().unwrap()),
            None::<&Value>,
        )
        .unwrap();
    assert_eq!(scanned["scan"]["file_count"], json!(1));
    assert!(folder.join(".rustsync-manifest.json").is_file());

    let read_only: Value = authenticated
        .call(
            "POST",
            &format!(
                "/api/v1/folders/{}/links/generate",
                created["id"].as_str().unwrap()
            ),
            Some(&json!({"access": "read-only"})),
        )
        .unwrap();
    assert_eq!(read_only["folder"]["sync"]["access"], json!("read-write"));
    assert_eq!(
        read_only["folder"]["sync"]["share_id"],
        created["folder"]["sync"]["share_id"]
    );
    assert!(read_only["link"]
        .as_str()
        .unwrap()
        .contains("access=read-only"));

    let status: Value = authenticated
        .call(
            "GET",
            &format!("/api/v1/folders/{}/sync", created["id"].as_str().unwrap()),
            None::<&Value>,
        )
        .unwrap();
    assert_eq!(status["running"], json!(false));
    assert!(status["runs"].as_array().unwrap().is_empty());
}

#[test]
fn rejects_unsupported_share_keys_as_caller_error() {
    let temp = tempdir().unwrap();
    let folder = temp.path().join("folder");
    fs::create_dir(&folder).unwrap();

    let server = WebServer::bind(ServerOptions::new(
        "127.0.0.1:0",
        temp.path().join("state.json"),
    ))
    .unwrap();
    let address = server.local_addr().unwrap();
    server.spawn();

    let base_url = format!("http://{address}");
    let mut client = RemoteClient::new(&base_url, None, None).unwrap();

    // Advanced Folder keys (G/H) are deliberately unsupported and must be
    // reported as caller error, not masked behind a generic 500.
    for key in [
        "GJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ",
        "HJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ",
    ] {
        let error = client
            .call::<Value>(
                "POST",
                "/api/v1/folders",
                Some(&json!({"name": "advanced", "path": folder, "sync": {"key": key}})),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("HTTP 400"), "{key}: {error}");
        assert!(error.contains("invalid_key"), "{key}: {error}");
        assert!(
            error.contains("Advanced Folder keys are not supported"),
            "{key}: {error}"
        );
    }

    // An unknown key type is also a caller error.
    let error = client
        .call::<Value>(
            "POST",
            "/api/v1/folders",
            Some(&json!({"name": "garbage", "path": folder, "sync": {"key": "XNOTAKEY"}})),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("HTTP 400"), "{error}");
    assert!(error.contains("invalid_key"), "{error}");

    // A valid standard read-write key still succeeds.
    let created: Value = client
        .call(
            "POST",
            "/api/v1/folders",
            Some(&json!({
                "name": "standard",
                "path": folder,
                "sync": {"key": "AJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ"}
            })),
        )
        .unwrap();
    assert_eq!(created["folder"]["sync"]["key_type"], json!("A"));
}

#[test]
fn exposes_derived_key_roles_for_each_share_key_family() {
    let temp = tempdir().unwrap();
    let server = WebServer::bind(ServerOptions::new(
        "127.0.0.1:0",
        temp.path().join("state.json"),
    ))
    .unwrap();
    let address = server.local_addr().unwrap();
    server.spawn();

    let base_url = format!("http://{address}");
    let mut client = RemoteClient::new(&base_url, None, None).unwrap();

    // Encrypt-capable read-write key: all three roles are available.
    let d = temp.path().join("d");
    fs::create_dir(&d).unwrap();
    let folder: Value = client
        .call(
            "POST",
            "/api/v1/folders",
            Some(&json!({
                "name": "d",
                "path": d,
                "sync": {"key": "DJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ"}
            })),
        )
        .unwrap();
    let keys = &folder["folder"]["sync"]["keys"];
    assert_eq!(
        keys["read_write"],
        json!("DJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ")
    );
    assert_eq!(
        keys["read_only"],
        json!("EH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZDZR47LKBWQANFZSCU5CTMTFG3CI")
    );
    assert_eq!(
        keys["encrypted"],
        json!("FH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZD")
    );

    // Read-only key: read-only plus the matching encrypted key, no read-write.
    let e = temp.path().join("e");
    fs::create_dir(&e).unwrap();
    let folder: Value = client
        .call(
            "POST",
            "/api/v1/folders",
            Some(&json!({
                "name": "e",
                "path": e,
                "sync": {"key": "EH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZDZR47LKBWQANFZSCU5CTMTFG3CI"}
            })),
        )
        .unwrap();
    let keys = &folder["folder"]["sync"]["keys"];
    assert!(keys.get("read_write").is_none());
    assert_eq!(
        keys["encrypted"],
        json!("FH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZD")
    );

    // Standard read-only key: read-only only; the family has no encrypted role.
    let b = temp.path().join("b");
    fs::create_dir(&b).unwrap();
    let folder: Value = client
        .call(
            "POST",
            "/api/v1/folders",
            Some(&json!({
                "name": "b",
                "path": b,
                "sync": {"key": "BJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ"}
            })),
        )
        .unwrap();
    let keys = &folder["folder"]["sync"]["keys"];
    assert!(keys.get("read_write").is_none());
    assert!(keys.get("encrypted").is_none());
    assert_eq!(
        keys["read_only"],
        json!("BJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ")
    );
}
