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
            })),
        )
        .unwrap();
    assert_eq!(created["name"], json!("Documents"));

    let scanned: Value = authenticated
        .call(
            "POST",
            &format!("/api/v1/folders/{}/scan", created["id"].as_str().unwrap()),
            None::<&Value>,
        )
        .unwrap();
    assert_eq!(scanned["scan"]["file_count"], json!(1));
    assert!(folder.join(".rustsync-manifest.json").is_file());
}
