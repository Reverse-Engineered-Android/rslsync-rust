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

/// Fetch a static asset as text with a bare HTTP/1.1 request, so the test does
/// not depend on an external client being installed.
fn get_text(address: std::net::SocketAddr, path: &str) -> String {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default()
}

#[test]
fn reports_add_folder_input_errors_as_caller_errors() {
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

    let d = "DJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ";
    let e = "EH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZDZR47LKBWQANFZSCU5CTMTFG3CI";

    // Every one of these is reachable from the add-folder form. A generic 500
    // told the console nothing, so each must carry its own 4xx status and code.
    let cases: Vec<(&str, Value, u16, &str)> = vec![
        (
            "empty key field",
            json!({"name": "f", "path": folder, "sync": {"link": ""}}),
            400,
            "invalid_request",
        ),
        (
            "link and key together",
            json!({"name": "f", "path": folder, "sync": {"link": d, "key": d}}),
            400,
            "invalid_request",
        ),
        (
            "path that does not exist",
            json!({
                "name": "f",
                "path": temp.path().join("missing"),
                "sync": {"link": d}
            }),
            400,
            "invalid_request",
        ),
        (
            "relative path",
            json!({"name": "f", "path": "relative/folder", "sync": {"link": d}}),
            400,
            "invalid_request",
        ),
        (
            "blank name",
            json!({"name": "   ", "path": folder, "sync": {"link": d}}),
            400,
            "invalid_request",
        ),
        (
            "sync interval below the minimum",
            json!({
                "name": "f",
                "path": folder,
                "sync": {"link": d, "sync_interval_seconds": 5}
            }),
            400,
            "invalid_request",
        ),
        (
            "access contradicting the key",
            json!({"name": "f", "path": folder, "sync": {"link": e, "access": "read-write"}}),
            400,
            "invalid_request",
        ),
        (
            "encrypted-only folder without a key",
            json!({"name": "f", "path": folder, "sync": {"access": "encrypted-only"}}),
            400,
            "invalid_request",
        ),
        (
            "Advanced Folder key",
            json!({"name": "f", "path": folder, "sync": {"link": "GJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ"}}),
            400,
            "invalid_key",
        ),
    ];

    for (label, body, status, code) in cases {
        let error = client
            .call::<Value>("POST", "/api/v1/folders", Some(&body))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("HTTP {status}")),
            "{label}: expected {status}, got {error}"
        );
        assert!(
            error.contains(code),
            "{label}: expected {code}, got {error}"
        );
        assert!(
            !error.contains("HTTP 500"),
            "{label}: caller error masked as a server fault: {error}"
        );
    }

    // A duplicate path is a conflict rather than a malformed request, but it is
    // still the caller's fault and must not surface as a 500.
    let body = json!({"name": "dup", "path": folder, "sync": {"link": d}});
    client
        .call::<Value>("POST", "/api/v1/folders", Some(&body))
        .unwrap();
    let error = client
        .call::<Value>("POST", "/api/v1/folders", Some(&body))
        .unwrap_err()
        .to_string();
    assert!(error.contains("HTTP 409"), "{error}");
    assert!(error.contains("conflict"), "{error}");
}

#[test]
fn reports_key_generation_input_errors_as_caller_errors() {
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

    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "unknown key family",
            json!({"read_write": true, "key_family": "nonsense"}),
            "invalid_request",
        ),
        (
            "read-only encrypt-capable",
            json!({"read_write": false, "key_family": "encrypt-capable"}),
            "invalid_request",
        ),
        (
            "unknown derived role",
            json!({"from": "DJMJ5MWYMBKS5SCWMBRQ7LXBGZAQGLSAQ", "derive": "bogus"}),
            "invalid_request",
        ),
        (
            "read-write derived from a read-only key",
            json!({
                "from": "EH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZDZR47LKBWQANFZSCU5CTMTFG3CI",
                "derive": "read-write"
            }),
            "invalid_key",
        ),
    ];

    for (label, body, code) in cases {
        let error = client
            .call::<Value>("POST", "/api/v1/operations/keys/generate", Some(&body))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("HTTP 400"),
            "{label}: expected 400, got {error}"
        );
        assert!(
            error.contains(code),
            "{label}: expected {code}, got {error}"
        );
    }
}

#[test]
fn returns_the_share_link_when_a_folder_is_created() {
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

    // The console copies `result.link` right after a create, so it must be a
    // top-level sibling of `folder` and carry the freshly generated key.
    let created: Value = client
        .call(
            "POST",
            "/api/v1/folders",
            Some(&json!({
                "name": "generated",
                "path": folder,
                "sync": {"access": "read-write"}
            })),
        )
        .unwrap();
    let link = created["link"]
        .as_str()
        .expect("folder creation returns the share link");
    assert!(link.starts_with("rustsync://"), "{link}");
    let key = created["folder"]["sync"]["keys"]["read_write"]
        .as_str()
        .expect("a generated read-write folder exposes its key");
    assert!(link.contains(key), "link {link} does not carry key {key}");
}

#[test]
fn web_console_reads_the_share_link_from_the_create_response() {
    let temp = tempdir().unwrap();
    let server = WebServer::bind(ServerOptions::new(
        "127.0.0.1:0",
        temp.path().join("state.json"),
    ))
    .unwrap();
    let address = server.local_addr().unwrap();
    server.spawn();

    // The console is served from an embedded asset, so a regression here would
    // otherwise only show up in a browser. `link` is a sibling of `folder` in
    // the create response; reading it under `folder` silently skipped the copy
    // and left the generated link invisible.
    let app_js = get_text(address, "/app.js");
    assert!(
        !app_js.is_empty(),
        "the server did not serve the web console script"
    );
    assert!(
        !app_js.contains("result.folder.link"),
        "the console still reads the link from the wrong level"
    );
    assert!(
        app_js.contains("result.link"),
        "the console no longer reads the top-level link"
    );
    // A denied clipboard is a convenience failure, not an action failure.
    assert!(
        app_js.contains("copyToClipboard"),
        "clipboard access is not best-effort"
    );
}
