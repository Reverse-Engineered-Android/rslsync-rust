use crate::operations::{
    self, ApplyRequest, DecryptTreeRequest, EncodePingRequest, EncryptTreeRequest,
    GenerateKeyRequest, InspectKeyRequest, PullRequest, ScanRequest, TrackerAnnounceRequest,
};
use crate::server_state::{
    FolderRequest, FolderUpdate, ServerStateStore, DEFAULT_PASSWORD_EXEMPT_IPS,
};
use anyhow::{Context, Result};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tiny_http::{Header, Request, Response, Server as HttpServer, StatusCode};

const MAX_REQUEST_BODY: u64 = 1024 * 1024;
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub listen: String,
    pub state_path: PathBuf,
}

impl ServerOptions {
    pub fn new(listen: impl Into<String>, state_path: impl Into<PathBuf>) -> Self {
        Self {
            listen: listen.into(),
            state_path: state_path.into(),
        }
    }
}

struct SessionInfo {
    expires_at: Instant,
}

#[derive(Clone, Debug, Serialize)]
enum Principal {
    Bootstrap,
    LocalExempt { address: IpAddr },
    Token { token: String },
}

pub struct WebServer {
    http: Arc<HttpServer>,
    state: Arc<ServerStateStore>,
    sessions: Arc<Mutex<HashMap<String, SessionInfo>>>,
}

impl WebServer {
    pub fn bind(options: ServerOptions) -> Result<Self> {
        let http = HttpServer::http(&options.listen)
            .map_err(|error| anyhow::anyhow!("bind web server: {error}"))?;
        let state = ServerStateStore::load(options.state_path)?;
        Ok(Self {
            http: Arc::new(http),
            state: Arc::new(state),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.http
            .server_addr()
            .to_ip()
            .context("web server listener has no IP address")
    }

    pub fn serve_forever(self) -> Result<()> {
        self.spawn()
            .join()
            .map_err(|_| anyhow::anyhow!("server thread panicked"))?
    }

    pub fn spawn(self) -> thread::JoinHandle<Result<()>> {
        thread::spawn(move || {
            for request in self.http.incoming_requests() {
                let server = Self {
                    http: Arc::clone(&self.http),
                    state: Arc::clone(&self.state),
                    sessions: Arc::clone(&self.sessions),
                };
                thread::spawn(move || {
                    if let Err(error) = server.handle(request) {
                        eprintln!("web request failed: {error:#}");
                    }
                });
            }
            Ok(())
        })
    }

    fn handle(&self, mut request: Request) -> Result<()> {
        let method = request.method().clone();
        let path = request
            .url()
            .split('?')
            .next()
            .unwrap_or(request.url())
            .to_owned();
        let response = if path.starts_with("/api/") {
            self.handle_api(method.as_str(), &path, &mut request)
        } else if method == tiny_http::Method::Get {
            static_asset(&path)
        } else {
            api_error(405, "method_not_allowed", "method not allowed")
        };
        request.respond(with_security_headers(response))?;
        Ok(())
    }

    fn handle_api(
        &self,
        method: &str,
        path: &str,
        request: &mut Request,
    ) -> Response<std::io::Cursor<Vec<u8>>> {
        match (method, path) {
            ("GET", "/api/v1/status") => self.status_response(client_ip(request)),
            ("GET", "/api/v1/health") => json_response(
                200,
                &serde_json::json!({
                    "ok": true,
                    "version": env!("CARGO_PKG_VERSION"),
                }),
            ),
            ("POST", "/api/v1/auth/login") => self.login(request),
            ("POST", "/api/v1/auth/logout") => self.logout(request),
            ("GET", "/api/v1/settings") => {
                self.authorized(request, |_, _, _| self.settings_response())
            }
            ("PUT", "/api/v1/settings") => {
                self.authorized(request, |server, principal, request| {
                    match server.read_json(request) {
                        Ok(body) => server.update_settings(principal, body),
                        Err(response) => response,
                    }
                })
            }
            ("DELETE", "/api/v1/password") => {
                self.authorized(request, |server, _, _| server.delete_password())
            }
            ("GET", "/api/v1/folders") => {
                self.authorized(request, |server, _, _| server.list_folders())
            }
            ("POST", "/api/v1/folders") => self.authorized(request, |server, _, request| {
                server.json_endpoint(request, |body: FolderRequest| server.state.add_folder(body))
            }),
            ("GET", path) if path.starts_with("/api/v1/folders/") => {
                let id = path.trim_start_matches("/api/v1/folders/");
                self.authorized(request, |server, _, _| {
                    json_result(server.state.get_folder(id))
                })
            }
            ("PUT", path) if path.starts_with("/api/v1/folders/") => {
                let id = path.trim_start_matches("/api/v1/folders/").to_owned();
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: FolderUpdate| {
                        server.state.update_folder(&id, body)
                    })
                })
            }
            ("DELETE", path) if path.starts_with("/api/v1/folders/") => {
                let id = path.trim_start_matches("/api/v1/folders/").to_owned();
                self.authorized(request, |server, _, _| {
                    json_result(server.state.delete_folder(&id))
                })
            }
            ("POST", path) if path.starts_with("/api/v1/folders/") && path.ends_with("/scan") => {
                let id = path
                    .trim_start_matches("/api/v1/folders/")
                    .trim_end_matches("/scan")
                    .to_owned();
                self.authorized(request, |server, _, _| server.scan_folder(&id))
            }
            ("POST", "/api/v1/operations/scan") => {
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: ScanRequest| operations::scan(body))
                })
            }
            ("POST", "/api/v1/operations/apply") => {
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: ApplyRequest| operations::apply(body))
                })
            }
            ("POST", "/api/v1/operations/pull") => {
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: PullRequest| operations::pull_tree(body))
                })
            }
            ("POST", "/api/v1/operations/keys/generate") => {
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: GenerateKeyRequest| {
                        operations::generate_key(body)
                    })
                })
            }
            ("POST", "/api/v1/operations/keys/inspect") => {
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: InspectKeyRequest| {
                        operations::inspect_key(body)
                    })
                })
            }
            ("POST", "/api/v1/operations/ping/encode") => {
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: EncodePingRequest| {
                        operations::encode_ping(body)
                    })
                })
            }
            ("POST", "/api/v1/operations/vault/encrypt") => {
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: EncryptTreeRequest| {
                        operations::encrypt(body)
                    })
                })
            }
            ("POST", "/api/v1/operations/vault/decrypt") => {
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: DecryptTreeRequest| {
                        operations::decrypt(body)
                    })
                })
            }
            ("POST", "/api/v1/operations/tracker/announce") => {
                self.authorized(request, |server, _, request| {
                    server.json_endpoint(request, |body: TrackerAnnounceRequest| {
                        operations::tracker_announce(body)
                    })
                })
            }
            _ => api_error(404, "not_found", "API endpoint not found"),
        }
    }

    fn authorized(
        &self,
        request: &mut Request,
        handler: impl FnOnce(&Self, Principal, &mut Request) -> Response<std::io::Cursor<Vec<u8>>>,
    ) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.authenticate(request) {
            Ok(principal) => handler(self, principal, request),
            Err(response) => response,
        }
    }

    fn json_endpoint<T, R>(
        &self,
        request: &mut Request,
        operation: impl FnOnce(T) -> Result<R>,
    ) -> Response<std::io::Cursor<Vec<u8>>>
    where
        T: DeserializeOwned,
        R: Serialize,
    {
        match self.read_json(request) {
            Ok(body) => json_result(operation(body)),
            Err(response) => response,
        }
    }

    fn authenticate(
        &self,
        request: &Request,
    ) -> Result<Principal, Response<std::io::Cursor<Vec<u8>>>> {
        let address = client_ip(request).map(|address| address.ip());
        if !self
            .state
            .password_configured()
            .map_err(|error| internal_error(&error))?
        {
            return Ok(Principal::Bootstrap);
        }
        if let Some(address) = address {
            if self
                .state
                .ip_is_exempt(address)
                .map_err(|error| internal_error(&error))?
            {
                return Ok(Principal::LocalExempt { address });
            }
        }
        let token = bearer_token(request).or_else(|| cookie_token(request));
        if let Some(token) = token {
            self.validate_session(&token)
                .map_err(|error| api_error(401, "invalid_session", &error.to_string()))?;
            return Ok(Principal::Token { token });
        }
        Err(api_error(
            401,
            "authentication_required",
            "password authentication is required",
        ))
    }

    fn status_response(&self, address: Option<SocketAddr>) -> Response<std::io::Cursor<Vec<u8>>> {
        let password_configured = self.state.password_configured();
        let exempt = address
            .map(|address| self.state.ip_is_exempt(address.ip()))
            .transpose();
        match (password_configured, exempt) {
            (Ok(password_configured), Ok(exempt)) => {
                let authenticated = !password_configured || exempt.unwrap_or(false);
                json_response(
                    200,
                    &serde_json::json!({
                        "ok": true,
                        "version": env!("CARGO_PKG_VERSION"),
                        "password_configured": password_configured,
                        "auth_required": password_configured && !authenticated,
                        "authenticated": authenticated,
                        "password_exempt": exempt.unwrap_or(false),
                        "client_ip": address.map(|address| address.ip().to_string()),
                        "default_password_exempt_ips": DEFAULT_PASSWORD_EXEMPT_IPS,
                    }),
                )
            }
            (Err(error), _) | (_, Err(error)) => internal_error(&error),
        }
    }

    fn login(&self, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
        let body: LoginRequest = match self.read_json(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let password_configured = match self.state.password_configured() {
            Ok(value) => value,
            Err(error) => return internal_error(&error),
        };
        if !password_configured {
            return json_response(
                200,
                &serde_json::json!({
                    "authenticated": true,
                    "password_configured": false,
                }),
            );
        }
        let password_matches = match self.state.verify_password(&body.password) {
            Ok(value) => value,
            Err(error) => return internal_error(&error),
        };
        if !password_matches {
            return api_error(401, "invalid_password", "password is incorrect");
        }
        let token = random_token();
        self.sessions.lock().expect("session lock poisoned").insert(
            token.clone(),
            SessionInfo {
                expires_at: Instant::now() + SESSION_TTL,
            },
        );
        let cookie = format!(
            "rustsync_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            SESSION_TTL.as_secs()
        );
        let mut response = json_response(
            200,
            &serde_json::json!({
                "authenticated": true,
                "token": token,
                "expires_in_seconds": SESSION_TTL.as_secs(),
            }),
        );
        if let Ok(header) = Header::from_bytes("Set-Cookie", cookie.as_bytes()) {
            response.add_header(header);
        }
        response
    }

    fn logout(&self, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
        let token = bearer_token(request).or_else(|| cookie_token(request));
        if let Some(token) = token {
            self.sessions
                .lock()
                .expect("session lock poisoned")
                .remove(&token);
        }
        let mut response = json_response(200, &serde_json::json!({"ok": true}));
        if let Ok(header) = Header::from_bytes(
            "Set-Cookie",
            "rustsync_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".as_bytes(),
        ) {
            response.add_header(header);
        }
        response
    }

    fn settings_response(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.state.snapshot() {
            Ok(state) => json_response(
                200,
                &serde_json::json!({
                    "password_configured": state.password_hash.is_some(),
                    "password_exempt_ips": state.password_exempt_ips,
                }),
            ),
            Err(error) => internal_error(&error),
        }
    }

    fn update_settings(
        &self,
        principal: Principal,
        body: SettingsUpdate,
    ) -> Response<std::io::Cursor<Vec<u8>>> {
        if body.clear_password && body.password.is_some() {
            return api_error(
                400,
                "conflicting_password_update",
                "clear_password cannot be combined with a new password",
            );
        }
        if body.clear_password {
            if let Err(error) = self.state.clear_password() {
                return internal_error(&error);
            }
            self.sessions.lock().expect("session lock poisoned").clear();
        }
        if let Some(password) = body.password {
            if let Err(error) = self.state.set_password(&password) {
                return api_error(400, "invalid_password", &error.to_string());
            }
            self.sessions.lock().expect("session lock poisoned").clear();
            if let Principal::Token { token } = principal {
                self.sessions.lock().expect("session lock poisoned").insert(
                    token,
                    SessionInfo {
                        expires_at: Instant::now() + SESSION_TTL,
                    },
                );
            }
        }
        if let Some(values) = body.password_exempt_ips {
            if let Err(error) = self.state.set_password_exempt_ips(&values) {
                return api_error(400, "invalid_password_exempt_ips", &error.to_string());
            }
        }
        self.settings_response()
    }

    fn delete_password(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        if let Err(error) = self.state.clear_password() {
            return internal_error(&error);
        }
        self.sessions.lock().expect("session lock poisoned").clear();
        self.settings_response()
    }

    fn list_folders(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.state.list_folders() {
            Ok(folders) => json_response(200, &serde_json::json!({"folders": folders})),
            Err(error) => internal_error(&error),
        }
    }

    fn scan_folder(&self, id: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let folder = match self.state.get_folder(id) {
            Ok(folder) => folder,
            Err(error) => return not_found_or_internal(error),
        };
        let result = operations::scan(ScanRequest {
            root: folder.path.clone(),
            output: None,
            include: folder.include.clone(),
            exclude: folder.exclude.clone(),
        });
        match result {
            Ok(result) => match self.state.record_scan(id, result.summary.clone()) {
                Ok(folder) => json_response(
                    200,
                    &serde_json::json!({
                        "folder": folder,
                        "scan": result.summary,
                    }),
                ),
                Err(error) => internal_error(&error),
            },
            Err(error) => api_error(400, "scan_failed", &format!("{error:#}")),
        }
    }

    fn read_json<T: DeserializeOwned>(
        &self,
        request: &mut Request,
    ) -> Result<T, Response<std::io::Cursor<Vec<u8>>>> {
        let mut body = Vec::new();
        if let Err(error) = request
            .as_reader()
            .take(MAX_REQUEST_BODY + 1)
            .read_to_end(&mut body)
        {
            return Err(internal_error(&anyhow::anyhow!(error)));
        }
        if body.len() as u64 > MAX_REQUEST_BODY {
            return Err(api_error(
                413,
                "request_too_large",
                "request body exceeds 1 MiB",
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|error| api_error(400, "invalid_json", &error.to_string()))
    }

    fn validate_session(&self, token: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        let now = Instant::now();
        sessions.retain(|_, session| session.expires_at > now);
        match sessions.get(token) {
            Some(session) if session.expires_at > now => Ok(()),
            _ => anyhow::bail!("session is expired or unknown"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    password: String,
}

#[derive(Debug, Default, Deserialize)]
struct SettingsUpdate {
    password: Option<String>,
    #[serde(default)]
    clear_password: bool,
    password_exempt_ips: Option<Vec<String>>,
}

fn json_result<T: Serialize>(result: Result<T>) -> Response<std::io::Cursor<Vec<u8>>> {
    match result {
        Ok(value) => json_response(200, &value),
        Err(error) => not_found_or_internal(error),
    }
}

fn static_asset(path: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let (body, content_type) = match path {
        "/" | "/index.html" => (
            include_str!("../web/index.html"),
            "text/html; charset=utf-8",
        ),
        "/app.js" => (
            include_str!("../web/app.js"),
            "text/javascript; charset=utf-8",
        ),
        "/styles.css" => (include_str!("../web/styles.css"), "text/css; charset=utf-8"),
        _ => return api_error(404, "not_found", "static asset not found"),
    };
    Response::from_string(body)
        .with_status_code(StatusCode(200))
        .with_header(Header::from_bytes("Content-Type", content_type.as_bytes()).unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-cache".as_bytes()).unwrap())
}

fn json_response<T: Serialize>(status: u16, value: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(value)
        .unwrap_or_else(|_| b"{\"error\":\"serialization failed\"}".to_vec());
    Response::from_data(body)
        .with_status_code(StatusCode(status))
        .with_header(Header::from_bytes("Content-Type", "application/json".as_bytes()).unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store".as_bytes()).unwrap())
}

fn api_error(status: u16, code: &str, message: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        status,
        &serde_json::json!({
            "error": {
                "code": code,
                "message": message,
            }
        }),
    )
}

fn internal_error(error: &anyhow::Error) -> Response<std::io::Cursor<Vec<u8>>> {
    eprintln!("internal server error: {error:#}");
    api_error(500, "internal_error", "internal server error")
}

fn not_found_or_internal(error: anyhow::Error) -> Response<std::io::Cursor<Vec<u8>>> {
    if error.to_string().contains("not found") {
        api_error(404, "not_found", &error.to_string())
    } else {
        internal_error(&error)
    }
}

fn client_ip(request: &Request) -> Option<SocketAddr> {
    request.remote_addr().copied()
}

fn bearer_token(request: &Request) -> Option<String> {
    bearer_token_from_headers(request.headers())
}

fn bearer_token_from_headers(headers: &[Header]) -> Option<String> {
    headers
        .iter()
        .find(|header| {
            header
                .field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("authorization")
        })
        .and_then(|header| header.value.as_str().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
}

fn cookie_token(request: &Request) -> Option<String> {
    cookie_token_from_headers(request.headers())
}

fn cookie_token_from_headers(headers: &[Header]) -> Option<String> {
    let cookie = headers
        .iter()
        .find(|header| {
            header
                .field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("cookie")
        })
        .map(|header| header.value.as_str())?;
    cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == "rustsync_session").then(|| value.trim().to_owned())
    })
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn with_security_headers(
    mut response: Response<std::io::Cursor<Vec<u8>>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    for (name, value) in [
        ("X-Content-Type-Options", "nosniff"),
        (
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'",
        ),
        ("Referrer-Policy", "no-referrer"),
    ] {
        if let Ok(header) = Header::from_bytes(name, value.as_bytes()) {
            response.add_header(header);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_and_cookie_tokens() {
        let headers = vec![
            Header::from_bytes("Authorization", "Bearer abc123".as_bytes()).unwrap(),
            Header::from_bytes("Cookie", "other=x; rustsync_session=cookie456".as_bytes()).unwrap(),
        ];
        assert_eq!(
            bearer_token_from_headers(&headers).as_deref(),
            Some("abc123")
        );
        assert_eq!(
            cookie_token_from_headers(&headers).as_deref(),
            Some("cookie456")
        );
    }
}
