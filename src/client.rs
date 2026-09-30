use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct RemoteClient {
    host: String,
    port: u16,
    token: Option<String>,
    password: Option<String>,
    timeout: Duration,
}

impl RemoteClient {
    pub fn new(base_url: &str, token: Option<String>, password: Option<String>) -> Result<Self> {
        let endpoint = base_url
            .strip_prefix("http://")
            .context("remote server URL must use http://")?
            .trim_end_matches('/');
        if endpoint.contains('/') {
            bail!("remote server URL cannot include a path");
        }
        let (host, port) = endpoint
            .rsplit_once(':')
            .map(|(host, port)| (host.to_owned(), port.parse().unwrap_or(80)))
            .unwrap_or((endpoint.to_owned(), 80));
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(&host)
            .to_owned();
        if host.is_empty() {
            bail!("remote server URL has no host");
        }
        Ok(Self {
            host,
            port,
            token,
            password,
            timeout: Duration::from_secs(30),
        })
    }

    pub fn call<T: DeserializeOwned>(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T> {
        if self.token.is_none() && self.password.is_some() {
            self.login()?;
        }
        let response = self.request(method, path, body)?;
        serde_json::from_slice(&response)
            .with_context(|| format!("parse remote response for {method} {path}"))
    }

    pub fn login(&mut self) -> Result<()> {
        let password = self
            .password
            .clone()
            .context("remote authentication requires --server-password or --server-token")?;
        let response: Value = serde_json::from_slice(&self.request(
            "POST",
            "/api/v1/auth/login",
            Some(&serde_json::json!({"password": password})),
        )?)?;
        let token = response
            .get("token")
            .and_then(Value::as_str)
            .context("remote login response did not contain a token")?;
        self.token = Some(token.to_owned());
        Ok(())
    }

    fn request(&self, method: &str, path: &str, body: Option<&impl Serialize>) -> Result<Vec<u8>> {
        let payload = match body {
            Some(body) => serde_json::to_vec(body)?,
            None => Vec::new(),
        };
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))
            .with_context(|| format!("connect remote server {}:{}", self.host, self.port))?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.host);
        if let Some(token) = &self.token {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        if !payload.is_empty() {
            request.push_str("Content-Type: application/json\r\n");
        }
        request.push_str(&format!(
            "Content-Length: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            payload.len()
        ));
        stream.write_all(request.as_bytes())?;
        stream.write_all(&payload)?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        parse_http_response(&response)
    }
}

fn parse_http_response(response: &[u8]) -> Result<Vec<u8>> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("remote response has no HTTP header terminator")?;
    let header = std::str::from_utf8(&response[..split]).context("remote response headers")?;
    let mut lines = header.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .context("remote response has no valid HTTP status")?;
    let body = &response[split + 4..];
    if !(200..300).contains(&status) {
        let message = std::str::from_utf8(body)
            .unwrap_or("remote request failed")
            .to_owned();
        bail!("remote server returned HTTP {status}: {message}");
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"x\":1}";
        assert_eq!(parse_http_response(response).unwrap(), b"{\"x\":1}");
    }
}
