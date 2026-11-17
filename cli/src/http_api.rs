use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// JSON operation shared by the CLI and local web client.
#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum ManagementRequest<'a> {
    Connect {
        peer_device_id: &'a str,
    },
    PeerUpsert {
        public_key: &'a str,
        preshared_key: Option<&'a str>,
        endpoint: Option<SocketAddr>,
        keepalive_seconds: Option<u64>,
        allowed_ips: Vec<&'a str>,
    },
    PeerRemove {
        public_key: &'a str,
    },
    EndpointSet {
        public_key: &'a str,
        endpoint: SocketAddr,
    },
    EndpointClear {
        public_key: &'a str,
    },
    PeerStats {
        public_key: &'a str,
    },
    Status,
    Health,
    Stats,
    List,
    Shutdown,
}

#[derive(Deserialize)]
struct CommandResponse {
    message: String,
}

/// Send one management command to the loopback HTTP API with its bearer-token file.
pub(crate) fn send(
    address: &str,
    token_file: &str,
    command: &mut String,
) -> Result<String, String> {
    let result = send_inner(address, token_file, command);
    command.zeroize();
    result
}

/// Fetch the authenticated runtime snapshot for commands that need peer addresses.
pub(crate) fn snapshot(address: &str, token_file: &str) -> Result<serde_json::Value, String> {
    let address = parse_address(address)?;
    let token = read_token(token_file)?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|e| format!("could not connect to local API {address}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let request = format!(
        "GET /api/v1/snapshot HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        token.as_str()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    (&mut stream)
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    if response.len() > MAX_RESPONSE_BYTES {
        return Err("API response is too large".into());
    }
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("invalid HTTP response from local API")?;
    let status = std::str::from_utf8(&response[..header_end])
        .ok()
        .and_then(|h| h.lines().next())
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u16>().ok())
        .ok_or("invalid HTTP status from local API")?;
    let body = &response[header_end + 4..];
    if !(200..300).contains(&status) {
        return Err(format!("local API returned HTTP {status}"));
    }
    serde_json::from_slice(body).map_err(|e| format!("invalid snapshot JSON: {e}"))
}

/// Connect to the local API, send a bounded JSON request, and decode its response.
fn send_inner(address: &str, token_file: &str, command: &str) -> Result<String, String> {
    let address = parse_address(address)?;
    let token = read_token(token_file)?;

    let mut body = command.as_bytes().to_vec();
    let result = (|| {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .map_err(|error| format!("could not connect to local API {address}: {error}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(30))))
            .map_err(|error| format!("could not configure API connection: {error}"))?;

        let headers = Zeroizing::new(format!(
            "POST /api/v1/command HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            token.as_str(),
            body.len(),
        ));
        stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.write_all(&body))
            .and_then(|()| stream.flush())
            .map_err(|error| format!("could not send API request: {error}"))?;
        let mut response = Vec::new();
        (&mut stream)
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .map_err(|error| format!("could not read API response: {error}"))?;
        if response.len() > MAX_RESPONSE_BYTES {
            return Err("API response is too large".into());
        }
        decode_response(&response)
    })();
    body.zeroize();
    result
}

/// Build a login link whose fragment is consumed locally by the web panel.
pub(crate) fn web_url(address: &str, token_file: &str) -> Result<Zeroizing<String>, String> {
    let address = parse_address(address)?;
    let token = read_token(token_file)?;
    Ok(Zeroizing::new(format!(
        "http://{address}/#token={}",
        token.as_str()
    )))
}

pub(crate) fn is_listening(address: &str) -> Result<bool, String> {
    let address = parse_address(address)?;
    match TcpStream::connect_timeout(&address, Duration::from_secs(1)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Ok(false),
        Err(error) => Err(format!("Could not reach local API {address}: {error}")),
    }
}

fn parse_address(address: &str) -> Result<SocketAddr, String> {
    let address = address
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid --api address: {error}"))?;
    if !address.ip().is_loopback() {
        return Err("--api must use a loopback address".into());
    }
    Ok(address)
}

fn read_token(token_file: &str) -> Result<Zeroizing<String>, String> {
    let mut token_bytes = fs::read(token_file).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => format!(
            "API token file {token_file} was not found. Use `sudo portal web` to start the default agent, or --token-file PATH matching a running agent's api_token_file. Its startup output also contains a login link."
        ),
        std::io::ErrorKind::PermissionDenied => format!(
            "Cannot read API token file {token_file}. Run `sudo portal web` or use --token-file PATH for this agent."
        ),
        _ => format!("could not read API token file {token_file}: {error}"),
    })?;
    let token_text = String::from_utf8_lossy(&token_bytes);
    let token_text = token_text.trim();
    if token_text.len() != 64 || !token_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        token_bytes.zeroize();
        return Err(format!(
            "API token file {token_file} must contain a 64-character hex token"
        ));
    }
    let token = Zeroizing::new(token_text.to_owned());
    token_bytes.zeroize();

    Ok(token)
}

/// Parse an HTTP response and return its JSON message or the server's error.
fn decode_response(response: &[u8]) -> Result<String, String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "invalid HTTP response from local API".to_owned())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| "invalid HTTP response headers from local API".to_owned())?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "invalid HTTP status from local API".to_owned())?;
    let reply: CommandResponse = serde_json::from_slice(&response[header_end + 4..])
        .map_err(|error| format!("invalid JSON response from local API: {error}"))?;
    if (200..300).contains(&status) {
        Ok(reply.message)
    } else {
        Err(format!(
            "local API returned HTTP {status}: {}",
            reply.message
        ))
    }
}
