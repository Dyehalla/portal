use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use portal_files::FileServiceConfig;
use portal_runtime::{InterfaceAddress, RuntimeConfig, SecretKey, SmbConfig};
use zeroize::Zeroize;

// Run the selected command and report failures using a nonzero process exit code.
fn main() {
    if let Err(error) = entry() {
        eprintln!("portal-runtime: {error}");
        std::process::exit(1);
    }
}

// Parse the runtime subcommand and dispatch to startup or key generation.
fn entry() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        print_usage();
        return Ok(());
    };
    match command {
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "run" => run_command(&args[1..]),
        "keygen" => keygen_command(&args[1..]),
        other => Err(format!(
            "unknown command `{other}`; use `portal-runtime help`"
        )),
    }
}

// Print supported runtime commands and their startup options.
fn print_usage() {
    println!(
        "\
portal-runtime — Linux WireGuard runtime with a local HTTP management API

Commands:
  portal-runtime run --tun NAME --private-key-file PATH --listen ADDR [options]
  portal-runtime keygen --private-key-file PATH

Run options:
  --api-listen IP:PORT      Loopback management API (default: 127.0.0.1:51821)
  --api-token-file PATH     API bearer token (default: /run/portal.token)
  --address IP/PREFIX       Interface address; repeatable
  --mtu BYTES               Interface MTU (default: 1420)
  --workers COUNT           Packet workers (Device default if omitted)
  --handshake-rate-limit N  Handshakes per second (Device default if omitted)
  --no-dual-stack           Bind only the address family of --listen
  --no-auto-routes          Leave host routes to the administrator
  --grpc-listen IP:PORT     Shared peer-to-peer gRPC listener (requires a service)
  --files-root DIR          Enable the file download service with this shared root
  --files-http-listen IP:PORT HTTP listener for file contents
  --files-allow-download IP  Grant file downloads to this tunnel IP; repeatable
  --smb-root DIR            Read-only Samba share (requires Samba and --grpc-listen)
  --smb-name NAME           Share name (default: documents)
  --smb-listen IP           Tunnel IP assigned with --address
  --smb-user USER           Unix/SMB account (default: current user or sudo caller)
  --smb-as-root             Run Samba as root (requires privileged runtime)
  --smb-port PORT           TCP port (default: 1445; 445 with --smb-as-root)
  --smb-password-file PATH  Owner-only file containing the SMB password
  --smb-allow-peer IP       Allow SMB connections from this tunnel IP; repeatable

The runtime stays in the foreground. Use the separate `portal` CLI to manage it."
    );
}

// Validate runtime options, build the device configuration, and start the foreground service.
fn run_command(args: &[String]) -> Result<(), String> {
    let options = parse_options(args, &["no-dual-stack", "no-auto-routes", "smb-as-root"])?;
    validate_options(
        &options,
        &[
            "tun",
            "private-key-file",
            "listen",
            "address",
            "mtu",
            "workers",
            "handshake-rate-limit",
            "api-listen",
            "api-token-file",
            "grpc-listen",
            "files-root",
            "files-http-listen",
            "files-allow-download",
            "smb-root",
            "smb-name",
            "smb-listen",
            "smb-user",
            "smb-as-root",
            "smb-port",
            "smb-password-file",
            "smb-allow-peer",
            "no-dual-stack",
            "no-auto-routes",
        ],
        &["address", "files-allow-download", "smb-allow-peer"],
    )?;
    let tun_name = required(&options, "tun")?;
    portal_runtime::validate_interface_name(tun_name)?;
    let private_key = SecretKey(read_key_file(required(&options, "private-key-file")?)?);
    let listen = required(&options, "listen")?
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid --listen address: {error}"))?;
    let addresses = options
        .get("address")
        .into_iter()
        .flatten()
        .map(|value| InterfaceAddress::parse(value))
        .collect::<Result<Vec<_>, _>>()?;
    let mtu = parse_number(options.get("mtu").and_then(first), 1420_u32, "--mtu")?;
    if !(576..=65_535).contains(&mtu) {
        return Err("--mtu must be between 576 and 65535".into());
    }
    if addresses.iter().any(|address| address.address.is_ipv6()) && mtu < 1280 {
        return Err("--mtu must be at least 1280 when an IPv6 address is configured".into());
    }

    let workers = options
        .get("workers")
        .and_then(first)
        .map(|value| parse_number(Some(value), 1_usize, "--workers"))
        .transpose()?;
    let handshake_rate_limit = options
        .get("handshake-rate-limit")
        .and_then(first)
        .map(|value| parse_number(Some(value), 1_u64, "--handshake-rate-limit"))
        .transpose()?;
    let api_listen = options
        .get("api-listen")
        .and_then(first)
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid --api-listen address: {error}"))
        })
        .transpose()?
        .unwrap_or_else(|| "127.0.0.1:51821".parse().expect("constant socket address"));
    if !api_listen.ip().is_loopback() {
        return Err("--api-listen must use a loopback address".into());
    }
    let api_token_file = options
        .get("api-token-file")
        .and_then(first)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/portal.token"));
    let grpc_listen = options
        .get("grpc-listen")
        .and_then(first)
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid --grpc-listen address: {error}"))
        })
        .transpose()?;
    if grpc_listen.is_some_and(|address| address.ip().is_unspecified()) {
        return Err("bind --grpc-listen to a specific tunnel address".into());
    }
    let file_service = match options.get("files-root").and_then(first) {
        Some(root) => {
            let http_listen = required(&options, "files-http-listen")?
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid --files-http-listen address: {error}"))?;
            if http_listen.ip().is_unspecified() {
                return Err("bind --files-http-listen to a specific tunnel address".into());
            }
            let allowed_downloaders = options
                .get("files-allow-download")
                .into_iter()
                .flatten()
                .map(|value| {
                    value.parse::<IpAddr>().map_err(|error| {
                        format!("invalid --files-allow-download peer IP `{value}`: {error}")
                    })
                })
                .collect::<Result<HashSet<_>, _>>()?;
            if allowed_downloaders.is_empty() {
                return Err("at least one --files-allow-download IP is required".into());
            }
            Some(FileServiceConfig {
                root: PathBuf::from(root),
                http_listen,
                allowed_downloaders,
            })
        }
        None => {
            if options.contains_key("files-http-listen")
                || options.contains_key("files-allow-download")
            {
                return Err("file service options require --files-root".into());
            }
            None
        }
    };
    let smb = match options.get("smb-root").and_then(first) {
        Some(root) => {
            let listen = required(&options, "smb-listen")?
                .parse::<IpAddr>()
                .map_err(|error| format!("invalid --smb-listen: {error}"))?;
            if !addresses.iter().any(|address| address.address == listen)
                || listen.is_loopback()
                || listen.is_unspecified()
                || listen.is_multicast()
            {
                return Err("--smb-listen must be a tunnel IP assigned with --address".into());
            }
            let allowed_peers = options
                .get("smb-allow-peer")
                .into_iter()
                .flatten()
                .map(|value| {
                    value
                        .parse::<IpAddr>()
                        .map_err(|error| format!("invalid --smb-allow-peer: {error}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if allowed_peers.is_empty() {
                return Err("at least one --smb-allow-peer IP is required".into());
            }
            Some(SmbConfig {
                root: PathBuf::from(root),
                name: options
                    .get("smb-name")
                    .and_then(first)
                    .cloned()
                    .unwrap_or_else(|| "documents".into()),
                listen,
                user: options.get("smb-user").and_then(first).cloned(),
                as_root: options.contains_key("smb-as-root"),
                port: options
                    .get("smb-port")
                    .and_then(first)
                    .map(|value| {
                        value
                            .parse::<u16>()
                            .map_err(|error| format!("invalid --smb-port: {error}"))
                    })
                    .transpose()?,
                password_file: PathBuf::from(required(&options, "smb-password-file")?),
                allowed_peers,
            })
        }
        None => {
            if options.keys().any(|name| name.starts_with("smb-")) {
                return Err("SMB options require --smb-root".into());
            }
            None
        }
    };
    match (grpc_listen, (file_service.is_some() || smb.is_some())) {
        (Some(_), false) => {
            return Err("--grpc-listen requires at least one configured gRPC service".into());
        }
        (None, true) => return Err("file sharing requires --grpc-listen".into()),
        _ => {}
    }
    portal_runtime::run(RuntimeConfig {
        tun_name: tun_name.to_owned(),
        private_key,
        listen,
        addresses,
        mtu,
        workers,
        handshake_rate_limit,
        dual_stack: !options.contains_key("no-dual-stack"),
        auto_routes: !options.contains_key("no-auto-routes"),
        api_listen,
        api_token_file,
        grpc_listen,
        file_service,
        smb,
    })
}

// Create a protected private-key file and print the corresponding public key.
fn keygen_command(args: &[String]) -> Result<(), String> {
    let options = parse_options(args, &[])?;
    validate_options(&options, &["private-key-file"], &[])?;
    let path = PathBuf::from(required(&options, "private-key-file")?);
    let public_key = portal_runtime::create_key_file(&path)?;
    println!(
        "private key saved to {} (raw 32-byte format)",
        path.display()
    );
    println!("public key: {}", encode_hex(&public_key));
    Ok(())
}

// Parse `--name value` arguments and collect repeated options in their original order.
fn parse_options(
    args: &[String],
    boolean_options: &[&str],
) -> Result<HashMap<String, Vec<String>>, String> {
    let mut options = HashMap::<String, Vec<String>>::new();
    let mut index = 0;
    while index < args.len() {
        let option = args[index]
            .strip_prefix("--")
            .ok_or_else(|| format!("expected an option, got `{}`", args[index]))?;
        if option.is_empty() {
            return Err("empty option name".into());
        }
        if boolean_options.contains(&option) {
            options
                .entry(option.to_owned())
                .or_default()
                .push("true".into());
            index += 1;
            continue;
        }
        let value = args
            .get(index + 1)
            .filter(|value| !value.starts_with("--"))
            .ok_or_else(|| format!("option --{option} requires a value"))?;
        options
            .entry(option.to_owned())
            .or_default()
            .push(value.clone());
        index += 2;
    }
    Ok(options)
}

// Reject unknown flags and repeated options that are not explicitly repeatable.
fn validate_options(
    options: &HashMap<String, Vec<String>>,
    allowed: &[&str],
    repeatable: &[&str],
) -> Result<(), String> {
    for (name, values) in options {
        if !allowed.contains(&name.as_str()) {
            return Err(format!("unknown option --{name}"));
        }
        if values.len() > 1 && !repeatable.contains(&name.as_str()) {
            return Err(format!("option --{name} may only be specified once"));
        }
    }
    Ok(())
}

// Return the first value for a required option or explain which option is missing.
fn required<'a>(options: &'a HashMap<String, Vec<String>>, name: &str) -> Result<&'a str, String> {
    options
        .get(name)
        .and_then(first)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required option --{name}"))
}

// Return the first parsed value for an option, if present.
fn first(values: &Vec<String>) -> Option<&String> {
    values.first()
}

// Parse an optional numeric argument, using its configured default when omitted.
fn parse_number<T>(value: Option<&String>, default: T, option: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.map_or(Ok(default), |value| {
        value
            .parse::<T>()
            .map_err(|error| format!("invalid {option} value `{value}`: {error}"))
    })
}

// Read a 32-byte raw or 64-character hexadecimal key, clearing the file buffer afterward.
fn read_key_file(path: &str) -> Result<[u8; 32], String> {
    let mut bytes =
        fs::read(path).map_err(|error| format!("could not read key file {path}: {error}"))?;
    if bytes.len() == 32 {
        let key = bytes.as_slice().try_into().expect("length checked");
        bytes.zeroize();
        return Ok(key);
    }
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let result = parse_key_hex(&bytes[start..end]);
    bytes.zeroize();
    result
}

// Decode an exact-length hexadecimal key and wipe partial output if a digit is invalid.
fn parse_key_hex(value: &[u8]) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("key must be exactly 64 hexadecimal characters".into());
    }
    let mut key = [0_u8; 32];
    for index in 0..key.len() {
        let offset = index * 2;
        let high = match hex_nibble(value[offset]) {
            Ok(nibble) => nibble,
            Err(error) => {
                key.zeroize();
                return Err(error);
            }
        };
        let low = match hex_nibble(value[offset + 1]) {
            Ok(nibble) => nibble,
            Err(error) => {
                key.zeroize();
                return Err(error);
            }
        };
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

// Convert one ASCII hexadecimal character to its four-bit value.
fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("key contains a non-hexadecimal character".into()),
    }
}

// Encode key bytes as lowercase hexadecimal for display.
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
