mod http_api;
mod keys;

mod cli {
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::net::SocketAddr;
    use zeroize::{Zeroize, Zeroizing};

    pub(super) fn entry() -> Result<(), String> {
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
            "keygen" => keygen_command(&args[1..]),
            "peer" => peer_command(&args[1..]),
            "endpoint" => endpoint_command(&args[1..]),
            "stats" | "status" | "health" | "list" | "peer-stats" | "shutdown" => {
                control_command(command, &args[1..])
            }
            other => Err(format!("unknown command `{other}`; use `portal help`")),
        }
    }

    fn print_usage() {
        println!(
            "\
portal — control CLI for a running portal runtime

Commands:
  portal keygen --private-key-file PATH
  portal peer upsert [--api IP:PORT] [--token-file PATH] --public-key HEX [--preshared-key-file PATH]
      [--endpoint ADDR] [--keepalive SECONDS] [--allowed-ip PREFIX ...]
  portal peer remove [--api IP:PORT] [--token-file PATH] --public-key HEX
  portal endpoint set|clear [--api IP:PORT] [--token-file PATH] --public-key HEX [--endpoint ADDR]
  portal status|health|stats|list|shutdown [--api IP:PORT] [--token-file PATH]
  portal peer-stats [--api IP:PORT] [--token-file PATH] --public-key HEX

Keys are 32 raw bytes or 64 hexadecimal characters. Start portal-runtime separately.
The default API is 127.0.0.1:51821; its token file is per-user in the temporary directory."
        );
    }

    fn keygen_command(args: &[String]) -> Result<(), String> {
        let options = parse_options(args, &[])?;
        validate_options(&options, &["private-key-file"], &[])?;
        let path = std::path::Path::new(required(&options, "private-key-file")?);
        let public_key = crate::keys::create_key_file(path)?;
        println!(
            "private key saved to {} (raw 32-byte format)",
            path.display()
        );
        println!("public key: {}", encode_hex(&public_key));
        Ok(())
    }

    fn peer_command(args: &[String]) -> Result<(), String> {
        let Some(action) = args.first().map(String::as_str) else {
            return Err("usage: portal peer <upsert|remove> [--api IP:PORT] ...".into());
        };
        let options = parse_options(&args[1..], &[])?;
        match action {
            "upsert" => {
                validate_options(
                    &options,
                    &[
                        "api",
                        "token-file",
                        "public-key",
                        "preshared-key-file",
                        "endpoint",
                        "keepalive",
                        "allowed-ip",
                    ],
                    &["allowed-ip"],
                )?;
                let public_key = parse_key_hex(required(&options, "public-key")?)?;
                let psk = options
                    .get("preshared-key-file")
                    .and_then(first)
                    .map(|path| read_key_file(path).map(Zeroizing::new))
                    .transpose()?;
                let endpoint = options
                    .get("endpoint")
                    .and_then(first)
                    .map(|value| {
                        value
                            .parse::<SocketAddr>()
                            .map_err(|error| format!("invalid --endpoint: {error}"))
                    })
                    .transpose()?;
                let keepalive = options
                    .get("keepalive")
                    .and_then(first)
                    .map(|value| parse_number(Some(value), 1_u64, "--keepalive"))
                    .transpose()?;
                if keepalive.is_some_and(|seconds| seconds == 0 || seconds > u16::MAX as u64) {
                    return Err("--keepalive must be between 1 and 65535 seconds".into());
                }
                let psk = Zeroizing::new(
                    psk.as_ref()
                        .map(|key| encode_hex(key.as_ref()))
                        .unwrap_or_else(|| "-".into()),
                );
                let allowed_ips = options
                    .get("allowed-ip")
                    .filter(|ips| !ips.is_empty())
                    .map(|ips| ips.iter().map(String::as_str).collect())
                    .unwrap_or_default();
                let public_key = encode_hex(&public_key);
                let command = crate::http_api::ManagementRequest::PeerUpsert {
                    public_key: &public_key,
                    preshared_key: (psk.as_str() != "-").then_some(psk.as_str()),
                    endpoint,
                    keepalive_seconds: keepalive,
                    allowed_ips,
                };
                let result = send_command(&options, &command)?;
                print_operation(result)
            }
            "remove" => {
                validate_options(&options, &["api", "token-file", "public-key"], &[])?;
                let key = parse_key_hex(required(&options, "public-key")?)?;
                let public_key = encode_hex(&key);
                let command = crate::http_api::ManagementRequest::PeerRemove {
                    public_key: &public_key,
                };
                let result = send_command(&options, &command)?;
                print_operation(result)
            }
            _ => Err(format!("unknown peer action `{action}`")),
        }
    }

    fn endpoint_command(args: &[String]) -> Result<(), String> {
        let Some(action) = args.first().map(String::as_str) else {
            return Err(
                "usage: portal endpoint <set|clear> [--api IP:PORT] --public-key HEX".into(),
            );
        };
        let options = parse_options(&args[1..], &[])?;
        match action {
            "set" => validate_options(
                &options,
                &["api", "token-file", "public-key", "endpoint"],
                &[],
            )?,
            "clear" => validate_options(&options, &["api", "token-file", "public-key"], &[])?,
            _ => {}
        }
        let key = parse_key_hex(required(&options, "public-key")?)?;
        match action {
            "set" => {
                let endpoint = required(&options, "endpoint")?
                    .parse::<SocketAddr>()
                    .map_err(|error| format!("invalid --endpoint: {error}"))?;
                let public_key = encode_hex(&key);
                let command = crate::http_api::ManagementRequest::EndpointSet {
                    public_key: &public_key,
                    endpoint,
                };
                let result = send_command(&options, &command)?;
                print_operation(result)
            }
            "clear" => {
                let public_key = encode_hex(&key);
                let command = crate::http_api::ManagementRequest::EndpointClear {
                    public_key: &public_key,
                };
                let result = send_command(&options, &command)?;
                print_operation(result)
            }
            _ => Err(format!("unknown endpoint action `{action}`")),
        }
    }

    fn control_command(command: &str, args: &[String]) -> Result<(), String> {
        let options = parse_options(args, &[])?;
        if command == "peer-stats" {
            validate_options(&options, &["api", "token-file", "public-key"], &[])?;
        } else {
            validate_options(&options, &["api", "token-file"], &[])?;
        }
        let response = if command == "peer-stats" {
            let key = parse_key_hex(required(&options, "public-key")?)?;
            let public_key = encode_hex(&key);
            let request = crate::http_api::ManagementRequest::PeerStats {
                public_key: &public_key,
            };
            send_command(&options, &request)?
        } else {
            let request = match command {
                "status" => crate::http_api::ManagementRequest::Status,
                "health" => crate::http_api::ManagementRequest::Health,
                "stats" => crate::http_api::ManagementRequest::Stats,
                "list" => crate::http_api::ManagementRequest::List,
                "shutdown" => crate::http_api::ManagementRequest::Shutdown,
                _ => unreachable!("control_command is only called for known operations"),
            };
            send_command(&options, &request)?
        };
        print_operation(response)
    }

    fn default_token_file() -> std::path::PathBuf {
        #[cfg(unix)]
        let name = format!("portal-{}.token", unsafe { libc::geteuid() });
        #[cfg(not(unix))]
        let name = "portal.token";
        std::env::temp_dir().join(name)
    }

    /// Send a command to the local HTTP API using its address and bearer-token file.
    fn send_command(
        options: &HashMap<String, Vec<String>>,
        command: &crate::http_api::ManagementRequest<'_>,
    ) -> Result<String, String> {
        let address = options
            .get("api")
            .and_then(first)
            .map(String::as_str)
            .unwrap_or("127.0.0.1:51821");
        let default_token = default_token_file();
        let token_file = options
            .get("token-file")
            .and_then(first)
            .map(String::as_str)
            .unwrap_or(default_token.to_str().ok_or("token path is not UTF-8")?);
        let mut request = serde_json::to_string(command)
            .map_err(|error| format!("could not encode API request: {error}"))?;
        crate::http_api::send(address, token_file, &mut request)
    }

    fn print_operation(message: String) -> Result<(), String> {
        if !message.is_empty() {
            println!("{message}");
        }
        Ok(())
    }

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

    fn required<'a>(
        options: &'a HashMap<String, Vec<String>>,
        name: &str,
    ) -> Result<&'a str, String> {
        options
            .get(name)
            .and_then(first)
            .map(String::as_str)
            .ok_or_else(|| format!("missing required option --{name}"))
    }

    fn first(values: &Vec<String>) -> Option<&String> {
        values.first()
    }

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
        let key = parse_key_hex_bytes(&bytes[start..end]);
        bytes.zeroize();
        key
    }

    pub(crate) fn parse_key_hex(value: &str) -> Result<[u8; 32], String> {
        parse_key_hex_bytes(value.as_bytes())
    }

    fn parse_key_hex_bytes(value: &[u8]) -> Result<[u8; 32], String> {
        if value.len() != 64 {
            return Err("key must be exactly 64 hexadecimal characters".into());
        }
        let mut key = [0_u8; 32];
        for index in 0..key.len() {
            let start = index * 2;
            let high = match hex_nibble(value[start]) {
                Ok(nibble) => nibble,
                Err(error) => {
                    key.zeroize();
                    return Err(error);
                }
            };
            let low = match hex_nibble(value[start + 1]) {
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

    fn hex_nibble(value: u8) -> Result<u8, String> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'A'..=b'F' => Ok(value - b'A' + 10),
            _ => Err("key contains a non-hexadecimal character".into()),
        }
    }

    pub(crate) fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}

fn main() {
    if let Err(error) = cli::entry() {
        eprintln!("portal: {error}");
        std::process::exit(1);
    }
}
