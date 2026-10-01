#[cfg(target_os = "linux")]
mod linux;

mod cli {
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::net::{IpAddr, SocketAddr};
    use std::path::PathBuf;

    use portal::{AllowedIp, PeerKey};
    use zeroize::Zeroize;

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
            "run" => run_command(&args[1..]),
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
portal — Linux CLI for the portal WireGuard device

Commands:
  portal keygen --private-key-file PATH
  portal run --tun NAME --private-key-file PATH --listen ADDR --socket PATH [options]
  portal peer upsert --socket PATH --public-key HEX [--preshared-key-file PATH]
      [--endpoint ADDR] [--keepalive SECONDS] [--allowed-ip PREFIX ...]
  portal peer remove --socket PATH --public-key HEX
  portal endpoint set --socket PATH --public-key HEX --endpoint ADDR
  portal endpoint clear --socket PATH --public-key HEX
  portal status|health|stats|list|shutdown --socket PATH
  portal peer-stats --socket PATH --public-key HEX

Run options:
  --address IP/PREFIX       Interface address; repeatable
  --mtu BYTES               Interface MTU (default: 1420)
  --workers COUNT           Packet workers (Device default if omitted)
  --handshake-rate-limit N  Handshakes per second (Device default if omitted)
  --no-dual-stack           Bind only the address family of --listen
  --no-auto-routes          Leave host routes to the administrator

Keys are 32 raw bytes or 64 hexadecimal characters. The run process stays in
the foreground; manage it through its Unix control socket from another shell."
        );
    }

    fn run_command(args: &[String]) -> Result<(), String> {
        let options = parse_options(args, &["no-dual-stack", "no-auto-routes"])?;
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
                "socket",
                "no-dual-stack",
                "no-auto-routes",
            ],
            &["address"],
        )?;
        let tun_name = required(&options, "tun")?;
        crate::validate_interface_name(tun_name)?;
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
        let socket_path = options
            .get("socket")
            .and_then(first)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/run/portal-{tun_name}.sock")));
        let auto_routes = !options.contains_key("no-auto-routes");

        crate::run_device(RunOptions {
            tun_name: tun_name.to_owned(),
            private_key,
            listen,
            addresses,
            mtu,
            workers,
            handshake_rate_limit,
            dual_stack: !options.contains_key("no-dual-stack"),
            auto_routes,
            socket_path,
        })
    }

    fn keygen_command(args: &[String]) -> Result<(), String> {
        let options = parse_options(args, &[])?;
        validate_options(&options, &["private-key-file"], &[])?;
        let path = PathBuf::from(required(&options, "private-key-file")?);
        let public_key = crate::create_key_file(&path)?;
        println!(
            "private key saved to {} (raw 32-byte format)",
            path.display()
        );
        println!("public key: {}", encode_hex(&public_key));
        Ok(())
    }

    fn peer_command(args: &[String]) -> Result<(), String> {
        let Some(action) = args.first().map(String::as_str) else {
            return Err("usage: portal peer <upsert|remove> --socket PATH ...".into());
        };
        let options = parse_options(&args[1..], &[])?;
        match action {
            "upsert" => {
                let socket_path = required(&options, "socket")?;
                validate_options(
                    &options,
                    &[
                        "socket",
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
                    .map(|path| read_key_file(path).map(SecretKey))
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
                let allowed_ips = options
                    .get("allowed-ip")
                    .into_iter()
                    .flatten()
                    .map(|value| {
                        value
                            .parse::<AllowedIp>()
                            .map_err(|error| format!("invalid --allowed-ip `{value}`: {error}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let allowed_ips = if allowed_ips.is_empty() {
                    "-".to_owned()
                } else {
                    allowed_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let mut request = format!(
                    "peer-upsert {} {} {} {} {}",
                    encode_hex(&public_key),
                    psk.as_ref()
                        .map(|key| encode_hex(&key.0))
                        .unwrap_or_else(|| "-".into()),
                    endpoint
                        .map(|address| address.to_string())
                        .unwrap_or_else(|| "-".into()),
                    keepalive
                        .map(|seconds| seconds.to_string())
                        .unwrap_or_else(|| "-".into()),
                    allowed_ips
                );
                let result = crate::send_control(socket_path, &request);
                request.zeroize();
                result
            }
            "remove" => {
                validate_options(&options, &["socket", "public-key"], &[])?;
                let key = parse_key_hex(required(&options, "public-key")?)?;
                crate::send_control(
                    required(&options, "socket")?,
                    &format!("peer-remove {}", encode_hex(&key)),
                )
            }
            _ => Err(format!("unknown peer action `{action}`")),
        }
    }

    fn endpoint_command(args: &[String]) -> Result<(), String> {
        let Some(action) = args.first().map(String::as_str) else {
            return Err("usage: portal endpoint <set|clear> --socket PATH --public-key HEX".into());
        };
        let options = parse_options(&args[1..], &[])?;
        match action {
            "set" => validate_options(&options, &["socket", "public-key", "endpoint"], &[])?,
            "clear" => validate_options(&options, &["socket", "public-key"], &[])?,
            _ => {}
        }
        let key = parse_key_hex(required(&options, "public-key")?)?;
        let request = match action {
            "set" => {
                let endpoint = required(&options, "endpoint")?
                    .parse::<SocketAddr>()
                    .map_err(|error| format!("invalid --endpoint: {error}"))?;
                format!("endpoint-set {} {endpoint}", encode_hex(&key))
            }
            "clear" => format!("endpoint-clear {}", encode_hex(&key)),
            _ => return Err(format!("unknown endpoint action `{action}`")),
        };
        crate::send_control(required(&options, "socket")?, &request)
    }

    fn control_command(command: &str, args: &[String]) -> Result<(), String> {
        let options = parse_options(args, &[])?;
        if command == "peer-stats" {
            validate_options(&options, &["socket", "public-key"], &[])?;
        } else {
            validate_options(&options, &["socket"], &[])?;
        }
        let request = if command == "peer-stats" {
            let key = parse_key_hex(required(&options, "public-key")?)?;
            format!("peer-stats {}", encode_hex(&key))
        } else {
            command.to_owned()
        };
        crate::send_control(required(&options, "socket")?, &request)
    }

    pub(crate) struct RunOptions {
        pub(crate) tun_name: String,
        pub(crate) private_key: SecretKey,
        pub(crate) listen: SocketAddr,
        pub(crate) addresses: Vec<InterfaceAddress>,
        pub(crate) mtu: u32,
        pub(crate) workers: Option<usize>,
        pub(crate) handshake_rate_limit: Option<u64>,
        pub(crate) dual_stack: bool,
        pub(crate) auto_routes: bool,
        pub(crate) socket_path: PathBuf,
    }

    pub(crate) struct SecretKey(pub(crate) PeerKey);

    impl Drop for SecretKey {
        fn drop(&mut self) {
            self.0.zeroize();
        }
    }

    #[derive(Clone, Copy)]
    pub(crate) struct InterfaceAddress {
        pub(crate) address: IpAddr,
        pub(crate) prefix_len: u8,
    }

    impl InterfaceAddress {
        fn parse(value: &str) -> Result<Self, String> {
            let (address, prefix) = value.rsplit_once('/').ok_or_else(|| {
                format!("invalid interface address `{value}`; expected IP/PREFIX")
            })?;
            let address = address
                .parse::<IpAddr>()
                .map_err(|error| format!("invalid interface address `{value}`: {error}"))?;
            let prefix_len = prefix
                .parse::<u8>()
                .map_err(|error| format!("invalid interface prefix `{value}`: {error}"))?;
            AllowedIp::new(address, prefix_len)
                .map_err(|error| format!("invalid interface address `{value}`: {error}"))?;
            Ok(Self {
                address,
                prefix_len,
            })
        }
    }

    impl std::fmt::Display for InterfaceAddress {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}/{}", self.address, self.prefix_len)
        }
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

    pub(crate) fn parse_optional(value: &str) -> Option<&str> {
        (value != "-").then_some(value)
    }

    pub(crate) fn parse_optional_key(value: &str) -> Result<Option<PeerKey>, String> {
        parse_optional(value).map(parse_key_hex).transpose()
    }

    fn read_key_file(path: &str) -> Result<PeerKey, String> {
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

    pub(crate) fn parse_key_hex(value: &str) -> Result<PeerKey, String> {
        parse_key_hex_bytes(value.as_bytes())
    }

    fn parse_key_hex_bytes(value: &[u8]) -> Result<PeerKey, String> {
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

    pub(crate) fn one_line(message: &str) -> String {
        message.replace('\r', " ").replace('\n', " ")
    }
}

#[cfg(target_os = "linux")]
fn run_device(options: cli::RunOptions) -> Result<(), String> {
    linux::run_device(options)
}

#[cfg(not(target_os = "linux"))]
fn run_device(_: cli::RunOptions) -> Result<(), String> {
    Err("portal CLI currently supports Linux only".into())
}

#[cfg(target_os = "linux")]
fn create_key_file(path: &std::path::Path) -> Result<portal::PeerKey, String> {
    linux::create_key_file(path)
}

#[cfg(not(target_os = "linux"))]
fn create_key_file(_: &std::path::Path) -> Result<portal::PeerKey, String> {
    Err("portal CLI currently supports Linux only".into())
}

#[cfg(target_os = "linux")]
fn send_control(socket_path: &str, request: &str) -> Result<(), String> {
    linux::send_control(socket_path, request)
}

#[cfg(not(target_os = "linux"))]
fn send_control(_: &str, _: &str) -> Result<(), String> {
    Err("portal CLI currently supports Linux only".into())
}

#[cfg(target_os = "linux")]
fn validate_interface_name(name: &str) -> Result<(), String> {
    linux::validate_interface_name(name)
}

#[cfg(not(target_os = "linux"))]
fn validate_interface_name(_: &str) -> Result<(), String> {
    Err("portal CLI currently supports Linux only".into())
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = cli::entry() {
        eprintln!("portal: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("portal CLI currently supports Linux only");
    std::process::exit(1);
}
