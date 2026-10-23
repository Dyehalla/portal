use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use portal_runtime::{FileConfig, InterfaceAddress, RuntimeConfig, SecretKey, defaults};
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
        return run_command(&[]);
    };
    match command {
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "run" => run_command(&args[1..]),
        "keygen" => keygen_command(&args[1..]),
        "enroll" => enroll_command(&args[1..]),
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
  portal-runtime                             Start with defaults
  portal-runtime run [options]                Manual startup, or default config
  portal-runtime run --config PATH            Managed startup from JSON
  portal-runtime keygen [--private-key-file PATH]
  portal-runtime enroll [--config PATH] [--user-token-file PATH]

Run options:
  --tun NAME                TUN interface (default: {tun})
  --private-key-file PATH   Device key (default: {key}; created once if absent)
  --listen IP:PORT          WireGuard UDP socket (default: {listen})
  --api-listen IP:PORT      Loopback API and web panel (default: {api})
  --api-token-file PATH     API bearer token (default: {api_token})
  --address IP/PREFIX       Repeatable; default: no manual interface addresses
  --mtu BYTES               Interface MTU (default: {mtu})
  --workers COUNT           Default: available CPU count, capped at 256
  --handshake-rate-limit N  Handshakes per second (default: 100)
  --no-dual-stack           Disable dual stack (default: enabled)
  --no-auto-routes          Disable automatic routes (default: enabled)

Without run options, {config} is used if present; otherwise manual defaults apply.
Explicit manual options select manual mode. --config cannot be combined with them.
Enrollment defaults: config={config}, user-token-file={user_token}.
JSON fields also have defaults. Enrollment still requires a real user token.
An enrolled device's missing key is never replaced automatically.
The runtime stays in the foreground. Web panel: http://{api}/",
        tun = defaults::TUN_NAME,
        key = defaults::PRIVATE_KEY_FILE,
        listen = defaults::LISTEN,
        api = defaults::API_LISTEN,
        api_token = defaults::API_TOKEN_FILE,
        mtu = defaults::MTU,
        config = defaults::CONFIG_FILE,
        user_token = defaults::USER_TOKEN_FILE,
    );
}

// Validate runtime options, build the device configuration, and start the foreground service.
fn run_command(args: &[String]) -> Result<(), String> {
    if matches!(args, [arg] if matches!(arg.as_str(), "--help" | "-h")) {
        print_usage();
        return Ok(());
    }
    let options = parse_options(args, &["no-dual-stack", "no-auto-routes"])?;
    if let Some(path) = configuration_file(&options, Path::new(defaults::CONFIG_FILE))? {
        validate_options(&options, &["config"], &[])?;
        let config = FileConfig::load(&path)?;
        let key = load_startup_key(&config.private_key_file, false)?;
        return portal_runtime::run(config.into_runtime(key));
    }
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
            "no-dual-stack",
            "no-auto-routes",
        ],
        &["address"],
    )?;
    let tun_name = option_or(&options, "tun", defaults::TUN_NAME);
    portal_runtime::validate_interface_name(tun_name)?;
    let listen = option_or(&options, "listen", defaults::LISTEN)
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid --listen address: {error}"))?;
    let addresses = options
        .get("address")
        .into_iter()
        .flatten()
        .map(|value| InterfaceAddress::parse(value))
        .collect::<Result<Vec<_>, _>>()?;
    let mtu = parse_number(
        options.get("mtu").and_then(|values| first(values)),
        defaults::MTU,
        "--mtu",
    )?;
    if !(576..=65_535).contains(&mtu) {
        return Err("--mtu must be between 576 and 65535".into());
    }
    if addresses.iter().any(|address| address.address.is_ipv6()) && mtu < 1280 {
        return Err("--mtu must be at least 1280 when an IPv6 address is configured".into());
    }

    let workers = options
        .get("workers")
        .and_then(|values| first(values))
        .map(|value| parse_number(Some(value), 1_usize, "--workers"))
        .transpose()?;
    let handshake_rate_limit = options
        .get("handshake-rate-limit")
        .and_then(|values| first(values))
        .map(|value| parse_number(Some(value), 1_u64, "--handshake-rate-limit"))
        .transpose()?;
    if workers.is_some_and(|n| n == 0 || n > 256) {
        return Err("--workers must be between 1 and 256".into());
    }
    if handshake_rate_limit == Some(0) {
        return Err("--handshake-rate-limit must be greater than zero".into());
    }
    let api_listen = options
        .get("api-listen")
        .and_then(|values| first(values))
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid --api-listen address: {error}"))
        })
        .transpose()?
        .unwrap_or_else(|| {
            defaults::API_LISTEN
                .parse()
                .expect("constant socket address")
        });
    if !api_listen.ip().is_loopback() {
        return Err("--api-listen must use a loopback address".into());
    }
    let api_token_file = options
        .get("api-token-file")
        .and_then(|values| first(values))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(defaults::API_TOKEN_FILE));
    let private_key_file = Path::new(option_or(
        &options,
        "private-key-file",
        defaults::PRIVATE_KEY_FILE,
    ));
    let private_key = load_startup_key(private_key_file, true)?;
    portal_runtime::run(RuntimeConfig {
        coordinator: None,
        tun_name: tun_name.to_owned(),
        private_key,
        listen,
        addresses,
        mtu,
        workers,
        handshake_rate_limit,
        dual_stack: defaults::DUAL_STACK && !options.contains_key("no-dual-stack"),
        auto_routes: defaults::AUTO_ROUTES && !options.contains_key("no-auto-routes"),
        api_listen,
        api_token_file,
    })
}

fn enroll_command(args: &[String]) -> Result<(), String> {
    let options = parse_options(args, &[])?;
    validate_options(&options, &["config", "user-token-file"], &[])?;
    let config = FileConfig::load(Path::new(option_or(
        &options,
        "config",
        defaults::CONFIG_FILE,
    )))?;
    let already_enrolled = fs::symlink_metadata(&config.coordinator.credential_file)
        .map(|_| true)
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(e)
            }
        })
        .map_err(|e| format!("could not inspect device credentials: {e}"))?;
    let key = load_startup_key(&config.private_key_file, !already_enrolled)?;
    println!(
        "{}",
        portal_runtime::enroll(
            config.coordinator,
            key,
            Path::new(option_or(
                &options,
                "user-token-file",
                defaults::USER_TOKEN_FILE
            ))
        )?
    );
    Ok(())
}

// Create a protected private-key file and print the corresponding public key.
fn keygen_command(args: &[String]) -> Result<(), String> {
    let options = parse_options(args, &[])?;
    validate_options(&options, &["private-key-file"], &[])?;
    let path = PathBuf::from(option_or(
        &options,
        "private-key-file",
        defaults::PRIVATE_KEY_FILE,
    ));
    prepare_key_directory(&path)?;
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

// Resolve an optional argument using the same defaults as the JSON configuration.
fn option_or<'a>(
    options: &'a HashMap<String, Vec<String>>,
    name: &str,
    default: &'a str,
) -> &'a str {
    options
        .get(name)
        .and_then(|values| first(values))
        .map(String::as_str)
        .unwrap_or(default)
}

// Never silently switch to manual mode if an existing config cannot be read.
fn configuration_file(
    options: &HashMap<String, Vec<String>>,
    default: &Path,
) -> Result<Option<PathBuf>, String> {
    if let Some(path) = options.get("config").and_then(|values| first(values)) {
        return Ok(Some(path.into()));
    }
    if !options.is_empty() {
        return Ok(None);
    }
    match fs::symlink_metadata(default) {
        Ok(_) => Ok(Some(default.into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "could not inspect runtime config {}: {e}",
            default.display()
        )),
    }
}

fn prepare_key_directory(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(parent)
            .map_err(|e| format!("could not create key directory {}: {e}", parent.display()))?;
    }
    Ok(())
}

fn load_startup_key(path: &Path, create_if_missing: bool) -> Result<SecretKey, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && create_if_missing => {
            prepare_key_directory(path)?;
            portal_runtime::create_key_file(path)?;
            eprintln!("created device key: {}", path.display());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "device key {} is missing; restore the enrolled device key or run keygen/enroll for a new device",
                path.display()
            ));
        }
        Err(e) => {
            return Err(format!(
                "could not inspect device key {}: {e}",
                path.display()
            ));
        }
    }
    read_key_file(path).map(SecretKey)
}

// Return the first parsed value for an option, if present.
fn first(values: &[String]) -> Option<&String> {
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
fn read_key_file(path: &Path) -> Result<[u8; 32], String> {
    let mut bytes = fs::read(path)
        .map_err(|error| format!("could not read key file {}: {error}", path.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_is_optional_but_an_existing_or_explicit_file_is_never_ignored() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.json");
        let empty = HashMap::new();
        assert!(configuration_file(&empty, &path).unwrap().is_none());
        fs::write(&path, "not JSON").unwrap();
        assert_eq!(
            configuration_file(&empty, &path).unwrap(),
            Some(path.clone())
        );
        assert!(FileConfig::load(&path).is_err());
        let manual = parse_options(&["--tun".into(), "manual0".into()], &[]).unwrap();
        assert!(configuration_file(&manual, &path).unwrap().is_none());
        let explicit = parse_options(&["--config".into(), "missing.json".into()], &[]).unwrap();
        assert_eq!(
            configuration_file(&explicit, &path).unwrap(),
            Some(PathBuf::from("missing.json"))
        );
    }

    #[test]
    fn first_manual_start_creates_a_private_random_key_and_restarts_preserve_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state/device.key");
        let first = load_startup_key(&path, true).unwrap();
        let second = load_startup_key(&path, true).unwrap();
        assert_eq!(first.0, second.0);
        assert_eq!(fs::metadata(&path).unwrap().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        let other = load_startup_key(&directory.path().join("other.key"), true).unwrap();
        assert_ne!(first.0, other.0);
    }

    #[test]
    fn missing_enrolled_keys_corrupt_files_and_dangling_links_are_not_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device.key");
        assert!(load_startup_key(&path, false).is_err());
        assert!(!path.exists());
        fs::write(&path, b"invalid key").unwrap();
        assert!(load_startup_key(&path, true).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"invalid key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = directory.path().join("link.key");
            let missing = directory.path().join("missing.key");
            symlink(&missing, &link).unwrap();
            assert!(load_startup_key(&link, true).is_err());
            assert!(!missing.exists());
            assert_eq!(
                configuration_file(&HashMap::new(), &link).unwrap(),
                Some(link)
            );
        }
    }
}
