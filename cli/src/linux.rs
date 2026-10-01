use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::cli::{
    InterfaceAddress, RunOptions, SecretKey, encode_hex, one_line, parse_key_hex, parse_optional,
    parse_optional_key,
};
use portal::{AllowedIp, Device, DeviceConfig, PeerConfig, PeerKey};
use zeroize::Zeroize;

static STOP: AtomicBool = AtomicBool::new(false);
const CONTROL_READ_TIMEOUT: Duration = Duration::from_secs(2);
const LOOP_INTERVAL: Duration = Duration::from_millis(100);
const MAX_CONTROL_LINE: usize = 64 * 1024;

extern "C" fn request_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

pub(crate) fn create_key_file(path: &Path) -> Result<PeerKey, String> {
    let mut private_key = [0_u8; 32];
    if let Err(error) =
        fs::File::open("/dev/urandom").and_then(|mut random| random.read_exact(&mut private_key))
    {
        private_key.zeroize();
        return Err(format!("could not read /dev/urandom: {error}"));
    }

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => {
            private_key.zeroize();
            return Err(format!("could not create {}: {error}", path.display()));
        }
    };
    if let Err(error) = file.write_all(&private_key).and_then(|_| file.sync_all()) {
        private_key.zeroize();
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("could not write private key: {error}"));
    }

    let private = boringtun::x25519::StaticSecret::from(private_key);
    let public = boringtun::x25519::PublicKey::from(&private);
    private_key.zeroize();
    Ok(*public.as_bytes())
}

pub(crate) fn send_control(socket_path: &str, request: &str) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|error| format!("could not connect to {}: {error}", socket_path))?;
    let mut payload = request.as_bytes().to_vec();
    payload.push(b'\n');
    let write_result = stream.write_all(&payload);
    payload.zeroize();
    write_result.map_err(|error| format!("could not send control request: {error}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| format!("could not finish control request: {error}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("could not read control response: {error}"))?;
    let response = response.trim();
    if let Some(message) = response.strip_prefix("OK") {
        let message = message.trim();
        if !message.is_empty() {
            println!("{message}");
        }
        Ok(())
    } else if let Some(message) = response.strip_prefix("ERR ") {
        Err(message.to_owned())
    } else {
        Err(format!("invalid response from control socket: {response}"))
    }
}

#[derive(Clone)]
struct PeerRecord {
    endpoint: Option<SocketAddr>,
    keepalive: Option<Duration>,
    allowed_ips: Vec<AllowedIp>,
}

struct Runtime {
    device: Option<Device>,
    tun_name: String,
    addresses: Vec<InterfaceAddress>,
    link_up: bool,
    auto_routes: bool,
    peers: HashMap<PeerKey, PeerRecord>,
    routes: HashMap<AllowedIp, bool>,
    shutdown_requested: bool,
}

pub(crate) fn run_device(mut options: RunOptions) -> Result<(), String> {
    STOP.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(
            libc::SIGINT,
            request_stop as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            request_stop as *const () as libc::sighandler_t,
        );
    }
    ensure_interface_absent(&options.tun_name)?;

    let mut device_config = DeviceConfig::new(
        options.private_key.0,
        options.listen,
        options.tun_name.clone(),
    );
    device_config.dual_stack = options.dual_stack;
    if let Some(workers) = options.workers {
        device_config.workers = workers;
    }
    if let Some(rate_limit) = options.handshake_rate_limit {
        device_config.handshake_rate_limit = rate_limit;
    }
    let device = match Device::new(device_config) {
        Ok(device) => device,
        Err(error) => return Err(error.to_string()),
    };
    options.private_key.0.zeroize();

    let mut configured_addresses = Vec::new();
    let mut link_up = false;
    let setup_result = (|| {
        ip_checked(&[
            "link".into(),
            "set".into(),
            "dev".into(),
            options.tun_name.clone(),
            "mtu".into(),
            options.mtu.to_string(),
        ])?;
        for address in &options.addresses {
            add_interface_address(&options.tun_name, *address)?;
            configured_addresses.push(*address);
        }
        ip_checked(&[
            "link".into(),
            "set".into(),
            "dev".into(),
            options.tun_name.clone(),
            "up".into(),
        ])?;
        link_up = true;
        Ok::<(), String>(())
    })();

    if let Err(error) = setup_result {
        let _ = cleanup_interface(&options.tun_name, &configured_addresses, link_up);
        let mut device = device;
        let _ = device.shutdown();
        return Err(error);
    }

    let listener = match bind_control_socket(&options.socket_path) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = cleanup_interface(&options.tun_name, &configured_addresses, link_up);
            let mut device = device;
            let _ = device.shutdown();
            return Err(error);
        }
    };

    println!(
        "READY tun={} listen={} public_key={} socket={}",
        options.tun_name,
        device.listen_addr(),
        encode_hex(&device.public_key()),
        options.socket_path.display()
    );

    let mut runtime = Runtime {
        device: Some(device),
        tun_name: options.tun_name,
        addresses: configured_addresses,
        link_up,
        auto_routes: options.auto_routes,
        peers: HashMap::new(),
        routes: HashMap::new(),
        shutdown_requested: false,
    };

    let serve_result = serve(&listener, &mut runtime);
    let cleanup_result = runtime.cleanup();
    drop(listener);
    if let Err(error) = fs::remove_file(&options.socket_path) {
        if error.kind() != io::ErrorKind::NotFound {
            eprintln!("portal: could not remove control socket: {error}");
        }
    }
    serve_result?;
    cleanup_result
}

fn serve(listener: &UnixListener, runtime: &mut Runtime) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("could not configure control socket: {error}"))?;
    while !STOP.load(Ordering::Relaxed) && !runtime.shutdown_requested {
        if let Some(device) = runtime.device.as_ref() {
            device
                .health()
                .map_err(|error| format!("WireGuard device failed: {error}"))?;
        }
        match listener.accept() {
            Ok((stream, _)) => handle_stream(stream, runtime),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(LOOP_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("control socket failed: {error}")),
        }
    }
    Ok(())
}

fn handle_stream(mut stream: UnixStream, runtime: &mut Runtime) {
    let _ = stream.set_read_timeout(Some(CONTROL_READ_TIMEOUT));
    let mut line = String::new();
    let read_result = match stream.try_clone() {
        Ok(reader) => reader
            .take(MAX_CONTROL_LINE as u64)
            .read_to_string(&mut line),
        Err(error) => {
            let _ = stream
                .write_all(format!("ERR could not clone control socket: {error}\n").as_bytes());
            return;
        }
    };
    let response = match read_result {
        Ok(_) if line.len() >= MAX_CONTROL_LINE => Err("control request is too large".to_owned()),
        Ok(_) if !line.ends_with('\n') => Err("control request must end with a newline".to_owned()),
        Ok(_) if line[..line.len() - 1].contains('\n') => {
            Err("control socket accepts one request per connection".to_owned())
        }
        Ok(_) => runtime.handle_request(line.trim()),
        Err(error) => Err(format!("could not read control request: {error}")),
    };
    line.zeroize();
    let response = match response {
        Ok(message) => format!("OK {message}\n"),
        Err(message) => format!("ERR {}\n", one_line(&message)),
    };
    let _ = stream.write_all(response.as_bytes());
}

impl Runtime {
    fn handle_request(&mut self, request: &str) -> Result<String, String> {
        let fields = request.split_whitespace().collect::<Vec<_>>();
        let Some(command) = fields.first().copied() else {
            return Err("empty control request".into());
        };
        match command {
            "peer-upsert" => self.peer_upsert(&fields),
            "peer-remove" => self.peer_remove(&fields),
            "endpoint-set" => self.endpoint_set(&fields),
            "endpoint-clear" => self.endpoint_clear(&fields),
            "stats" => self.stats(),
            "peer-stats" => self.peer_stats(&fields),
            "health" => self.health(),
            "status" => self.status(),
            "list" => self.list_peers(),
            "shutdown" if fields.len() == 1 => {
                self.shutdown_requested = true;
                Ok("shutdown requested".into())
            }
            "shutdown" => Err("shutdown takes no arguments".into()),
            _ => Err(format!("unknown control request `{command}`")),
        }
    }

    fn peer_upsert(&mut self, fields: &[&str]) -> Result<String, String> {
        if fields.len() != 6 {
            return Err("peer-upsert expects key, psk, endpoint, keepalive and allowed IPs".into());
        }
        let public_key = parse_key_hex(fields[1])?;
        let preshared_key = parse_optional_key(fields[2])?.map(SecretKey);
        let requested_endpoint = parse_optional(fields[3])
            .map(|value| {
                value
                    .parse::<SocketAddr>()
                    .map_err(|error| format!("invalid endpoint: {error}"))
            })
            .transpose()?;
        let keepalive = parse_optional(fields[4])
            .map(|value| {
                let seconds = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid keepalive: {error}"))?;
                if seconds == 0 || seconds > u16::MAX as u64 {
                    return Err(String::from(
                        "keepalive must be between 1 and 65535 seconds",
                    ));
                }
                Ok(Duration::from_secs(seconds))
            })
            .transpose()?;
        let allowed_ips = if fields[5] == "-" {
            Vec::new()
        } else {
            fields[5]
                .split(',')
                .map(|value| {
                    value
                        .parse::<AllowedIp>()
                        .map_err(|error| format!("invalid allowed IP `{value}`: {error}"))
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let old_record = self.peers.get(&public_key).cloned();
        let record = PeerRecord {
            endpoint: requested_endpoint
                .or_else(|| old_record.as_ref().and_then(|peer| peer.endpoint)),
            keepalive,
            allowed_ips,
        };
        let mut staged = self.peers.clone();
        staged.insert(public_key, record.clone());
        let desired_routes = self.desired_routes(&staged);
        let newly_added = self.add_missing_routes(&desired_routes)?;

        let peer_config = PeerConfig {
            public_key,
            preshared_key: preshared_key.as_ref().map(|key| key.0),
            endpoint: requested_endpoint,
            persistent_keepalive: keepalive,
            allowed_ips: record.allowed_ips.clone(),
        };
        if let Err(error) = self
            .device
            .as_ref()
            .expect("running device")
            .upsert_peer(peer_config)
        {
            self.rollback_new_routes(&newly_added);
            return Err(error.to_string());
        }

        self.peers = staged;
        let stale_route_errors = self.remove_stale_routes(&desired_routes);
        if stale_route_errors.is_empty() {
            Ok(format!("peer {} upserted", encode_hex(&public_key)))
        } else {
            Err(format!(
                "peer was updated, but stale host route cleanup failed: {}",
                stale_route_errors.join("; ")
            ))
        }
    }

    fn peer_remove(&mut self, fields: &[&str]) -> Result<String, String> {
        if fields.len() != 2 {
            return Err("peer-remove expects one public key".into());
        }
        let public_key = parse_key_hex(fields[1])?;
        self.device
            .as_ref()
            .expect("running device")
            .remove_peer(&public_key)
            .map_err(|error| error.to_string())?;
        self.peers.remove(&public_key);
        let desired = self.desired_routes(&self.peers);
        let errors = self.remove_stale_routes(&desired);
        if errors.is_empty() {
            Ok(format!("peer {} removed", encode_hex(&public_key)))
        } else {
            Err(format!(
                "peer was removed, but host route cleanup failed: {}",
                errors.join("; ")
            ))
        }
    }

    fn endpoint_set(&mut self, fields: &[&str]) -> Result<String, String> {
        if fields.len() != 3 {
            return Err("endpoint-set expects a public key and socket address".into());
        }
        let public_key = parse_key_hex(fields[1])?;
        let endpoint = fields[2]
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid endpoint: {error}"))?;
        if !self.peers.contains_key(&public_key) {
            return Err("peer is not managed by this CLI".into());
        }
        self.device
            .as_ref()
            .expect("running device")
            .set_peer_endpoint(&public_key, endpoint)
            .map_err(|error| error.to_string())?;
        self.peers
            .get_mut(&public_key)
            .expect("peer checked")
            .endpoint = Some(endpoint);
        Ok(format!(
            "endpoint for {} set to {endpoint}",
            encode_hex(&public_key)
        ))
    }

    fn endpoint_clear(&mut self, fields: &[&str]) -> Result<String, String> {
        if fields.len() != 2 {
            return Err("endpoint-clear expects one public key".into());
        }
        let public_key = parse_key_hex(fields[1])?;
        if !self.peers.contains_key(&public_key) {
            return Err("peer is not managed by this CLI".into());
        }
        self.device
            .as_ref()
            .expect("running device")
            .clear_peer_endpoint(&public_key)
            .map_err(|error| error.to_string())?;
        self.peers
            .get_mut(&public_key)
            .expect("peer checked")
            .endpoint = None;
        Ok(format!("endpoint for {} cleared", encode_hex(&public_key)))
    }

    fn stats(&self) -> Result<String, String> {
        let stats = self.device.as_ref().expect("running device").stats();
        Ok(format!(
            "received_udp={} received_tun={} dropped={} timer_send_errors={} udp_send_errors={}",
            stats.received_udp_packets,
            stats.received_tun_packets,
            stats.dropped_packets,
            stats.timer_send_errors,
            stats.udp_send_errors
        ))
    }

    fn peer_stats(&self, fields: &[&str]) -> Result<String, String> {
        if fields.len() != 2 {
            return Err("peer-stats expects one public key".into());
        }
        let key = parse_key_hex(fields[1])?;
        let stats = self
            .device
            .as_ref()
            .expect("running device")
            .peer_stats(&key)
            .map_err(|error| error.to_string())?;
        Ok(format!(
            "peer={} tx_packets={} tx_bytes={} rx_packets={} rx_bytes={}",
            encode_hex(&key),
            stats.tx_packets,
            stats.tx_bytes,
            stats.rx_packets,
            stats.rx_bytes
        ))
    }

    fn health(&self) -> Result<String, String> {
        self.device
            .as_ref()
            .expect("running device")
            .health()
            .map_err(|error| error.to_string())?;
        Ok("healthy".into())
    }

    fn status(&self) -> Result<String, String> {
        let device = self.device.as_ref().expect("running device");
        device.health().map_err(|error| error.to_string())?;
        Ok(format!(
            "tun={} listen={} public_key={} peers={}",
            self.tun_name,
            device.listen_addr(),
            encode_hex(&device.public_key()),
            self.peers.len()
        ))
    }

    fn list_peers(&self) -> Result<String, String> {
        let mut peers = self
            .peers
            .iter()
            .map(|(key, peer)| {
                let ips = if peer.allowed_ips.is_empty() {
                    "-".to_owned()
                } else {
                    peer.allowed_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                format!(
                    "{} endpoint={} keepalive={} allowed_ips={}",
                    encode_hex(key),
                    peer.endpoint
                        .map(|endpoint| endpoint.to_string())
                        .unwrap_or_else(|| "-".into()),
                    peer.keepalive
                        .map(|value| value.as_secs().to_string())
                        .unwrap_or_else(|| "-".into()),
                    ips
                )
            })
            .collect::<Vec<_>>();
        peers.sort();
        Ok(if peers.is_empty() {
            "no peers".into()
        } else {
            peers.join("; ")
        })
    }

    fn desired_routes(&self, peers: &HashMap<PeerKey, PeerRecord>) -> HashSet<AllowedIp> {
        if !self.auto_routes {
            return HashSet::new();
        }
        peers
            .values()
            .flat_map(|peer| peer.allowed_ips.iter().copied())
            .collect()
    }

    fn add_missing_routes(
        &mut self,
        desired: &HashSet<AllowedIp>,
    ) -> Result<Vec<AllowedIp>, String> {
        let mut added = Vec::new();
        for route in desired {
            if self.routes.contains_key(route) {
                continue;
            }
            match ensure_host_route(&self.tun_name, *route) {
                Ok(owned) => {
                    self.routes.insert(*route, owned);
                    added.push(*route);
                }
                Err(error) => {
                    self.rollback_new_routes(&added);
                    return Err(error);
                }
            }
        }
        Ok(added)
    }

    fn rollback_new_routes(&mut self, routes: &[AllowedIp]) {
        for route in routes.iter().rev() {
            match self.routes.get(route).copied() {
                Some(true) => {
                    if delete_host_route(&self.tun_name, *route).is_ok() {
                        self.routes.remove(route);
                    }
                }
                Some(false) => {
                    self.routes.remove(route);
                }
                None => {}
            }
        }
    }

    fn remove_stale_routes(&mut self, desired: &HashSet<AllowedIp>) -> Vec<String> {
        let stale = self
            .routes
            .keys()
            .filter(|route| !desired.contains(route))
            .copied()
            .collect::<Vec<_>>();
        let mut errors = Vec::new();
        for route in stale {
            let owned = self.routes.get(&route).copied().unwrap_or(false);
            if owned {
                if let Err(error) = delete_host_route(&self.tun_name, route) {
                    errors.push(error);
                    continue;
                }
            }
            self.routes.remove(&route);
        }
        errors
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let desired = HashSet::new();
        let mut errors = self.remove_stale_routes(&desired);
        if let Err(error) = cleanup_interface(&self.tun_name, &self.addresses, self.link_up) {
            errors.push(error);
        }
        if let Some(mut device) = self.device.take() {
            if let Err(error) = device.shutdown() {
                errors.push(format!("device shutdown failed: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn bind_control_socket(path: &Path) -> Result<UnixListener, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => match UnixStream::connect(path) {
            Ok(_) => {
                return Err(format!(
                    "control socket {} is already in use",
                    path.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                fs::remove_file(path).map_err(|error| {
                    format!("could not remove stale socket {}: {error}", path.display())
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "could not inspect existing socket {}: {error}",
                    path.display()
                ));
            }
        },
        Ok(_) => {
            return Err(format!(
                "control socket path {} already exists and is not a socket",
                path.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "could not inspect control socket path {}: {error}",
                path.display()
            ));
        }
    }
    let listener = UnixListener::bind(path)
        .map_err(|error| format!("could not bind control socket {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        let _ = fs::remove_file(path);
        format!(
            "could not secure control socket {}: {error}",
            path.display()
        )
    })?;
    if let Err(error) = listener.set_nonblocking(true) {
        drop(listener);
        let _ = fs::remove_file(path);
        return Err(format!("could not configure control socket: {error}"));
    }
    Ok(listener)
}

fn ensure_interface_absent(name: &str) -> Result<(), String> {
    let output = run_ip(&["link".into(), "show".into(), "dev".into(), name.into()])?;
    if output.status.success() {
        Err(format!(
            "interface `{name}` already exists; refusing to change it"
        ))
    } else {
        Ok(())
    }
}

fn add_interface_address(name: &str, address: InterfaceAddress) -> Result<(), String> {
    let (family, address) = match address.address {
        IpAddr::V4(_) => ("-4", address.to_string()),
        IpAddr::V6(_) => ("-6", address.to_string()),
    };
    ip_checked(&[
        family.into(),
        "addr".into(),
        "add".into(),
        address.into(),
        "dev".into(),
        name.into(),
    ])
}

fn cleanup_interface(
    name: &str,
    addresses: &[InterfaceAddress],
    link_up: bool,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for address in addresses.iter().rev() {
        let family = if address.address.is_ipv4() {
            "-4"
        } else {
            "-6"
        };
        if let Err(error) = ip_checked(&[
            family.into(),
            "addr".into(),
            "del".into(),
            address.to_string(),
            "dev".into(),
            name.into(),
        ]) {
            errors.push(error);
        }
    }
    if link_up {
        if let Err(error) = ip_checked(&[
            "link".into(),
            "set".into(),
            "dev".into(),
            name.into(),
            "down".into(),
        ]) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn ensure_host_route(interface: &str, route: AllowedIp) -> Result<bool, String> {
    if route.prefix_len() == 0 {
        return Err(format!(
            "automatic default route {route} is disabled to avoid routing WireGuard endpoint traffic back into the tunnel; use --no-auto-routes and configure policy routing separately"
        ));
    }
    let family = if route.network().is_ipv4() {
        "-4"
    } else {
        "-6"
    };
    let prefix = route.to_string();
    let output = run_ip(&[
        family.into(),
        "route".into(),
        "add".into(),
        prefix.clone(),
        "dev".into(),
        interface.into(),
    ])?;
    if output.status.success() {
        return Ok(true);
    }
    if route_exists_via(family, &prefix, interface)? {
        Ok(false)
    } else {
        Err(command_failure("ip", &output))
    }
}

fn delete_host_route(interface: &str, route: AllowedIp) -> Result<(), String> {
    let family = if route.network().is_ipv4() {
        "-4"
    } else {
        "-6"
    };
    let prefix = route.to_string();
    if !route_exists_via(family, &prefix, interface)? {
        return Ok(());
    }
    ip_checked(&[
        family.into(),
        "route".into(),
        "del".into(),
        prefix,
        "dev".into(),
        interface.into(),
    ])
}

fn route_exists_via(family: &str, prefix: &str, interface: &str) -> Result<bool, String> {
    let output = run_ip(&[
        family.into(),
        "route".into(),
        "show".into(),
        "exact".into(),
        prefix.into(),
    ])?;
    if !output.status.success() {
        return Err(command_failure("ip", &output));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text.lines().any(|line| {
        let words = line.split_whitespace().collect::<Vec<_>>();
        words
            .windows(2)
            .any(|pair| pair[0] == "dev" && pair[1] == interface)
    }))
}

fn run_ip(args: &[String]) -> Result<Output, String> {
    let binary = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"]
        .into_iter()
        .find(|path| Path::new(*path).is_file())
        .ok_or_else(|| "could not find iproute2 `ip` executable".to_owned())?;
    Command::new(binary)
        .args(args)
        .output()
        .map_err(|error| format!("could not execute iproute2: {error}"))
}

fn ip_checked(args: &[String]) -> Result<(), String> {
    let output = run_ip(args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_failure("ip", &output))
    }
}

fn command_failure(name: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        format!("`{name}` exited with status {}", output.status)
    } else {
        format!("`{name}` failed: {stderr}")
    }
}

pub(crate) fn validate_interface_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 15
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err("TUN name must be 1-15 ASCII letters, digits, `_`, `-` or `.` and cannot start with `-`".into());
    }
    Ok(())
}
