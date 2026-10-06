use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};

use portal::AllowedIp;
use zeroize::Zeroize;

use crate::InterfaceAddress;
use portal::PeerKey;

use super::HostPlatform;

pub(crate) mod control_socket;

pub(crate) struct LinuxPlatform;

static STOP: AtomicBool = AtomicBool::new(false);

// Signal-safe callback that asks the runtime loop to stop and release host resources.
extern "C" fn request_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

impl HostPlatform for LinuxPlatform {
    // Reset the shutdown flag and register handlers for terminal and service-manager signals.
    fn install_signal_handlers(&self) {
        STOP.store(false, Ordering::Release);
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
    }

    // Read the flag set by the SIGINT or SIGTERM handler.
    fn stop_requested(&self) -> bool {
        STOP.load(Ordering::Acquire)
    }

    // Use iproute2 to ensure startup will not modify an interface owned by someone else.
    fn ensure_interface_absent(&self, name: &str) -> Result<(), String> {
        let output = run_ip(&["link".into(), "show".into(), "dev".into(), name.into()])?;
        if output.status.success() {
            Err(format!(
                "interface `{name}` already exists; refusing to change it"
            ))
        } else {
            Ok(())
        }
    }

    // Apply the requested MTU to the named TUN interface.
    fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), String> {
        ip_checked(&[
            "link".into(),
            "set".into(),
            "dev".into(),
            name.into(),
            "mtu".into(),
            mtu.to_string(),
        ])
    }

    // Add an address using the matching iproute2 address family.
    fn add_interface_address(&self, name: &str, address: InterfaceAddress) -> Result<(), String> {
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

    // Bring the configured TUN interface up.
    fn set_interface_up(&self, name: &str) -> Result<(), String> {
        ip_checked(&[
            "link".into(),
            "set".into(),
            "dev".into(),
            name.into(),
            "up".into(),
        ])
    }

    // Remove configured addresses and lower the link, collecting every cleanup failure.
    fn cleanup_interface(
        &self,
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

    // Add a route unless it is a default route, and report whether this call created it.
    fn ensure_host_route(&self, interface: &str, route: AllowedIp) -> Result<bool, String> {
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

    // Delete the route only when it currently points through this runtime's interface.
    fn delete_host_route(&self, interface: &str, route: AllowedIp) -> Result<(), String> {
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
}

/// Generate a WireGuard key, save the private bytes with mode 0600, and return the public key.
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

/// Validate a Linux interface name against kernel length and character restrictions.
pub(crate) fn validate_interface_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 15
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(
            "TUN name must be 1-15 ASCII letters, digits, `_`, `-` or `.` and cannot start with `-`"
                .into(),
        );
    }
    Ok(())
}

// Check whether an exact route is already installed through the requested interface.
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

// Locate and execute iproute2 without invoking a shell.
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

// Run an iproute2 operation and turn a nonzero exit status into a readable error.
fn ip_checked(args: &[String]) -> Result<(), String> {
    let output = run_ip(args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_failure("ip", &output))
    }
}

// Build an error message from iproute2's stderr or exit status.
fn command_failure(name: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        format!("`{name}` exited with status {}", output.status)
    } else {
        format!("`{name}` failed: {stderr}")
    }
}
