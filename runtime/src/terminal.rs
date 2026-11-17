use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::TerminalConfig;

/// Owns the foreground OpenSSH process used by the first terminal iteration.
pub(crate) struct TerminalSupervisor {
    config: TerminalConfig,
    child: Option<Child>,
    config_file: PathBuf,
    last_exit: Option<String>,
    restart_after: Option<Instant>,
}

impl TerminalSupervisor {
    pub(crate) fn new(config: TerminalConfig) -> Self {
        let config_file = config.host_key_dir.join("sshd_config");
        Self {
            config,
            child: None,
            config_file,
            last_exit: None,
            restart_after: None,
        }
    }

    pub(crate) fn status(&self) -> &'static str {
        if self.child.is_some() {
            "running"
        } else if self.last_exit.is_some() {
            "failed"
        } else {
            "stopped"
        }
    }
    pub(crate) fn listen_port(&self) -> u16 {
        self.config.listen_port
    }
    pub(crate) fn user(&self) -> &str {
        &self.config.user
    }

    pub(crate) fn last_exit(&self) -> Option<&str> {
        self.last_exit.as_deref()
    }

    pub(crate) fn reconcile(&mut self, addresses: &[String]) -> Result<(), String> {
        if !self.config.enabled || addresses.is_empty() {
            return Ok(());
        }
        if let Some(child) = self.child.as_mut() {
            match child
                .try_wait()
                .map_err(|e| format!("could not inspect sshd: {e}"))?
            {
                None => return Ok(()),
                Some(status) => {
                    self.last_exit = Some(status.to_string());
                    self.child = None;
                    self.restart_after = Some(Instant::now() + Duration::from_secs(2));
                }
            }
        }
        if self.restart_after.is_some_and(|at| at > Instant::now()) {
            return Ok(());
        }
        self.prepare_config(addresses)?;
        let check = Command::new("sshd")
            .args(["-t", "-f"])
            .arg(&self.config_file)
            .output()
            .map_err(|e| format!("sshd is unavailable: {e}"))?;
        if !check.status.success() {
            return Err(format!(
                "sshd configuration check failed: {}",
                String::from_utf8_lossy(&check.stderr).trim()
            ));
        }
        let child = Command::new("sshd")
            .args(["-D", "-e", "-f"])
            .arg(&self.config_file)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("could not start sshd: {e}"))?;
        self.child = Some(child);
        self.last_exit = None;
        self.restart_after = None;
        Ok(())
    }

    fn prepare_config(&self, addresses: &[String]) -> Result<(), String> {
        validate_user(&self.config.user)?;
        fs::create_dir_all(&self.config.host_key_dir)
            .map_err(|e| format!("could not create SSH host-key directory: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.config.host_key_dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("could not secure SSH host-key directory: {e}"))?;
        }
        let key = self.config.host_key_dir.join("ssh_host_ed25519_key");
        if !key.exists() {
            let result = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .output()
                .map_err(|e| format!("could not create SSH host key: {e}"))?;
            if !result.status.success() {
                return Err(format!(
                    "ssh-keygen failed: {}",
                    String::from_utf8_lossy(&result.stderr).trim()
                ));
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key)
                .map_err(|e| format!("could not inspect SSH host key: {e}"))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o600 {
                return Err("SSH host key must have permissions 0600".into());
            }
        }
        let authorized = self.config.authorized_keys_file.display();
        let mut text = String::new();
        for address in addresses {
            let ip: IpAddr = address
                .parse()
                .map_err(|_| format!("invalid terminal address `{address}`"))?;
            text.push_str("ListenAddress ");
            if ip.is_ipv6() {
                text.push('[');
            }
            text.push_str(address);
            if ip.is_ipv6() {
                text.push(']');
            }
            text.push(':');
            text.push_str(&self.config.listen_port.to_string());
            text.push('\n');
        }
        text.push_str(&format!(
            "HostKey {}\nAuthorizedKeysFile {}\nAllowUsers {}\n",
            key.display(),
            authorized,
            self.config.user
        ));
        text.push_str(&format!(
            "MaxSessions {}\nClientAliveInterval {}\nClientAliveCountMax 1\n",
            self.config.max_sessions, self.config.idle_timeout_seconds
        ));
        text.push_str("PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nAllowTcpForwarding no\nX11Forwarding no\nPermitTunnel no\nGatewayPorts no\nPermitUserEnvironment no\nUsePAM no\nPidFile none\n");
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&self.config_file)
            .map_err(|e| format!("could not write sshd configuration: {e}"))?;
        file.write_all(text.as_bytes())
            .map_err(|e| format!("could not write sshd configuration: {e}"))?;
        Ok(())
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), String> {
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            {
                // Give sshd a chance to close sessions and flush diagnostics.
                let _ = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            std::thread::sleep(Duration::from_millis(100));
            if child
                .try_wait()
                .map_err(|e| format!("could not stop sshd: {e}"))?
                .is_none()
            {
                let _ = child.kill();
            }
            child
                .wait()
                .map_err(|e| format!("could not stop sshd: {e}"))?;
        }
        Ok(())
    }
}

fn validate_user(user: &str) -> Result<(), String> {
    if user.is_empty()
        || user.len() > 32
        || user
            .bytes()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')))
    {
        return Err("terminal user must be a simple system account name".into());
    }
    let status = Command::new("id")
        .args(["-u", "--", user])
        .status()
        .map_err(|e| format!("could not inspect terminal user: {e}"))?;
    if !status.success() {
        return Err(format!("terminal user `{user}` does not exist"));
    }
    Ok(())
}
