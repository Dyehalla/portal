use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, chown};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use md4::{Digest, Md4};
use zeroize::{Zeroize, Zeroizing};

use crate::SmbConfig;

const START_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// A separate smbd process tree and private, per-run Samba databases.
pub(crate) struct SmbService {
    child: Option<Child>,
    _directory: PrivateDirectory,
    log: File,
    access: Option<std::sync::Arc<crate::smb::SmbAccess>>,
}

struct PrivateDirectory(PathBuf);

struct Identity {
    name: String,
    uid: u32,
    account_uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

impl Identity {
    fn apply(&self, command: &mut Command) -> Result<(), String> {
        let current = unsafe { libc::geteuid() };
        if current != 0 && self.uid != current {
            return Err("changing the Samba process user requires a privileged runtime".into());
        }
        let uid = self.uid;
        let gid = self.gid;
        let groups = self.groups.clone();
        // Only async-signal-safe syscalls execute between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if current == 0 && uid != 0 {
                    if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                        || libc::setgid(gid) != 0
                        || libc::setuid(uid) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}

fn id_value(option: &str, user: Option<&str>) -> Result<String, String> {
    let mut command = Command::new(binary("id")?);
    command.arg(option);
    if let Some(user) = user {
        command.args(["--", user]);
    }
    let output = command
        .output()
        .map_err(|error| format!("could not resolve SMB user: {error}"))?;
    if !output.status.success() {
        return Err("SMB user does not exist".into());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "SMB user information is not UTF-8".into())
}

fn resolve_identity(user: Option<&str>, as_root: bool) -> Result<Identity, String> {
    let current = unsafe { libc::geteuid() };
    if as_root && current != 0 {
        return Err("--smb-as-root requires an already privileged runtime".into());
    }
    // sudo callers keep their user identity even though WireGuard setup needs root.
    let sudo_uid = if current == 0 {
        std::env::var("SUDO_UID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|uid| *uid != 0)
            .map(|uid| uid.to_string())
    } else {
        None
    };
    let name = id_value("-un", user.or(sudo_uid.as_deref()))?;
    validate_name(&name, "SMB user")?;
    let uid = id_value("-u", Some(&name))?
        .parse::<u32>()
        .map_err(|_| "invalid SMB uid")?;
    let gid = id_value("-g", Some(&name))?
        .parse::<u32>()
        .map_err(|_| "invalid SMB gid")?;
    let groups = id_value("-G", Some(&name))?
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "invalid SMB group".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !as_root && uid == 0 {
        return Err("choose a non-root --smb-user or explicitly enable --smb-as-root".into());
    }
    if !as_root && current != 0 && current != uid {
        return Err("an unprivileged runtime can only run Samba as its own user".into());
    }
    Ok(Identity {
        name,
        account_uid: uid,
        uid: if as_root { 0 } else { uid },
        gid: if as_root { 0 } else { gid },
        groups: if as_root { vec![0] } else { groups },
    })
}

fn handoff_directory(path: &Path, identity: &Identity) -> Result<(), String> {
    if unsafe { libc::geteuid() } == identity.uid {
        return Ok(());
    }
    chown(
        path.join("private/smbpasswd"),
        Some(identity.uid),
        Some(identity.gid),
    )
    .map_err(|e| format!("could not assign SMB password database ownership: {e}"))?;
    // Everything is still inaccessible to the target user until the parent is handed off last.
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        chown(
            entry.map_err(|e| e.to_string())?.path(),
            Some(identity.uid),
            Some(identity.gid),
        )
        .map_err(|e| format!("could not assign Samba state ownership: {e}"))?;
    }
    chown(path, Some(identity.uid), Some(identity.gid))
        .map_err(|e| format!("could not assign Samba directory ownership: {e}"))
}

impl PrivateDirectory {
    fn new() -> Result<Self, String> {
        for _ in 0..16 {
            let path = std::env::temp_dir().join(format!(
                "portal-smb-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!("could not create private Samba directory: {error}"));
                }
            }
        }
        Err("could not allocate private Samba directory".into())
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl SmbService {
    pub(crate) fn start(config: SmbConfig) -> Result<Self, String> {
        Self::start_impl(config, false)
    }

    fn start_impl(mut config: SmbConfig, allow_loopback: bool) -> Result<Self, String> {
        validate_name(&config.name, "share name")?;
        let identity = resolve_identity(config.user.as_deref(), config.as_root)?;
        config.user = Some(identity.name.clone());
        let port = config
            .port
            .unwrap_or(if config.as_root { 445 } else { 1445 });
        if port == 0 {
            return Err("SMB port must be nonzero".into());
        }
        config.port = Some(port);
        if ["global", "homes", "printers"].contains(&config.name.to_ascii_lowercase().as_str()) {
            return Err("reserved Samba share name".into());
        }
        if config.listen.is_unspecified()
            || (!allow_loopback && config.listen.is_loopback())
            || config.listen.is_multicast()
            || config.allowed_peers.is_empty()
            || config.allowed_peers.iter().any(|ip| {
                ip.is_unspecified() || ip.is_multicast() || (!allow_loopback && ip.is_loopback())
            })
        {
            return Err("SMB requires a specific tunnel IP and allowed peer IPs".into());
        }
        let smbd = binary("smbd")?;
        let testparm = binary("testparm")?;
        config.root = fs::canonicalize(&config.root)
            .map_err(|error| format!("could not resolve SMB root: {error}"))?;
        if !config.root.is_dir() {
            return Err("--smb-root must be a directory".into());
        }
        let password = read_password(&config.password_file, identity.uid)?;
        let address = SocketAddr::new(config.listen, port);
        // Fail explicitly when a system Samba instance already owns this address/port.
        drop(
            TcpListener::bind(address)
                .map_err(|error| format!("SMB port {address} is unavailable: {error}"))?,
        );
        let directory = PrivateDirectory::new()?;
        for name in ["private", "state", "cache", "lock", "pid", "ncalrpc"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(directory.0.join(name))
                .map_err(|error| format!("could not prepare Samba directory: {error}"))?;
        }
        let configuration = render_config(&config, &directory.0)?;
        let path = directory.0.join("smb.conf");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("could not create Samba configuration: {error}"))?;
        file.write_all(configuration.as_bytes())
            .map_err(|error| format!("could not write Samba configuration: {error}"))?;
        drop(file);

        write_passdb(&directory.0.join("private/smbpasswd"), &identity, &password)?;
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.0.join("smbd.log"))
            .map_err(|error| format!("could not create Samba log: {error}"))?;
        let setup_log = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.0.join("setup.log"))
            .map_err(|e| e.to_string())?;
        // Hand off only this per-run directory; no system Samba files are changed.
        handoff_directory(&directory.0, &identity)?;
        let mut check = Command::new(testparm);
        check.arg("--suppress-prompt").arg(&path);
        identity.apply(&mut check)?;
        run_setup(check, &setup_log)?;
        let mut command = Command::new(smbd);
        command
            .args(["--foreground", "--no-process-group", "--debug-stdout"])
            .arg("--configfile")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
            .process_group(0);
        identity.apply(&mut command)?;
        let child = command
            .spawn()
            .map_err(|error| format!("could not start smbd: {error}"))?;
        let mut service = Self {
            child: Some(child),
            _directory: directory,
            log,
            access: Some(std::sync::Arc::new(crate::smb::SmbAccess {
                share: crate::models::SmbShare {
                    name: config.name.clone(),
                    host: config.listen.to_string(),
                    port: u32::from(port),
                    read_only: true,
                },
                username: identity.name.clone(),
                password,
                allowed_peers: config.allowed_peers.clone(),
            })),
        };
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            service.health()?;
            if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
                thread::sleep(Duration::from_millis(100));
                service.health()?;
                break;
            }
            if Instant::now() >= deadline {
                return Err("Samba did not start listening within 10 seconds".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        println!(
            "SMB read-only share: smb://{address}/{} user={}",
            config.name, identity.name
        );
        Ok(service)
    }

    pub(crate) fn access(&self) -> std::sync::Arc<crate::smb::SmbAccess> {
        self.access
            .as_ref()
            .expect("running Samba has connection metadata")
            .clone()
    }

    pub(crate) fn health(&mut self) -> Result<(), String> {
        match self.child.as_mut().expect("SMB child present").try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => Err(format!("smbd exited with {status}: {}", self.log_tail())),
            Err(error) => Err(format!("could not inspect smbd: {error}")),
        }
    }

    fn log_tail(&self) -> String {
        read_log_tail(&self.log, 2048)
    }

    pub(crate) fn stop(&mut self) -> Result<(), String> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let group = -(child.id() as libc::pid_t);
        unsafe {
            libc::kill(group, libc::SIGTERM);
        }
        let deadline = Instant::now() + STOP_TIMEOUT;
        let result = loop {
            match child.try_wait() {
                Ok(Some(_)) => break Ok(()),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                Ok(None) => break Err("Samba exceeded shutdown grace period".into()),
                Err(error) => break Err(format!("could not wait for Samba: {error}")),
            }
        };
        // Kill session children too, even if the parent has already exited.
        unsafe {
            libc::kill(group, libc::SIGKILL);
        }
        let _ = child.wait();
        result
    }
}

impl Drop for SmbService {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn binary(name: &str) -> Result<PathBuf, String> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| format!("{name} is not installed; install the Samba package"))
}

fn validate_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(format!(
            "invalid {label}: use 1-64 ASCII letters, digits, dots, underscores or hyphens"
        ));
    }
    Ok(())
}

fn config_path(path: &Path) -> Result<&str, String> {
    let value = path
        .to_str()
        .ok_or_else(|| "Samba paths must be UTF-8".to_owned())?;
    if value.trim() != value || value.chars().any(|c| c.is_control() || "%\\\"".contains(c)) {
        return Err(
            "Samba paths may not contain control characters, %, backslashes or quotes".into(),
        );
    }
    Ok(value)
}

fn render_config(config: &SmbConfig, directory: &Path) -> Result<String, String> {
    let root = config_path(&config.root)?;
    let directory = config_path(directory)?;
    let peers = config
        .allowed_peers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let listen = config.listen;
    let user = config
        .user
        .as_deref()
        .ok_or_else(|| "SMB user is unresolved".to_owned())?;
    let port = config
        .port
        .unwrap_or(if config.as_root { 445 } else { 1445 });
    let name = &config.name;
    Ok(format!(
        "[global]\n\
server role = standalone server\n\
security = user\n\
interfaces = {listen}\n\
bind interfaces only = yes\n\
smb ports = {port}\n\
server min protocol = SMB2_02\n\
map to guest = Never\n\
load printers = no\n\
disable spoolss = yes\n\
printing = bsd\n\
printcap name = /dev/null\n\
private dir = {directory}/private\n\
state directory = {directory}/state\n\
cache directory = {directory}/cache\n\
lock directory = {directory}/lock\n\
pid directory = {directory}/pid\n\
ncalrpc dir = {directory}/ncalrpc\n\
passdb backend = smbpasswd:{directory}/private/smbpasswd\n\
log file = {directory}/smbd.log\n\
max log size = 1024\n\
hosts allow = {peers}\n\
hosts deny = ALL\n\
[{name}]\n\
path = {root}\n\
read only = yes\n\
guest ok = no\n\
valid users = {user}\n\
follow symlinks = no\n\
wide links = no\n"
    ))
}

fn write_passdb(path: &Path, identity: &Identity, password: &str) -> Result<(), String> {
    let encoded = Zeroizing::new(
        password
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let mut hash = Md4::digest(encoded.as_slice());
    let mut hex = Zeroizing::new(String::with_capacity(32));
    for byte in hash.iter() {
        use std::fmt::Write as _;
        write!(&mut *hex, "{byte:02X}").expect("writing a string cannot fail");
    }
    hash.as_mut_slice().zeroize();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let record = Zeroizing::new(format!(
        "{}:{}:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:{}:[U          ]:LCT-{:08X}:\n",
        identity.name,
        identity.account_uid,
        hex.as_str(),
        now
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("could not create private SMB password database: {error}"))?;
    file.write_all(record.as_bytes())
        .map_err(|error| format!("could not write SMB password database: {error}"))
}

fn read_password(path: &Path, owner: u32) -> Result<Zeroizing<String>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("could not open SMB password file: {error}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || (metadata.uid() != unsafe { libc::geteuid() } && metadata.uid() != owner)
        || metadata.mode() & 0o077 != 0
    {
        return Err("SMB password file must be owner-only and owned by the runtime user".into());
    }
    let mut password = Zeroizing::new(String::new());
    file.take(1025)
        .read_to_string(&mut password)
        .map_err(|e| format!("could not read SMB password: {e}"))?;
    if password.ends_with('\n') {
        password.pop();
    }
    if password.is_empty() || password.len() > 1024 || password.chars().any(|c| c.is_control()) {
        return Err("SMB password must contain 1-1024 bytes with no control characters".into());
    }
    Ok(password)
}

fn read_log_tail(log: &File, limit: usize) -> String {
    let length = log.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    let start = length.saturating_sub(limit as u64);
    let mut bytes = vec![0; (length - start) as usize];
    let count = log.read_at(&mut bytes, start).unwrap_or(0);
    String::from_utf8_lossy(&bytes[..count]).into_owned()
}

fn run_setup(mut command: Command, log: &File) -> Result<(), String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log.try_clone().map_err(|e| e.to_string())?));
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not run Samba setup: {e}"))?;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(format!(
                    "Samba setup failed: {status}: {}",
                    read_log_tail(log, 4096)
                ));
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "Samba setup timed out or could not be monitored: {result:?}"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "client")]
    #[tokio::test]
    #[ignore = "requires Samba binaries and local TCP sockets; run as a non-root user"]
    async fn rootless_samba_serves_files() {
        let uid = unsafe { libc::geteuid() };
        assert_ne!(uid, 0, "run this test as a non-root user");
        let identity = resolve_identity(None, false).unwrap();
        assert_eq!(identity.uid, uid);
        assert!(resolve_identity(None, true).is_err());
        let directory = PrivateDirectory::new().unwrap();
        let root = directory.0.join("share");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("hello.txt"), b"rootless Samba\n").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("outside")).unwrap();
        let password = format!("{:032x}", rand::random::<u128>());
        let password_path = directory.0.join("password");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&password_path)
            .unwrap();
        file.write_all(password.as_bytes()).unwrap();
        drop(file);
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let config = SmbConfig {
            root: root.clone(),
            name: "documents".into(),
            listen: "127.0.0.1".parse().unwrap(),
            user: None,
            as_root: false,
            port: Some(port),
            password_file: password_path,
            allowed_peers: vec!["127.0.0.1".parse().unwrap()],
        };
        let mut service = SmbService::start_impl(config, true).unwrap();
        // Exercise the HTTP API before authenticating with the returned credentials.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_address = listener.local_addr().unwrap();
        let router = crate::api::router(crate::api::ApiState {
            downloads: None,
            smb: Some(service.access()),
        });
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let http_task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
        });
        let peer_url = format!("http://{http_address}");
        let shares = crate::list_shares(&peer_url).await.unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].port, u32::from(port));
        let connection = crate::prepare_smb_connection(&peer_url, "documents")
            .await
            .unwrap();
        assert_eq!(connection.share.host, "127.0.0.1");
        assert_eq!(connection.username, identity.name);
        assert_eq!(connection.password.as_str(), password);
        stop.send(()).unwrap();
        http_task.await.unwrap();
        let pid = service.child.as_ref().unwrap().id();
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let uids = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .unwrap();
        assert!(
            uids.split_whitespace()
                .all(|value| value.parse::<u32>().unwrap() == uid)
        );
        let auth = directory.0.join("auth");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&auth)
            .unwrap();
        write!(
            file,
            "username = {}\npassword = {}\n",
            connection.username,
            connection.password.as_str()
        )
        .unwrap();
        drop(file);
        let downloaded = directory.0.join("downloaded");
        let client = |operation: &str| {
            Command::new(binary("smbclient").unwrap())
                .arg("//portal-peer/documents")
                .arg("-I")
                .arg("127.0.0.1")
                .arg("-p")
                .arg(port.to_string())
                .arg("-A")
                .arg(&auth)
                .arg("--timeout=5")
                .arg("-c")
                .arg(operation)
                .output()
                .unwrap()
        };
        let output = client(&format!("get hello.txt {}", downloaded.display()));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&downloaded).unwrap(), b"rootless Samba\n");
        let output = client(&format!("put {} forbidden.txt", downloaded.display()));
        assert!(
            !root.join("forbidden.txt").exists(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let leaked = directory.0.join("leaked");
        let _ = client(&format!("get outside {}", leaked.display()));
        assert!(!leaked.exists() || fs::metadata(leaked).unwrap().len() == 0);
        service.stop().unwrap();
        assert!(
            TcpStream::connect_timeout(
                &SocketAddr::new("127.0.0.1".parse().unwrap(), port),
                Duration::from_millis(100)
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "requires installed Samba testparm"]
    fn samba_accepts_generated_configuration() {
        let directory = PrivateDirectory::new().unwrap();
        for name in ["private", "state", "cache", "lock", "pid", "ncalrpc"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(directory.0.join(name))
                .unwrap();
        }
        let root = directory.0.join("shared documents");
        fs::create_dir(&root).unwrap();
        let config = SmbConfig {
            root: root.clone(),
            name: "documents".into(),
            listen: "10.20.0.1".parse().unwrap(),
            user: Some("reader".into()),
            as_root: false,
            port: Some(445),
            password_file: "/unused".into(),
            allowed_peers: vec!["10.20.0.2".parse().unwrap()],
        };
        let path = directory.0.join("smb.conf");
        fs::write(&path, render_config(&config, &directory.0).unwrap()).unwrap();
        let mut command = Command::new(binary("testparm").unwrap());
        command.arg("--suppress-prompt").arg(&path);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "testparm: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Check Samba's interpreted values, including paths containing spaces.
        for (section, parameter, expected) in [
            ("global", "interfaces", "10.20.0.1"),
            ("global", "smb ports", "445"),
            ("global", "hosts allow", "10.20.0.2"),
            ("documents", "path", root.to_str().unwrap()),
            ("documents", "read only", "Yes"),
            ("documents", "guest ok", "No"),
            ("documents", "follow symlinks", "No"),
            ("documents", "valid users", "reader"),
        ] {
            let output = Command::new(binary("testparm").unwrap())
                .arg("--suppress-prompt")
                .arg(format!("--section-name={section}"))
                .arg(format!("--parameter-name={parameter}"))
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{section}/{parameter}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&output.stdout).trim(),
                expected,
                "{section}/{parameter}"
            );
        }
    }

    #[test]
    fn config_restricts_network_users_and_writes() {
        let config = SmbConfig {
            root: "/srv/shared documents".into(),
            name: "documents".into(),
            listen: "10.20.0.1".parse().unwrap(),
            user: Some("reader".into()),
            as_root: false,
            port: Some(445),
            password_file: "/unused".into(),
            allowed_peers: vec!["10.20.0.2".parse().unwrap()],
        };
        let text = render_config(&config, Path::new("/tmp/portal-smb-test")).unwrap();
        for line in [
            "bind interfaces only = yes",
            "interfaces = 10.20.0.1",
            "hosts allow = 10.20.0.2",
            "hosts deny = ALL",
            "read only = yes",
            "valid users = reader",
            "guest ok = no",
            "follow symlinks = no",
        ] {
            assert!(text.lines().any(|actual| actual == line));
        }
        assert!(config_path(Path::new("/share\n[global]")).is_err());
        assert!(config_path(Path::new("/share/%u")).is_err());
        assert!(validate_name("user\nadmin users = root", "user").is_err());
    }

    #[test]
    fn private_state_is_removed_and_process_is_stopped() {
        let directory = PrivateDirectory::new().unwrap();
        let path = directory.0.clone();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        let child = Command::new("/usr/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let log = File::open("/dev/null").unwrap();
        let mut service = SmbService {
            child: Some(child),
            _directory: directory,
            log,
            access: None,
        };
        service.health().unwrap();
        service.stop().unwrap();
        service.stop().unwrap();
        drop(service);
        assert!(!path.exists());
    }
}
