use crate::error::{Error, Result};
use axum::http::HeaderMap;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    User,
    Device,
}

#[derive(Clone, Copy)]
pub(crate) struct Credential {
    pub role: Role,
    pub hash: [u8; 32],
}

pub(crate) fn random_hex(bytes: usize) -> String {
    let mut random = Zeroizing::new(vec![0; bytes]);
    rand::rngs::OsRng.fill_bytes(&mut random);
    random.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn issue(role: Role) -> (String, [u8; 32]) {
    let prefix = match role {
        Role::User => "usr_",
        Role::Device => "dev_",
    };
    let token = format!("{prefix}{}", random_hex(32));
    let hash = Sha256::digest(token.as_bytes()).into();
    (token, hash)
}

pub(crate) fn parse(token: &str) -> Result<Credential> {
    if token.len() != 68 || !token.as_bytes()[4..].iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::unauthorized());
    }
    let role = match &token.as_bytes()[..4] {
        b"usr_" => Role::User,
        b"dev_" => Role::Device,
        _ => return Err(Error::unauthorized()),
    };
    Ok(Credential {
        role,
        hash: Sha256::digest(token.as_bytes()).into(),
    })
}

pub(crate) fn from_headers(headers: &HeaderMap) -> Result<Credential> {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let value = values.next().ok_or_else(Error::unauthorized)?;
    if values.next().is_some() {
        return Err(Error::unauthorized());
    }
    let token = value
        .to_str()
        .ok()
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(Error::unauthorized)?;
    parse(token)
}

/// Keep the state directory private, including SQLite journal files and the admin key.
pub(crate) fn prepare_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    check_private(path, true)
}

pub(crate) fn check_private(path: &Path, directory: bool) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink()
        || (directory && !meta.is_dir())
        || (!directory && !meta.is_file())
    {
        return Err(std::io::Error::other(
            "coordinator state must use regular files in a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other(
                "coordinator state requires owner-only permissions (0700 directory, 0600 files)",
            ));
        }
    }
    Ok(())
}

pub(crate) fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Persist the bootstrap administrator credential without refreshing it on restart.
pub(crate) fn admin_key(directory: &Path, existing_network: bool) -> std::io::Result<Credential> {
    let path = directory.join("admin.token");
    if !path.try_exists()? {
        if existing_network {
            return Err(std::io::Error::other(
                "admin.token is missing; restore it with the coordinator state",
            ));
        }
        let temporary = directory.join(format!(".admin-{}.tmp", random_hex(16)));
        let result = (|| {
            let mut file = create_private(&temporary)?;
            let (token, _) = issue(Role::User);
            let token = Zeroizing::new(token);
            file.write_all(token.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::hard_link(&temporary, &path)?;
            Ok::<_, std::io::Error>(())
        })();
        let _ = fs::remove_file(&temporary);
        result?;
        #[cfg(unix)]
        fs::File::open(directory)?.sync_all()?;
    }
    check_private(&path, false)?;
    let mut token = Zeroizing::new(String::new());
    std::fs::File::open(path)?
        .take(128)
        .read_to_string(&mut token)?;
    let credential = parse(token.trim())
        .map_err(|_| std::io::Error::other("invalid coordinator admin.token"))?;
    if credential.role != Role::User {
        return Err(std::io::Error::other(
            "admin.token must contain a user credential",
        ));
    }
    Ok(credential)
}

/// A second process must not serve the same state with independent notifications.
pub(crate) fn lock_directory(directory: &Path) -> std::io::Result<std::fs::File> {
    let path = directory.join("coordinator.lock");
    match create_private(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    check_private(&path, false)?;
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    file.try_lock()
        .map_err(|_| std::io::Error::other("coordinator state is already in use"))?;
    Ok(file)
}
