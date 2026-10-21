use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// Keep exclusive ownership until the token is removed. The sidecar lock is never unlinked:
/// unlinking a locked file could let another process lock a different inode at the same path.
pub(crate) struct TokenFile {
    path: Option<PathBuf>,
    file: File,
    _lock: File,
}

impl TokenFile {
    pub(crate) fn remove(mut self) -> Result<(), String> {
        self.remove_owned()
    }

    fn remove_owned(&mut self) -> Result<(), String> {
        let Some(path) = self.path.take() else {
            return Ok(());
        };
        let owned = self.file.metadata().map_err(|e| e.to_string())?;
        match fs::symlink_metadata(&path) {
            Ok(current) if current.dev() == owned.dev() && current.ino() == owned.ino() => {
                fs::remove_file(&path)
                    .map_err(|e| format!("could not remove API token file {}: {e}", path.display()))
            }
            Ok(_) => Err(format!(
                "API token file {} was replaced; refusing to remove it",
                path.display()
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!(
                "could not inspect API token file {}: {e}",
                path.display()
            )),
        }
    }
}

impl Drop for TokenFile {
    fn drop(&mut self) {
        let _ = self.remove_owned();
    }
}

/// Lock the token path, then create or refresh its owner-only token.
pub(crate) fn create(path: &Path) -> Result<(String, TokenFile), String> {
    let mut lock_name = path
        .file_name()
        .ok_or("API token path needs a filename")?
        .to_os_string();
    lock_name.push(".lock");
    let lock = open_secure(&path.with_file_name(lock_name))?;
    lock.try_lock().map_err(|e| {
        format!(
            "API token file {} is in use or cannot be locked: {e}",
            path.display()
        )
    })?;
    let mut owned = TokenFile {
        path: Some(path.to_owned()),
        file: open_secure(path)?,
        _lock: lock,
    };
    let mut random = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token = Zeroizing::new(encode_hex(&random));
    random.zeroize();

    owned
        .file
        .set_len(0)
        .map_err(|error| format!("could not reset API token file {}: {error}", path.display()))?;
    owned
        .file
        .write_all(token.as_bytes())
        .and_then(|()| owned.file.write_all(b"\n"))
        .and_then(|()| owned.file.sync_all())
        .map_err(|error| format!("could not write API token file {}: {error}", path.display()))?;
    Ok((token.to_string(), owned))
}

fn open_secure(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("could not open API token/lock file {}: {e}", path.display()))?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "could not inspect API token file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(format!(
            "API token file {} is not a regular file owned by this user",
            path.display()
        ));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            format!(
                "could not secure API token file {}: {error}",
                path.display()
            )
        })?;
    Ok(file)
}

/// Encode random token bytes as lowercase hexadecimal.
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
    fn token_ownership_survives_a_second_runtime_and_restarts_cleanly() {
        let root =
            std::env::temp_dir().join(format!("portal-token-{:032x}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        let path = root.join("api.token");
        let (first, owner) = create(&path).unwrap();
        assert!(create(&path).err().unwrap().contains("in use"));
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), first);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        owner.remove().unwrap();
        assert!(!path.exists());
        let (second, owner) = create(&path).unwrap();
        assert_ne!(first, second);
        drop(owner);
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shutdown_does_not_remove_a_replaced_token_file() {
        let root =
            std::env::temp_dir().join(format!("portal-token-{:032x}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        let path = root.join("api.token");
        let (_, owner) = create(&path).unwrap();
        fs::rename(&path, root.join("old.token")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(owner.remove().unwrap_err().contains("replaced"));
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        fs::remove_dir_all(root).unwrap();
    }
}
