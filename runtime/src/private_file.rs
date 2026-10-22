use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) fn read(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let info = file.metadata().map_err(|e| e.to_string())?;
    if !info.is_file()
        || info.uid() != unsafe { libc::geteuid() }
        || info.mode() & 0o077 != 0
        || info.len() > limit
    {
        return Err(format!(
            "{} must be an owner-only regular file of at most {limit} bytes",
            path.display()
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("private file exceeded size limit".into());
    }
    Ok(bytes)
}

fn parent(path: &Path) -> Result<&Path, String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let info = fs::symlink_metadata(parent)
        .map_err(|e| format!("state directory {}: {e}", parent.display()))?;
    if !info.is_dir() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o077 != 0 {
        return Err(format!(
            "state directory {} must belong to this user and have mode 0700",
            parent.display()
        ));
    }
    Ok(parent)
}

pub(crate) fn lock(path: &Path) -> Result<File, String> {
    parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("unsafe agent lock file".into());
    }
    file.try_lock()
        .map_err(|_| "this device identity is already in use by another process")?;
    Ok(file)
}

pub(crate) fn write(path: &Path, bytes: &[u8], create_new: bool) -> Result<(), String> {
    let parent = parent(path)?;
    let temp = parent.join(format!(".portal-{:032x}.tmp", rand::random::<u128>()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        if create_new {
            fs::hard_link(&temp, path)
                .map_err(|e| format!("could not create {}: {e}", path.display()))?;
            fs::remove_file(&temp).map_err(|e| e.to_string())?;
        } else {
            fs::rename(&temp, path).map_err(|e| e.to_string())?;
        }
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    })();
    let _ = fs::remove_file(temp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn credentials_are_private_atomic_exclusive_and_never_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.path().join("credential.json");
        write(&file, b"first", true).unwrap();
        assert!(write(&file, b"replacement", true).is_err());
        assert_eq!(read(&file, 128).unwrap().as_slice(), b"first");
        write(&file, b"new", false).unwrap();
        assert_eq!(read(&file, 128).unwrap().as_slice(), b"new");
        assert!(read(&file, 2).is_err());
        let link = dir.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(read(&link, 128).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&file, 128).is_err());
        let lock_path = dir.path().join("identity.lock");
        let first = lock(&lock_path).unwrap();
        assert!(lock(&lock_path).is_err());
        drop(first);
        assert!(lock(&lock_path).is_ok());
    }
}
