use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// Create or safely refresh the owner-only bearer token used by the local HTTP API.
pub(crate) fn create(path: &Path) -> Result<String, String> {
    let mut random = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token = Zeroizing::new(encode_hex(&random));
    random.zeroize();

    let mut options = OpenOptions::new();
    options.write(true).custom_flags(libc::O_NOFOLLOW);
    let file = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(format!(
                    "API token file {} must be a regular file owned by this user with mode 0600",
                    path.display()
                ));
            }
            options.open(path).map_err(|error| {
                format!("could not open API token file {}: {error}", path.display())
            })?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => options
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| {
                format!(
                    "could not create API token file {}: {error}",
                    path.display()
                )
            })?,
        Err(error) => {
            return Err(format!(
                "could not inspect API token file {}: {error}",
                path.display()
            ));
        }
    };

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
    file.set_len(0)
        .map_err(|error| format!("could not reset API token file {}: {error}", path.display()))?;
    let mut file = file;
    file.write_all(token.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("could not write API token file {}: {error}", path.display()))?;

    Ok(token.to_string())
}

/// Remove the API token file after the runtime has shut down.
pub(crate) fn remove(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not remove API token file {}: {error}",
            path.display()
        )),
    }
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
