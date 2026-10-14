use std::path::Path;

#[cfg(unix)]
pub fn create_key_file(path: &Path) -> Result<[u8; 32], String> {
    use rand::RngCore;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use zeroize::Zeroizing;

    let mut bytes = Zeroizing::new([0_u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|error| format!("could not generate private key: {error}"))?;
    let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let public = secret.verifying_key().to_bytes();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    if let Err(error) = file.write_all(&*bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("could not write private key: {error}"));
    }
    Ok(public)
}

#[cfg(not(unix))]
pub fn create_key_file(_path: &Path) -> Result<[u8; 32], String> {
    Err("secure key-file creation is currently supported only on Unix".into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn key_file_is_private_and_never_overwrites_existing_file() {
        let directory =
            std::env::temp_dir().join(format!("portal-key-test-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("key");
        let public = create_key_file(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let private =
            ed25519_dalek::SigningKey::from_bytes(&<[u8; 32]>::try_from(bytes.as_slice()).unwrap());
        assert_eq!(public, private.verifying_key().to_bytes());
        assert!(create_key_file(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
