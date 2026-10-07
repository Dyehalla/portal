use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::Stdio;

struct CredentialsDirectory(PathBuf);
impl Drop for CredentialsDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) async fn open_smb(connection: crate::SmbConnection) -> Result<(), String> {
    // Private directory plus create_new prevents following a pre-existing auth-file symlink.
    let directory =
        std::env::temp_dir().join(format!("portal-smb-client-{:032x}", rand::random::<u128>()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|e| format!("could not create SMB credential directory: {e}"))?;
    let directory = CredentialsDirectory(directory);
    let path = directory.0.join("auth");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("could not create SMB credential file: {e}"))?;
    let contents = zeroize::Zeroizing::new(format!(
        "username = {}\npassword = {}\n",
        connection.username,
        connection.password.as_str()
    ));
    file.write_all(contents.as_bytes())
        .map_err(|e| format!("could not write SMB credentials: {e}"))?;
    drop(file);
    let address = format!("//portal-peer/{}", connection.share.name);
    let status = tokio::process::Command::new("smbclient")
        .arg(address)
        .arg("-I")
        .arg(&connection.share.host)
        .arg("-p")
        .arg(connection.share.port.to_string())
        .arg("-A")
        .arg(path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .status()
        .await
        .map_err(|e| format!("could not open smbclient (install Samba client tools): {e}"))?;
    if !status.success() {
        return Err(format!("smbclient exited with {status}"));
    }
    Ok(())
}
