use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

const CONTROL_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Bind the Linux local-control socket, replace stale sockets, and restrict it to mode 0600.
pub(crate) fn bind(path: &Path) -> Result<UnixListener, String> {
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
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(path);
        return Err(format!(
            "could not secure control socket {}: {error}",
            path.display()
        ));
    }
    if let Err(error) = listener.set_nonblocking(true) {
        let _ = fs::remove_file(path);
        return Err(format!("could not configure control socket: {error}"));
    }
    Ok(listener)
}

/// Accept one local client and apply the Unix socket read timeout before calling its handler.
pub(crate) fn process_one(
    listener: &UnixListener,
    handler: impl FnOnce(&mut UnixStream) -> Result<(), String>,
) -> Result<(), String> {
    match listener.accept() {
        Ok((mut stream, _)) => {
            let result = stream
                .set_read_timeout(Some(CONTROL_READ_TIMEOUT))
                .map_err(|error| format!("could not configure control socket timeout: {error}"))
                .and_then(|()| handler(&mut stream));
            if let Err(error) = result {
                eprintln!("portal-runtime: control request failed: {error}");
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(()),
        Err(error) => Err(format!("control socket failed: {error}")),
    }
}
