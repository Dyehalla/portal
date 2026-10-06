use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use zeroize::Zeroize;

const MAX_CONTROL_RESPONSE: usize = 64 * 1024;

pub(crate) fn send(socket_path: &str, request: &mut String) -> Result<String, String> {
    let result = (|| {
        let mut stream = UnixStream::connect(socket_path)
            .map_err(|error| format!("could not connect to {socket_path}: {error}"))?;
        let mut payload = request.as_bytes().to_vec();
        payload.push(b'\n');
        let write_result = stream.write_all(&payload);
        payload.zeroize();
        write_result.map_err(|error| format!("could not send control request: {error}"))?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| format!("could not finish control request: {error}"))?;

        let mut response = String::new();
        (&mut stream)
            .take((MAX_CONTROL_RESPONSE + 1) as u64)
            .read_to_string(&mut response)
            .map_err(|error| format!("could not read control response: {error}"))?;
        if response.len() > MAX_CONTROL_RESPONSE {
            return Err("control response is too large".into());
        }
        let response = response.trim_end_matches('\n');
        if let Some(message) = response.strip_prefix("OK") {
            Ok(message.trim().to_owned())
        } else if let Some(message) = response.strip_prefix("ERR ") {
            Err(message.to_owned())
        } else {
            Err(format!("invalid response from control socket: {response}"))
        }
    })();
    request.zeroize();
    result
}
