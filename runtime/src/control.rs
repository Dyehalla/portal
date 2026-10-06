use std::io::{Read, Write};

use zeroize::Zeroize;

use crate::service::Runtime;

const MAX_CONTROL_LINE: usize = 64 * 1024;

// Read one bounded newline-delimited command, dispatch it, and send a single-line result.
pub(crate) fn handle_stream<S: Read + Write>(
    stream: &mut S,
    runtime: &mut Runtime,
) -> Result<(), String> {
    let mut line = String::new();
    let read_result = (&mut *stream)
        .take(MAX_CONTROL_LINE as u64)
        .read_to_string(&mut line);
    let response = match read_result {
        Ok(_) if line.len() >= MAX_CONTROL_LINE => Err("control request is too large".to_owned()),
        Ok(_) if !line.ends_with('\n') => Err("control request must end with a newline".to_owned()),
        Ok(_) if line[..line.len() - 1].contains('\n') => {
            Err("control socket accepts one request per connection".to_owned())
        }
        Ok(_) => runtime.handle_request(&line[..line.len() - 1]),
        Err(error) => Err(format!("could not read control request: {error}")),
    };
    line.zeroize();

    let response = match response {
        Ok(message) => format!("OK {message}\n"),
        Err(message) => format!("ERR {}\n", one_line(&message)),
    };
    stream
        .write_all(response.as_bytes())
        .map_err(|error| format!("could not send control response: {error}"))
}

// Replace line breaks so an error stays within the one-response-per-connection format.
fn one_line(message: &str) -> String {
    message.replace('\r', " ").replace('\n', " ")
}
