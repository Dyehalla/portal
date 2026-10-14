use bytes::Bytes;
use futures_util::StreamExt;
use std::{future::Future, time::Duration};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
async fn network_wait<T>(future: impl Future<Output = T>, operation: &str) -> Result<T, String> {
    tokio::time::timeout(NETWORK_TIMEOUT, future)
        .await
        .map_err(|_| format!("{operation} timed out after 30 seconds"))
}

/// Send a file operation to a registered peer through the application's QUIC endpoint.
pub async fn proxy_request(
    network: portal_net::Net,
    peer: portal_net::PeerKey,
    operation: &str,
    body: &[u8],
) -> Result<portal_net::IncomingResponse, String> {
    if !["resources", "list", "metadata", "download"].contains(&operation) {
        return Err("unknown file operation".into());
    }
    let payload = serde_json::from_slice(body).map_err(|_| "invalid file request")?;
    network
        .request(
            peer,
            portal_net::Request {
                service: "files".into(),
                operation: operation.into(),
                payload,
            },
        )
        .await
}
/// Limit idle body reads and preserve QUIC length/truncation checks.
pub fn response_stream(
    response: portal_net::IncomingResponse,
) -> impl futures_core::Stream<Item = Result<Bytes, std::io::Error>> {
    futures_util::stream::unfold(
        (tokio_util::io::ReaderStream::new(response.body), false),
        |(mut stream, done)| async move {
            if done {
                return None;
            }
            match network_wait(stream.next(), "QUIC response progress").await {
                Ok(None) => None,
                Ok(Some(chunk)) => {
                    let done = chunk.is_err();
                    Some((chunk, (stream, done)))
                }
                Err(error) => Some((Err(std::io::Error::other(error)), (stream, true))),
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn stalled_network_operation_times_out() {
        let result = network_wait(std::future::pending::<()>(), "QUIC body progress").await;
        assert!(result.unwrap_err().contains("timed out"));
    }
}
