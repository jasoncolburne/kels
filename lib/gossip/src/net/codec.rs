//! Length-prefixed postcard codec for protocol messages.
//!
//! Provides `write_message` and `read_message` functions for sending and receiving
//! postcard-serialized protocol messages over any `AsyncRead + AsyncWrite` stream
//! (typically a yamux stream on top of an [`super::crypto::EncryptedStream`]).

use std::io;

use futures::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, de::DeserializeOwned};

/// Maximum message size in bytes (1 MiB).
///
/// Messages larger than this are rejected to prevent DoS via memory exhaustion.
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// Write a postcard-serialized message with a 4-byte big-endian length prefix.
pub async fn write_message<S, M>(stream: &mut S, msg: &M) -> io::Result<()>
where
    S: futures::AsyncWrite + Unpin,
    M: Serialize,
{
    let encoded = postcard::to_stdvec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let len = encoded.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a postcard-serialized message with a 4-byte big-endian length prefix.
pub async fn read_message<S, M>(stream: &mut S) -> io::Result<M>
where
    S: futures::AsyncRead + Unpin,
    M: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"),
        ));
    }

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    postcard::from_bytes(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Write a raw byte payload with a 4-byte big-endian length prefix.
///
/// Used for handshake messages that aren't postcard-encoded.
pub async fn write_bytes<S: futures::AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> io::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a raw byte payload with a 4-byte big-endian length prefix.
///
/// Used for handshake messages that aren't postcard-encoded.
pub async fn read_bytes<S: futures::AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload too large: {len} bytes (max {MAX_MESSAGE_SIZE})"),
        ));
    }

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use serde::Deserialize;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;

    #[tokio::test]
    async fn message_roundtrip() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct TestMsg {
            value: u32,
            name: String,
        }

        let msg = TestMsg {
            value: 42,
            name: "hello".to_string(),
        };

        // Use a duplex stream for testing.
        let (mut client, mut server) = tokio::io::duplex(1024);

        // Convert to futures-compatible streams.
        let mut client = (&mut client).compat();
        let mut server = (&mut server).compat();

        write_message(&mut client, &msg).await.unwrap();
        let received: TestMsg = read_message(&mut server).await.unwrap();
        assert_eq!(msg, received);
    }

    #[tokio::test]
    async fn bytes_roundtrip() {
        let data = b"hello world";

        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut client = (&mut client).compat();
        let mut server = (&mut server).compat();

        write_bytes(&mut client, data).await.unwrap();
        let received = read_bytes(&mut server).await.unwrap();
        assert_eq!(&received, data);
    }
}
