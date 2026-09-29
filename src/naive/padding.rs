//! Independent implementation of the published NaiveProxy payload padding format.
//!
//! Record counts belong to each direction of a CONNECT stream, not to H2 frames.
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const FIRST_RECORDS: usize = 8;
const CHUNK: usize = 16 * 1024;

pub async fn encode<R, W>(reader: &mut R, writer: &mut W, padded: bool) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; CHUNK + 3 + 255];
    let mut total = 0;
    let mut remaining = if padded { FIRST_RECORDS } else { 0 };
    loop {
        let len = reader.read(&mut buffer[3..3 + CHUNK]).await?;
        if len == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }
        if remaining > 0 {
            let padding = rand::random::<u8>();
            buffer[..2].copy_from_slice(&(len as u16).to_be_bytes());
            buffer[2] = padding;
            buffer[3 + len..3 + len + usize::from(padding)].fill(0);
            writer
                .write_all(&buffer[..3 + len + usize::from(padding)])
                .await?;
            remaining -= 1;
        } else {
            writer.write_all(&buffer[3..3 + len]).await?;
        }
        total += len as u64;
    }
}

pub async fn decode<R, W>(reader: &mut R, writer: &mut W, padded: bool) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; CHUNK];
    let mut total = 0;
    if padded {
        for _ in 0..FIRST_RECORDS {
            let mut header = [0u8; 3];
            // EOF at a record boundary is a valid half-close, even before record eight.
            if reader.read(&mut header[..1]).await? == 0 {
                writer.shutdown().await?;
                return Ok(total);
            }
            reader.read_exact(&mut header[1..]).await?;
            let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let mut remaining = len;
            while remaining > 0 {
                let size = remaining.min(CHUNK);
                reader.read_exact(&mut buffer[..size]).await?;
                writer.write_all(&buffer[..size]).await?;
                remaining -= size;
            }
            reader
                .read_exact(&mut buffer[..usize::from(header[2])])
                .await?;
            total += len as u64;
        }
    }
    total += tokio::io::copy(reader, writer).await?;
    writer.shutdown().await?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::ReadBuf;

    // Deterministic short reads preserve the test's record boundaries.
    struct Chunks(VecDeque<Vec<u8>>);
    impl AsyncRead for Chunks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(chunk) = self.0.pop_front() {
                let len = chunk.len().min(out.remaining());
                out.put_slice(&chunk[..len]);
                if len < chunk.len() {
                    self.0.push_front(chunk[len..].to_vec());
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    fn fixture() -> Vec<u8> {
        let mut wire = Vec::new();
        for index in 0..8u8 {
            wire.extend_from_slice(&[0, 1, 2, b'a' + index, 0, 0]);
        }
        wire.extend_from_slice(b"raw tail");
        wire
    }

    #[tokio::test]
    async fn decodes_at_every_split_including_raw_transition() {
        let wire = fixture();
        for split in 1..wire.len() {
            let mut reader = Chunks([wire[..split].to_vec(), wire[split..].to_vec()].into());
            let mut output = Vec::new();
            assert_eq!(decode(&mut reader, &mut output, true).await.unwrap(), 16);
            assert_eq!(output, b"abcdefghraw tail");
        }
        let mut reader = Chunks(wire.iter().map(|byte| vec![*byte]).collect());
        let mut output = Vec::new();
        decode(&mut reader, &mut output, true).await.unwrap();
        assert_eq!(output, b"abcdefghraw tail");
    }

    #[tokio::test]
    async fn rejects_truncated_headers_payload_and_padding() {
        let record = [0, 2, 2, b'o', b'k', 0, 0];
        for end in 1..record.len() {
            let error = decode(&mut &record[..end], &mut Vec::new(), true)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
        assert_eq!(
            decode(&mut &record[..], &mut Vec::new(), true)
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn empty_records_and_maximum_payload() {
        let mut wire = vec![0, 0, 255];
        wire.extend([0; 255]);
        wire.extend([255, 255, 0]);
        wire.extend(vec![42; 65_535]);
        let mut output = Vec::new();
        assert_eq!(
            decode(&mut wire.as_slice(), &mut output, true)
                .await
                .unwrap(),
            65_535
        );
        assert_eq!(output, vec![42; 65_535]);
    }

    #[tokio::test]
    async fn encoder_pads_eight_records_then_switches_to_raw() {
        let mut reader = Chunks((0..10u8).map(|n| vec![n]).collect());
        let mut wire = Vec::new();
        assert_eq!(encode(&mut reader, &mut wire, true).await.unwrap(), 10);
        let mut cursor = wire.as_slice();
        for n in 0..8u8 {
            assert_eq!(&cursor[..2], &[0, 1]);
            assert_eq!(cursor[3], n);
            let end = 4 + usize::from(cursor[2]);
            assert!(cursor[4..end].iter().all(|byte| *byte == 0));
            cursor = &cursor[end..];
        }
        assert_eq!(cursor, &[8, 9]);
    }

    #[tokio::test]
    async fn large_input_roundtrip_with_backpressure() {
        let input = vec![123; 150_000];
        let (mut tx, mut rx) = tokio::io::duplex(7);
        let mut output = Vec::new();
        let mut source = input.as_slice();
        let (sent, received) = tokio::join!(
            encode(&mut source, &mut tx, true),
            decode(&mut rx, &mut output, true),
        );
        assert_eq!(sent.unwrap(), input.len() as u64);
        assert_eq!(received.unwrap(), input.len() as u64);
        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn unpadded_data_is_unchanged() {
        let input = b"\x00\x01\xffnot a padding record";
        let mut wire = Vec::new();
        encode(&mut input.as_slice(), &mut wire, false)
            .await
            .unwrap();
        let mut output = Vec::new();
        decode(&mut wire.as_slice(), &mut output, false)
            .await
            .unwrap();
        assert_eq!(output, input);
    }
}
