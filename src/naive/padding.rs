//! Independent implementation of the published NaiveProxy payload padding format.
//!
//! Record counts belong to each direction of a CONNECT stream, not to H2 frames.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

const FIRST_RECORDS: usize = 8;
const CHUNK: usize = 16 * 1024;

/// Applies the initial padding records directly to an underlying byte stream.
///
/// Writes buffer at most one record; flush or shutdown drains any pending bytes.
/// The encoding buffer is released after the eighth record.
pub struct PaddingIo<T> {
    inner: T,
    read: ReadState,
    write: WriteState,
}

#[derive(Default)]
struct ReadState {
    records: usize,
    header: [u8; 3],
    header_len: usize,
    payload: usize,
    padding: usize,
}

#[derive(Default)]
struct WriteState {
    records: usize,
    buffer: Vec<u8>,
    position: usize,
}

impl<T> PaddingIo<T> {
    pub fn new(inner: T, padded: bool) -> Self {
        let records = if padded { FIRST_RECORDS } else { 0 };
        Self {
            inner,
            read: ReadState {
                records,
                ..ReadState::default()
            },
            write: WriteState {
                records,
                ..WriteState::default()
            },
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PaddingIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Self { inner, read, .. } = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while read.records > 0 {
            while read.header_len < 3 {
                let mut header = ReadBuf::new(&mut read.header[read.header_len..]);
                ready!(Pin::new(&mut *inner).poll_read(cx, &mut header))?;
                let len = header.filled().len();
                if len == 0 {
                    return if read.header_len == 0 {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                    };
                }
                read.header_len += len;
                if read.header_len == 3 {
                    read.payload =
                        usize::from(u16::from_be_bytes([read.header[0], read.header[1]]));
                    read.padding = usize::from(read.header[2]);
                }
            }
            if read.payload > 0 {
                let limit = buf.remaining().min(read.payload);
                let mut payload = ReadBuf::new(buf.initialize_unfilled_to(limit));
                ready!(Pin::new(&mut *inner).poll_read(cx, &mut payload))?;
                let len = payload.filled().len();
                if len == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                read.payload -= len;
                buf.advance(len);
                return Poll::Ready(Ok(()));
            }
            while read.padding > 0 {
                let mut discarded = [0; 255];
                let mut padding = ReadBuf::new(&mut discarded[..read.padding]);
                ready!(Pin::new(&mut *inner).poll_read(cx, &mut padding))?;
                let len = padding.filled().len();
                if len == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                read.padding -= len;
            }
            read.records -= 1;
            read.header_len = 0;
        }
        Pin::new(inner).poll_read(cx, buf)
    }
}

impl WriteState {
    fn poll_drain<T: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut T,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.position < self.buffer.len() {
            let len = ready!(Pin::new(&mut *inner).poll_write(cx, &self.buffer[self.position..]))?;
            if len == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.position += len;
        }
        if self.records == 0 {
            self.buffer = Vec::new();
        } else {
            self.buffer.clear();
        }
        self.position = 0;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PaddingIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Self { inner, write, .. } = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(write.poll_drain(inner, cx))?;
        if write.records == 0 {
            return Pin::new(inner).poll_write(cx, buf);
        }
        let len = buf.len().min(CHUNK);
        let padding = rand::random::<u8>();
        write.buffer.reserve(len + 3 + usize::from(padding));
        write.buffer.extend_from_slice(&(len as u16).to_be_bytes());
        write.buffer.push(padding);
        write.buffer.extend_from_slice(&buf[..len]);
        write.buffer.resize(len + 3 + usize::from(padding), 0);
        write.records -= 1;
        if let Poll::Ready(result) = write.poll_drain(inner, cx) {
            result?;
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self { inner, write, .. } = self.get_mut();
        ready!(write.poll_drain(inner, cx))?;
        Pin::new(inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self { inner, write, .. } = self.get_mut();
        ready!(write.poll_drain(inner, cx))?;
        Pin::new(inner).poll_shutdown(cx)
    }
}

pub async fn encode<R, W>(reader: &mut R, writer: &mut W, padded: bool) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut writer = PaddingIo::new(writer, padded);
    let total = tokio::io::copy(reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(total)
}

pub async fn decode<R, W>(reader: &mut R, writer: &mut W, padded: bool) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = PaddingIo::new(reader, padded);
    let total = tokio::io::copy(&mut reader, writer).await?;
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
