use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    time::{Instant, sleep_until},
};

use crate::naive::padding;

struct ActiveIo<T> {
    inner: T,
    activity: watch::Sender<Instant>,
}

impl<T: AsyncRead + Unpin> AsyncRead for ActiveIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.activity.send_replace(Instant::now());
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActiveIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(size)) if size > 0) {
            this.activity.send_replace(Instant::now());
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub async fn relay<L, U>(
    local: L,
    upstream: U,
    padded: bool,
    idle: Duration,
) -> io::Result<(u64, u64)>
where
    L: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (activity, mut updates) = watch::channel(Instant::now());
    let upstream = ActiveIo {
        inner: upstream,
        activity,
    };
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let transfer = async {
        tokio::try_join!(
            padding::encode(&mut local_read, &mut upstream_write, padded),
            padding::decode(&mut upstream_read, &mut local_write, padded),
        )
    };
    let watchdog = async {
        loop {
            let deadline = *updates.borrow_and_update() + idle;
            tokio::select! {
                biased;
                change = updates.changed() => {
                    if change.is_err() { return Err(io::Error::new(io::ErrorKind::BrokenPipe, "tunnel closed")); }
                }
                _ = sleep_until(deadline) => return Err(io::Error::new(io::ErrorKind::TimedOut, "tunnel idle timeout")),
            }
        }
    };
    tokio::select! {
        result = transfer => result,
        result = watchdog => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn half_close_still_allows_response() {
        let (mut app, local) = tokio::io::duplex(4);
        let (upstream, mut server) = tokio::io::duplex(4);
        let task = tokio::spawn(relay(local, upstream, false, Duration::from_secs(2)));
        let app_task = tokio::spawn(async move {
            app.write_all(b"request").await.unwrap();
            app.shutdown().await.unwrap();
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            response
        });
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        server.write_all(b"response").await.unwrap();
        server.shutdown().await.unwrap();
        assert_eq!(app_task.await.unwrap(), b"response");
        assert_eq!(task.await.unwrap().unwrap(), (7, 8));
    }

    #[tokio::test]
    async fn idle_tunnel_expires() {
        let (_app, local) = tokio::io::duplex(4);
        let (upstream, _server) = tokio::io::duplex(4);
        let error = relay(local, upstream, true, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
