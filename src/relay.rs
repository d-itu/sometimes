use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, ready},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional},
    time::{Instant, Sleep, sleep_until},
};

use crate::naive::padding::PaddingIo;

pub(crate) struct IdleIo<T> {
    inner: T,
    last: Instant,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
}

impl<T> IdleIo<T> {
    pub(crate) fn new(inner: T, idle: Duration) -> Self {
        let last = Instant::now();
        Self {
            inner,
            last,
            idle,
            timer: Box::pin(sleep_until(last + idle)),
        }
    }

    fn poll_timeout<R>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<R>> {
        loop {
            ready!(self.timer.as_mut().poll(cx));
            let deadline = self.last + self.idle;
            if deadline <= Instant::now() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tunnel idle timeout",
                )));
            }
            self.timer.as_mut().reset(deadline);
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Pending => this.poll_timeout(cx),
            result => {
                if buf.filled().len() > before {
                    this.last = Instant::now();
                }
                result
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => this.poll_timeout(cx),
            result => {
                if matches!(result, Poll::Ready(Ok(len)) if len > 0) {
                    this.last = Instant::now();
                }
                result
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => this.poll_timeout(cx),
            result => result,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => this.poll_timeout(cx),
            result => result,
        }
    }
}

struct Activity {
    start: Instant,
    elapsed: AtomicU64,
}

impl Activity {
    fn record(&self) {
        self.elapsed
            .store(self.start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.start + Duration::from_nanos(self.elapsed.load(Ordering::Relaxed))
    }
}

struct ActiveIo<'a, T> {
    inner: T,
    activity: &'a Activity,
}

impl<T: AsyncRead + Unpin> AsyncRead for ActiveIo<'_, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.activity.record();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActiveIo<'_, T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(size)) if size > 0) {
            this.activity.record();
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
    mut local: L,
    upstream: U,
    padded: bool,
    idle: Duration,
) -> io::Result<(u64, u64)>
where
    L: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Activity {
        start: Instant::now(),
        elapsed: AtomicU64::new(0),
    };
    let upstream = ActiveIo {
        inner: upstream,
        activity: &activity,
    };
    let mut upstream = PaddingIo::new(upstream, padded);
    let watchdog = async {
        loop {
            let deadline = activity.last() + idle;
            sleep_until(deadline).await;
            if activity.last() + idle <= Instant::now() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tunnel idle timeout",
                ));
            }
        }
    };
    tokio::select! {
        result = copy_bidirectional(&mut local, &mut upstream) => result,
        result = watchdog => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn half_close_still_allows_response() {
        for padded in [false, true] {
            let (mut app, local) = tokio::io::duplex(4);
            let (upstream, server) = tokio::io::duplex(4);
            let mut server = PaddingIo::new(server, padded);
            let task = tokio::spawn(relay(local, upstream, padded, Duration::from_secs(2)));
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
    }

    #[tokio::test]
    async fn io_deadline_tracks_activity_in_both_directions() {
        for writing in [false, true] {
            let (stream, mut peer) = tokio::io::duplex(4);
            let mut stream = IdleIo::new(stream, Duration::from_millis(150));
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let mut byte = [0];
                if writing {
                    stream.write_all(b"x").await.unwrap();
                    peer.read_exact(&mut byte).await.unwrap();
                } else {
                    peer.write_all(b"x").await.unwrap();
                    stream.read_exact(&mut byte).await.unwrap();
                }
                assert_eq!(&byte, b"x");
            }
            let error = tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
    }

    #[tokio::test]
    async fn relay_deadline_tracks_activity_and_expires_after_half_close() {
        let (mut app, local) = tokio::io::duplex(4);
        let (upstream, mut peer) = tokio::io::duplex(4);
        let task = tokio::spawn(relay(local, upstream, false, Duration::from_millis(150)));
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            app.write_all(b"x").await.unwrap();
            assert_eq!(peer.read_u8().await.unwrap(), b'x');
        }
        app.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
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
