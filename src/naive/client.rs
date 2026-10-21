use std::{
    error::Error,
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rama::{
    extensions::{Extensions, ExtensionsRef},
    http::{
        Body, HeaderValue, Method, Request, Version,
        core::client::conn::http2,
        io::upgrade::{Upgraded, handle_upgrade},
    },
    net::{
        address::Authority,
        conn::{ConnectionHealth, ConnectionHealthWatcher, MaxConcurrency},
        uri::Uri,
    },
    rt::Executor,
    tcp::TcpStream,
    tls::rustls::{
        client::{TlsStream, client_root_certs},
        dep::{
            rustls::{ClientConfig, crypto::ring, pki_types::ServerName},
            tokio_rustls::TlsConnector,
        },
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, Semaphore},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    config::Upstream,
    dns::{
        self,
        bootstrap::{Resolver, Target},
    },
    outbound::connect_outbound,
};

mod pool;

use pool::{Allocation, Assignment, PoolPolicy, SessionPool, Slot, StreamPermit};

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

pub struct Client {
    upstream: Upstream,
    target: Target,
    outbound_mark: Option<u32>,
    tls: TlsConnector,
    authorization: HeaderValue,
    server_name: ServerName<'static>,
    resolver: Arc<Resolver>,
    pool: SessionPool,
}

pub struct Tunnel {
    pub stream: Upgraded,
    pub padded: bool,
    _session: Arc<Session>,
    _permit: StreamPermit,
}

impl AsyncRead for Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

struct Session {
    address: Option<SocketAddr>,
    sender: http2::SendRequest<Body>,
    _driver: Driver,
    streams: Arc<Semaphore>,
    admission: StdMutex<()>,
    max_streams: Arc<MaxConcurrency>,
    health: Arc<ConnectionHealthWatcher>,
    draining: AtomicBool,
    changed: Arc<Notify>,
    _slot: Arc<Option<Slot>>,
}

struct ConnectRequest<'a> {
    client: &'a Client,
    destination: Authority,
    failed: Vec<Weak<Session>>,
}

enum ConnectionProgress<T> {
    Ready(T),
    Reused(Arc<Session>, StreamPermit),
}

// Field order closes the transport before releasing its connection budget.
struct ReservedIo<S> {
    stream: S,
    _slot: Arc<Option<Slot>>,
}

impl<S: ExtensionsRef> ExtensionsRef for ReservedIo<S> {
    fn extensions(&self) -> &Extensions {
        self.stream.extensions()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReservedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReservedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

struct Driver(Option<JoinHandle<()>>);

#[derive(Debug)]
struct UnsentConnect;

impl fmt::Display for UnsentConnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("upstream CONNECT was not sent")
    }
}

impl Error for UnsentConnect {}

impl Drop for Driver {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

impl Client {
    pub fn new(upstream: Upstream, outbound_mark: Option<u32>) -> Result<Self> {
        Self::new_with_resolver(
            upstream,
            outbound_mark,
            Resolver::from_config(&dns::Config::default(), outbound_mark),
        )
    }

    pub(crate) fn new_with_resolver(
        upstream: Upstream,
        outbound_mark: Option<u32>,
        resolver: Arc<Resolver>,
    ) -> Result<Self> {
        upstream.validate()?;
        let server_name = ServerName::try_from(
            upstream
                .server_name
                .clone()
                .unwrap_or_else(|| upstream.host.clone()),
        )
        .context("invalid upstream TLS hostname")?;
        let mut tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(client_root_certs().as_ref().clone())
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let encoded = STANDARD.encode(format!("{}:{}", upstream.username, upstream.password));
        let mut authorization = HeaderValue::from_str(&format!("Basic {encoded}"))?;
        authorization.set_sensitive(true);
        Ok(Self {
            target: Target::new(&upstream.host, upstream.port),
            upstream,
            outbound_mark,
            tls: TlsConnector::from(Arc::new(tls)),
            authorization,
            server_name,
            resolver,
            pool: SessionPool::new(),
        })
    }

    pub async fn connect(&self, destination: impl Into<Authority>) -> Result<Tunnel> {
        let _pending = self.pool.enter()?;
        ConnectRequest::new(self, destination.into()).run().await
    }

    async fn establish(
        &self,
        address: SocketAddr,
        slot: &mut Option<Slot>,
    ) -> Result<Arc<Session>> {
        timeout(ATTEMPT_TIMEOUT, async {
            let tcp = connect_outbound(address, self.outbound_mark).await?;
            self.handshake_session_reserved(TcpStream::new(tcp), Some(address), slot.take())
                .await
        })
        .await
        .context("upstream connection attempt timed out")?
    }

    #[cfg(test)]
    async fn handshake(&self, tcp: TcpStream, destination: Authority) -> Result<Tunnel> {
        let session = self.handshake_session(tcp).await?;
        let permit = session.acquire().await?;
        session
            .connect(
                destination,
                self.authorization.clone(),
                self.upstream.require_padding,
                permit,
            )
            .await
    }

    #[cfg(test)]
    async fn handshake_session(&self, tcp: TcpStream) -> Result<Arc<Session>> {
        self.handshake_session_reserved(tcp, None, None).await
    }

    async fn handshake_session_reserved(
        &self,
        tcp: TcpStream,
        address: Option<SocketAddr>,
        slot: Option<Slot>,
    ) -> Result<Arc<Session>> {
        let tls = self
            .tls
            .connect(self.server_name.clone(), tcp)
            .await
            .context("upstream TLS handshake")?;
        ensure!(
            tls.get_ref().1.alpn_protocol() == Some(b"h2"),
            "upstream did not negotiate h2"
        );
        Session::handshake_reserved(
            TlsStream::new(tls),
            self.pool.changed.clone(),
            address,
            slot,
        )
        .await
    }
}

impl<'a> ConnectRequest<'a> {
    fn new(client: &'a Client, destination: Authority) -> Self {
        Self {
            client,
            destination,
            failed: Vec::new(),
        }
    }

    async fn assign(&self, allocation: Allocation) -> Assignment {
        self.client.pool.assign(allocation, &self.failed).await
    }

    async fn while_connecting<F: Future>(&self, work: F) -> ConnectionProgress<F::Output> {
        tokio::select! {
            // Publish a completed handshake before considering another pooled session.
            biased;
            result = work => ConnectionProgress::Ready(result),
            assignment = self.assign(Allocation::Waiting) => match assignment {
                Assignment::Stream(session, permit) => ConnectionProgress::Reused(session, permit),
                _ => unreachable!("waiting allocation only returns existing streams"),
            },
        }
    }

    async fn send(&mut self, session: Arc<Session>, permit: StreamPermit) -> Result<Tunnel> {
        let address = session.address;
        let failed = Arc::downgrade(&session);
        let result = session
            .connect(
                self.destination.clone(),
                self.client.authorization.clone(),
                self.client.upstream.require_padding,
                permit,
            )
            .await;
        if result.is_err() {
            self.failed.push(failed);
        }
        match address {
            Some(address) => result.with_context(|| format!("upstream {address}")),
            None => result,
        }
    }

    async fn stream(&self) -> Result<(Arc<Session>, StreamPermit)> {
        match self.assign(Allocation::Existing).await {
            Assignment::Stream(session, permit) => Ok((session, permit)),
            Assignment::Unavailable => Err(UnsentConnect.into()),
            Assignment::Connection(_) => {
                unreachable!("existing allocation cannot create connections")
            }
        }
    }

    async fn run(mut self) -> Result<Tunnel> {
        loop {
            let allocation = if self.failed.is_empty() {
                Allocation::Any
            } else {
                Allocation::Retry
            };
            let (session, permit) = match self.assign(allocation).await {
                Assignment::Stream(session, permit) => (session, permit),
                Assignment::Connection(slot) => {
                    let resolving = self.client.resolver.resolve_host(&self.client.target);
                    match self.while_connecting(resolving).await {
                        ConnectionProgress::Ready(Ok(addresses)) => {
                            return self.addresses(addresses.iter().copied(), slot).await;
                        }
                        ConnectionProgress::Ready(Err(error)) => {
                            drop(slot);
                            match self.assign(Allocation::Available).await {
                                Assignment::Stream(session, permit) => (session, permit),
                                Assignment::Unavailable => {
                                    return Err(error).context("resolve upstream hostname");
                                }
                                Assignment::Connection(_) => {
                                    unreachable!("available allocation cannot create connections")
                                }
                            }
                        }
                        ConnectionProgress::Reused(session, permit) => {
                            drop(slot);
                            (session, permit)
                        }
                    }
                }
                Assignment::Unavailable => unreachable!("pool allocation can create connections"),
            };
            if let Ok(tunnel) = self.send(session, permit).await {
                return Ok(tunnel);
            }
        }
    }

    async fn addresses(
        mut self,
        addresses: impl IntoIterator<Item = SocketAddr>,
        slot: Slot,
    ) -> Result<Tunnel> {
        let mut last_error = None;
        let mut slot = Some(slot);
        let mut addresses = addresses.into_iter().peekable();
        ensure!(
            addresses.peek().is_some(),
            "upstream hostname resolved to no addresses"
        );
        loop {
            let Some(&address) = addresses.peek() else {
                drop(slot.take());
                // All establishment outcomes share the final pooled-capacity wait.
                let Ok((session, permit)) = self.stream().await else {
                    break;
                };
                match self.send(session, permit).await {
                    Ok(tunnel) => return Ok(tunnel),
                    Err(error) => last_error = Some(error),
                }
                continue;
            };
            let allocation = match slot.take() {
                Some(reserved) => Assignment::Connection(reserved),
                None => self.assign(Allocation::Retry).await,
            };
            let progress = match allocation {
                Assignment::Stream(session, permit) => ConnectionProgress::Reused(session, permit),
                Assignment::Connection(reserved) => {
                    slot = Some(reserved);
                    let establishing = self.client.establish(address, &mut slot);
                    self.while_connecting(establishing).await
                }
                Assignment::Unavailable => unreachable!("retry allocation can create connections"),
            };
            let (session, permit) = match progress {
                ConnectionProgress::Reused(session, permit) => {
                    // Cancellation leaves this address eligible for a later attempt.
                    drop(slot.take());
                    (session, permit)
                }
                ConnectionProgress::Ready(result) => {
                    addresses.next();
                    match result {
                        Ok(session) => self.client.pool.publish(session).await,
                        Err(error) => {
                            last_error = Some(error.context(format!("upstream {address}")));
                        }
                    }
                    continue;
                }
            };
            match self.send(session, permit).await {
                Ok(tunnel) => return Ok(tunnel),
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(error) => Err(error).context("connect to upstream addresses"),
            None => Err(UnsentConnect).context("connect to upstream addresses"),
        }
    }
}

#[cfg(test)]
mod tests;

pub async fn connect_h2<S>(
    stream: S,
    destination: impl Into<Authority>,
    authorization: HeaderValue,
    require_padding: bool,
) -> Result<Tunnel>
where
    S: rama::io::Io + rama::extensions::ExtensionsRef + Unpin,
{
    let session = Session::handshake(stream, Arc::new(Notify::new())).await?;
    let permit = session.acquire().await?;
    session
        .connect(destination.into(), authorization, require_padding, permit)
        .await
}

impl Session {
    fn usable(&self) -> bool {
        !self.sender.is_closed()
            && !self.draining.load(Ordering::Relaxed)
            && self.health.health() == ConnectionHealth::Healthy
    }

    fn active(&self) -> usize {
        PoolPolicy::STREAMS - self.streams.available_permits()
    }

    fn try_acquire(&self) -> Option<StreamPermit> {
        // Serialize the peer-limit check with permit acquisition.
        let _admission = self.admission.lock().expect("admission mutex poisoned");
        let limit = self.max_streams.get();
        if !self.usable() || self.active() >= limit {
            return None;
        }
        let permit = self.streams.clone().try_acquire_owned().ok()?;
        Some(StreamPermit {
            permit: Some(permit),
            changed: self.changed.clone(),
        })
    }

    async fn acquire(&self) -> Result<StreamPermit> {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            ensure!(self.usable(), UnsentConnect);
            if let Some(permit) = self.try_acquire() {
                return Ok(permit);
            }
            notified.await;
        }
    }

    async fn handshake<S>(stream: S, changed: Arc<Notify>) -> Result<Arc<Self>>
    where
        S: rama::io::Io + rama::extensions::ExtensionsRef + Unpin,
    {
        Self::handshake_reserved(stream, changed, None, None).await
    }

    async fn handshake_reserved<S>(
        stream: S,
        changed: Arc<Notify>,
        address: Option<SocketAddr>,
        slot: Option<Slot>,
    ) -> Result<Arc<Self>>
    where
        S: rama::io::Io + ExtensionsRef + Unpin,
    {
        let slot = Arc::new(slot);
        let stream = ReservedIo {
            stream,
            _slot: slot.clone(),
        };
        // Subscribe before the handshake can process the first SETTINGS frame.
        let max_streams = stream
            .extensions()
            .insert_arc(Arc::new(MaxConcurrency::new(usize::MAX)));
        let mut capacity = max_streams.watch();
        let health = stream
            .extensions()
            .get_arc_or_insert(|| Arc::new(ConnectionHealthWatcher::default()));
        let mut health_changes = health.watch();
        let (sender, connection) = http2::Builder::new(Executor::new())
            .with_enable_push(false)
            .with_max_send_buf_size(64 * 1024)
            .handshake::<_, Body>(stream)
            .await
            .context("H2 handshake")?;
        let peer_settings = connection.peer_settings_handle();
        let closed = health.clone();
        let signal = changed.clone();
        let driver = Driver(Some(tokio::spawn(async move {
            tokio::pin!(connection);
            loop {
                tokio::select! {
                    result = &mut connection => {
                        if let Err(error) = result {
                            tracing::debug!(%error, "upstream H2 connection closed");
                        }
                        closed.mark_broken();
                        signal.notify_waiters();
                        break;
                    }
                    Some(_) = capacity.changed() => signal.notify_waiters(),
                    Some(_) = health_changes.changed() => signal.notify_waiters(),
                }
            }
        })));
        peer_settings
            .await_settings()
            .await
            .context("upstream closed before initial H2 SETTINGS")?;
        Ok(Arc::new(Self {
            address,
            sender,
            _driver: driver,
            streams: Arc::new(Semaphore::new(PoolPolicy::STREAMS)),
            admission: StdMutex::new(()),
            max_streams,
            health,
            draining: AtomicBool::new(false),
            changed,
            _slot: slot,
        }))
    }

    async fn connect(
        self: Arc<Self>,
        destination: Authority,
        authorization: HeaderValue,
        require_padding: bool,
        permit: StreamPermit,
    ) -> Result<Tunnel> {
        // Characters from the long-code region of the HPACK Huffman table.
        let padding: String = (0..rand::random_range(16..=32))
            .map(|_| ['!', '"', '#', '$', '\''][rand::random_range(0..5)])
            .collect();
        let mut padding = HeaderValue::from_str(&padding)?;
        padding.set_sensitive(true);
        let request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri(Uri::from_authority_form(destination))
            .header("proxy-authorization", authorization)
            .header("padding", padding)
            .body(Body::empty())?;
        let response = match self.sender.clone().try_send_request(request).await {
            Ok(response) => response,
            Err(mut error) => {
                let unsent = error.take_message().is_some();
                let error = error.into_error();
                if unsent || error.is_closed() {
                    self.draining.store(true, Ordering::Relaxed);
                    self.changed.notify_waiters();
                }
                let error = anyhow::Error::new(error);
                return if unsent {
                    Err(error.context(UnsentConnect).context("CONNECT request"))
                } else {
                    Err(error.context("CONNECT request"))
                };
            }
        };
        ensure!(
            response.status().is_success(),
            "upstream CONNECT rejected: {}",
            response.status()
        );
        let padded = response.headers().contains_key("padding");
        ensure!(
            padded || !require_padding,
            "upstream did not negotiate NaiveProxy padding"
        );
        let stream = handle_upgrade(&response)
            .await
            .map_err(anyhow::Error::from_boxed)
            .context("CONNECT tunnel upgrade")?;
        Ok(Tunnel {
            stream,
            padded,
            _session: self,
            _permit: permit,
        })
    }
}
