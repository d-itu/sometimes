//! Explicit proxy inbounds built on Rama's HTTP and SOCKS5 servers.
use std::{
    convert::Infallible,
    io, mem,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    config::Config,
    naive::client::{Client, Tunnel},
    outbound::connect_outbound,
    relay::relay,
    routing::{Action, normalize_domain},
};
use anyhow::Result;
use rama::{
    Service,
    extensions::{Extensions, ExtensionsRef},
    http::{
        Body, HeaderMap, Method, Request, Response, StatusCode, Version,
        core::{body::Incoming, client::conn::http1, server::conn::auto},
        header,
        io::upgrade::handle_upgrade,
    },
    io::BridgeIo,
    net::{
        address::{Domain, HostWithPort},
        client::{ConnectRequest, EstablishedClientConnection},
    },
    proxy::socks5::server::{Connector, Socks5Acceptor},
    rt::Executor,
    service::service_fn,
    tcp::TcpStream as RamaTcpStream,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{AbortHandle, JoinHandle, JoinSet},
    time::timeout,
};

#[cfg(test)]
mod tests;

#[derive(Clone)]
struct State {
    config: Arc<Config>,
    client: Arc<Client>,
    permits: Arc<Semaphore>,
}

// The bounded bridge applies Naive framing once, independently of the inbound protocol.
enum Transport {
    Direct(TcpStream),
    Proxy(DuplexStream),
}
struct Egress {
    transport: Transport,
    extensions: Extensions,
    driver: Option<JoinHandle<()>>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Egress {
    fn drop(&mut self) {
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}
impl ExtensionsRef for Egress {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}
impl AsyncRead for Egress {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().transport {
            Transport::Direct(io) => Pin::new(io).poll_read(cx, buf),
            Transport::Proxy(io) => Pin::new(io).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for Egress {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().transport {
            Transport::Direct(io) => Pin::new(io).poll_write(cx, buf),
            Transport::Proxy(io) => Pin::new(io).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().transport {
            Transport::Direct(io) => Pin::new(io).poll_flush(cx),
            Transport::Proxy(io) => Pin::new(io).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().transport {
            Transport::Direct(io) => Pin::new(io).poll_shutdown(cx),
            Transport::Proxy(io) => Pin::new(io).poll_shutdown(cx),
        }
    }
}
fn tunnel_transport(mut tunnel: Tunnel, idle: Duration) -> (Transport, Option<JoinHandle<()>>) {
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let driver = tokio::spawn(async move {
        if let Err(error) = relay(remote, &mut tunnel.stream, tunnel.padded, idle).await {
            tracing::debug!(%error, "Naive bridge ended");
        }
    });
    (Transport::Proxy(local), Some(driver))
}
impl State {
    async fn connect(&self, host: &str, port: u16) -> io::Result<Egress> {
        let domain = normalize_domain(host);
        if domain.is_none() && host.parse::<IpAddr>().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid destination hostname",
            ));
        }
        let before_dns = domain
            .as_deref()
            .and_then(|name| self.config.routing.select_before_dns(name, port));
        if before_dns == Some(Action::Reject) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "route rejected",
            ));
        }
        let permit = self.permits.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "outbound connection limit reached",
            )
        })?;
        timeout(
            Duration::from_secs(self.config.connect_timeout_secs),
            async {
                if before_dns == Some(Action::Proxy) {
                    let name = domain.as_deref().expect("pre-DNS decision has a domain");
                    let destination = HostWithPort::new(
                        Domain::try_from(name)
                            .expect("normalized domain is valid")
                            .into(),
                        port,
                    );
                    tracing::info!(%destination, ?before_dns, "route selected");
                    let tunnel = self
                        .client
                        .connect(destination)
                        .await
                        .map_err(io::Error::other)?;
                    let (transport, driver) = tunnel_transport(
                        tunnel,
                        Duration::from_secs(self.config.idle_timeout_secs),
                    );
                    return Ok(Egress {
                        transport,
                        driver,
                        extensions: Extensions::new(),
                        _permit: permit,
                    });
                }
                let destination = match host.parse() {
                    Ok(ip) => SocketAddr::new(ip, port),
                    Err(_) => tokio::net::lookup_host((host, port))
                        .await?
                        .next()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                "target DNS returned no address",
                            )
                        })?,
                };
                let (action, rule) = self.config.routing.select(destination, domain.as_deref());
                tracing::info!(%destination, domain = host, ?action, ?rule, "route selected");
                let (transport, driver) = match action {
                    Action::Reject => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "route rejected",
                        ));
                    }
                    Action::Direct => (
                        Transport::Direct(
                            connect_outbound(destination, self.config.outbound_mark).await?,
                        ),
                        None,
                    ),
                    Action::Proxy => {
                        let tunnel = self
                            .client
                            .connect(destination)
                            .await
                            .map_err(io::Error::other)?;
                        tunnel_transport(tunnel, Duration::from_secs(self.config.idle_timeout_secs))
                    }
                };
                Ok(Egress {
                    transport,
                    driver,
                    extensions: Extensions::new(),
                    _permit: permit,
                })
            },
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "target connection deadline exceeded",
            )
        })?
    }
}

fn response(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}
fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| header::HeaderName::from_bytes(v.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
    ] {
        headers.remove(name);
    }
}

struct DriverGuard(AbortHandle);
impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type Tasks = Arc<Mutex<JoinSet<()>>>;
fn spawn(tasks: &Tasks, task: impl Future<Output = ()> + Send + 'static) -> AbortHandle {
    let mut tasks = tasks.lock().unwrap();
    while tasks.try_join_next().is_some() {}
    tasks.spawn(task)
}
async fn request(mut request: Request<Incoming>, state: State, tasks: Tasks) -> Response {
    let connect = request.method() == Method::CONNECT;
    let Some(authority) = request.uri().authority().map(|a| a.to_string()) else {
        return response(StatusCode::BAD_REQUEST);
    };
    let port = request.uri().port_u16();
    if (!connect && request.uri().scheme_str() != Some("http"))
        || (connect && port.is_none())
        || authority.contains('@')
    {
        return response(StatusCode::BAD_REQUEST);
    }
    let host = request.uri().host_str().unwrap();
    let upstream = match state
        .connect(host.trim_matches(['[', ']']), port.unwrap_or(80))
        .await
    {
        Ok(stream) => stream,
        Err(error) => {
            tracing::debug!(%error, "HTTP target connection failed");
            return response(match error.kind() {
                io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
                io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
                io::ErrorKind::TimedOut => StatusCode::GATEWAY_TIMEOUT,
                io::ErrorKind::WouldBlock => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::BAD_GATEWAY,
            });
        }
    };
    if connect {
        let upgrade = handle_upgrade(&request);
        let idle = Duration::from_secs(state.config.idle_timeout_secs);
        spawn(&tasks, async move {
            match upgrade.await {
                Ok(stream) => {
                    if let Err(error) = relay(stream, upstream, false, idle).await {
                        tracing::debug!(%error, "HTTP CONNECT ended");
                    }
                }
                Err(error) => tracing::debug!(%error, "HTTP upgrade failed"),
            }
        });
        return response(StatusCode::OK);
    }
    request
        .uri_mut()
        .unset_scheme()
        .maybe_set_authority(None)
        .ensure_path_or_root();
    *request.version_mut() = Version::HTTP_11;
    strip_hop_headers(request.headers_mut());
    request
        .headers_mut()
        .insert(header::HOST, authority.as_str().parse().unwrap());
    // The response body owns the origin driver's lifetime; ingress can be reused.
    let (mut sender, connection) = match http1::handshake(upstream).await {
        Ok(value) => value,
        Err(_) => return response(StatusCode::BAD_GATEWAY),
    };
    let driver = DriverGuard(spawn(&tasks, async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "HTTP origin connection ended");
        }
    }));
    match timeout(
        Duration::from_secs(state.config.idle_timeout_secs),
        sender.send_request(request),
    )
    .await
    {
        Ok(Ok(mut reply)) => {
            strip_hop_headers(reply.headers_mut());
            reply.map(|body| Body::new(body).on_drop(move || drop(driver)))
        }
        Ok(Err(error)) => {
            tracing::debug!(%error, "HTTP forwarding failed");
            response(StatusCode::BAD_GATEWAY)
        }
        Err(_) => response(StatusCode::GATEWAY_TIMEOUT),
    }
}

pub async fn http(
    stream: TcpStream,
    config: Arc<Config>,
    client: Arc<Client>,
    permits: Arc<Semaphore>,
) -> Result<()> {
    let state = State {
        config,
        client,
        permits,
    };
    let tasks = Tasks::default();
    let pending = tasks.clone();
    let service = service_fn(move |req| {
        let state = state.clone();
        let tasks = pending.clone();
        async move { Ok::<_, Infallible>(request(req, state, tasks).await) }
    });
    let mut builder = auto::Builder::new(Executor::default());
    builder.h2_mut().set_max_concurrent_streams(32);
    let result = builder
        .serve_connection_with_upgrades(RamaTcpStream::new(stream), service)
        .await;
    let mut pending = {
        let mut tasks = tasks.lock().unwrap();
        mem::take(&mut *tasks)
    };
    while pending.join_next().await.is_some() {}
    result.map_err(anyhow::Error::from_boxed)
}

pub async fn socks(
    stream: TcpStream,
    config: Arc<Config>,
    client: Arc<Client>,
    permits: Arc<Semaphore>,
) -> Result<()> {
    let idle = Duration::from_secs(config.idle_timeout_secs);
    let state = State {
        config,
        client,
        permits,
    };
    let connect = service_fn(move |input: ConnectRequest| {
        let state = state.clone();
        async move {
            let conn = state
                .connect(&input.authority.host.to_string(), input.authority.port)
                .await?;
            Ok::<_, rama::error::BoxError>(EstablishedClientConnection { input, conn })
        }
    });
    let forward = service_fn(
        move |BridgeIo(local, upstream): BridgeIo<RamaTcpStream, Egress>| async move {
            relay(local, upstream, false, idle).await.map(|_| ())
        },
    );
    Socks5Acceptor::new(Executor::default())
        .with_connector(Connector::new(connect, forward))
        .serve(RamaTcpStream::new(stream))
        .await?;
    Ok(())
}
