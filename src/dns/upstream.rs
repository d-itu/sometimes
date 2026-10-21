use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Result, ensure};
use rama::net::address::{Authority, Domain, HostWithPort};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    time::timeout,
};

use super::{
    Config, Protocol, Upstream,
    bootstrap::{Resolver, Target},
    packet::validate_response,
};
use crate::{
    naive::{client::Client, padding::PaddingIo},
    outbound::connect_outbound,
    routing::{Action, Routing},
};

pub(super) struct PreparedUpstream {
    config: Upstream,
    target: Target,
    proxy_target: Option<HostWithPort>,
}

impl PreparedUpstream {
    pub(super) fn new(config: &Upstream) -> Self {
        let target = Target::new(&config.host, config.port);
        let proxy_target = target.domain().map(|name| {
            HostWithPort::new(
                Domain::try_from(name)
                    .expect("validated DNS upstream domain")
                    .into(),
                config.port,
            )
        });
        Self {
            config: config.clone(),
            target,
            proxy_target,
        }
    }

    pub(super) fn name(&self) -> &str {
        &self.config.name
    }
}

pub(super) struct QueryClient {
    deadline: Duration,
    max_packet_bytes: usize,
    routing: Routing,
    client: Arc<Client>,
    resolver: Arc<Resolver>,
    mark: Option<u32>,
}

impl QueryClient {
    pub(super) fn new(
        config: &Config,
        routing: Routing,
        client: Arc<Client>,
        resolver: Arc<Resolver>,
        mark: Option<u32>,
    ) -> Self {
        Self {
            deadline: Duration::from_millis(config.timeout_ms),
            max_packet_bytes: config.max_packet_bytes,
            routing,
            client,
            resolver,
            mark,
        }
    }

    pub(super) async fn query(
        &self,
        request: &[u8],
        upstream: &PreparedUpstream,
    ) -> Result<Vec<u8>> {
        timeout(self.deadline, self.query_inner(request, upstream)).await?
    }

    async fn query_inner(&self, request: &[u8], prepared: &PreparedUpstream) -> Result<Vec<u8>> {
        let upstream = &prepared.config;
        let domain = prepared.target.domain();
        if let Some(name) = domain
            && self.routing.select_before_dns(name, upstream.port) == Some(Action::Proxy)
        {
            ensure!(
                upstream.protocol != Protocol::Udp,
                "UDP DNS cannot use NaiveProxy"
            );
            let target = prepared.proxy_target.as_ref().unwrap().clone();
            tracing::info!(upstream = %upstream.name, %target, "DNS upstream routed through proxy");
            return self.query_tcp_proxy(request, target).await;
        }
        let addresses = self.resolver.resolve_host(&prepared.target).await?;
        let mut last_error = None;
        for &address in addresses.iter() {
            let (action, rule) = self.routing.select(address, domain);
            tracing::info!(
                upstream = %upstream.name,
                host = %upstream.host,
                %address,
                port = upstream.port,
                ?upstream.protocol,
                ?action,
                ?rule,
                "DNS upstream route selected"
            );
            let result = match action {
                Action::Reject => Err(anyhow::anyhow!("DNS upstream rejected by routing")),
                Action::Direct => match upstream.protocol {
                    Protocol::Udp => {
                        query_udp(request, address, self.max_packet_bytes, self.mark).await
                    }
                    Protocol::Tcp => self.query_tcp(request, address).await,
                },
                Action::Proxy => match upstream.protocol {
                    Protocol::Udp => Err(anyhow::anyhow!("UDP DNS cannot use NaiveProxy")),
                    Protocol::Tcp => self.query_tcp_proxy(request, address).await,
                },
            };
            match result {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last_error = Some(anyhow::anyhow!(
                        "DNS upstream {address} via {action:?}: {error:#}"
                    ))
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses")))
    }

    async fn query_tcp(&self, request: &[u8], address: SocketAddr) -> Result<Vec<u8>> {
        let mut stream = connect_outbound(address, self.mark).await?;
        query_tcp_stream(&mut stream, request, self.max_packet_bytes).await
    }

    async fn query_tcp_proxy(
        &self,
        request: &[u8],
        address: impl Into<Authority>,
    ) -> Result<Vec<u8>> {
        let tunnel = self.client.connect(address).await?;
        let padded = tunnel.padded;
        let mut stream = PaddingIo::new(tunnel, padded);
        query_tcp_stream(&mut stream, request, self.max_packet_bytes).await
    }
}

pub(super) async fn query_udp(
    request: &[u8],
    address: SocketAddr,
    max_packet_bytes: usize,
    mark: Option<u32>,
) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    #[cfg(target_os = "linux")]
    if let Some(mark) = mark {
        socket2::SockRef::from(&socket).set_mark(mark)?;
    }
    socket.connect(address).await?;
    socket.send(request).await?;
    let mut response = vec![0; max_packet_bytes + 1];
    let size = socket.recv(&mut response).await?;
    ensure!(
        size <= max_packet_bytes,
        "DNS UDP response exceeds max_packet_bytes"
    );
    response.truncate(size);
    validate_response(request, &response)?;
    Ok(response)
}

pub(super) async fn query_tcp_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
    max_packet_bytes: usize,
) -> Result<Vec<u8>> {
    stream.write_u16(request.len() as u16).await?;
    stream.write_all(request).await?;
    stream.flush().await?;
    let size = stream.read_u16().await? as usize;
    ensure!(size <= max_packet_bytes, "DNS response is too large");
    let mut response = vec![0; size];
    stream.read_exact(&mut response).await?;
    validate_response(request, &response)?;
    Ok(response)
}
