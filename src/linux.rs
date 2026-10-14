use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    config::{Config, InboundProtocol},
    dns,
    naive::client::Client,
    outbound::connect_outbound,
    relay::relay,
    routing::Action,
    sniff,
};
use anyhow::{Context, Result};
use rama::net::socket::SocketOptions;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};

pub fn listen(address: SocketAddr, transparent: bool) -> io::Result<TcpListener> {
    let socket = SocketOptions {
        address: Some(address.into()),
        reuse_address: Some(true),
        ip_transparent: (transparent && address.is_ipv4()).then_some(true),
        ip_transparent_v6: (transparent && address.is_ipv6()).then_some(true),
        only_v6: address.is_ipv6().then_some(true),
        ..SocketOptions::default_tcp()
    }
    .try_build_socket(address.into())?;
    socket.set_nonblocking(true)?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// Route one accepted flow while preserving the original destination.
pub async fn handle_flow<S>(
    stream: S,
    destination: SocketAddr,
    config: &Config,
    client: &Client,
) -> Result<(u64, u64)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (stream, domain) = sniff::inspect(stream, &config.sniff).await?;
    route_stream(stream, destination, domain.as_deref(), config, client).await
}

async fn route_stream<S>(
    stream: S,
    destination: SocketAddr,
    domain: Option<&str>,
    config: &Config,
    client: &Client,
) -> Result<(u64, u64)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (action, rule) = config.routing.select(destination, domain);
    tracing::info!(%destination, ?domain, ?action, ?rule, "route selected");
    let deadline = Duration::from_secs(config.connect_timeout_secs);
    let idle = Duration::from_secs(config.idle_timeout_secs);
    match action {
        Action::Reject => Ok((0, 0)),
        Action::Direct => {
            let upstream = timeout(
                deadline,
                connect_outbound(destination, config.outbound_mark),
            )
            .await
            .context("direct connection deadline exceeded")??;
            Ok(relay(stream, upstream, false, idle).await?)
        }
        Action::Proxy => {
            let mut tunnel = timeout(deadline, client.connect(destination))
                .await
                .context("upstream connection deadline exceeded")??;
            Ok(relay(stream, &mut tunnel.stream, tunnel.padded, idle).await?)
        }
    }
}

pub async fn run(config: Arc<Config>) -> Result<()> {
    let resolver = dns::bootstrap::Resolver::from_config(&config.dns, config.outbound_mark);
    let client = Arc::new(Client::new_with_resolver(
        config.upstream.clone(),
        config.outbound_mark,
        resolver.clone(),
    )?);
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let outbound_permits = Arc::new(Semaphore::new(config.max_connections));
    let mut acceptors = JoinSet::new();
    let mut flows = JoinSet::new();
    let dns = config.dns.clone();
    let dns_mark = config.outbound_mark;
    let dns_routing = config.routing.clone();
    let dns_client = client.clone();
    let mut dns_task = tokio::spawn(dns::run(
        Arc::new(dns),
        dns_mark,
        dns_routing,
        dns_client,
        resolver,
    ));
    // Bind all listeners before starting any accept task.
    let listeners = config
        .listeners
        .iter()
        .map(|listener| {
            let address = listener.socket_addr()?;
            listen(address, listener.protocol == InboundProtocol::Tproxy)
                .with_context(|| format!("bind listener {address}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(config.listeners.len());
    for (listener, configured) in listeners.into_iter().zip(config.listeners.iter().cloned()) {
        let tx = accepted_tx.clone();
        acceptors.spawn(async move {
            loop {
                let accepted = listener.accept().await?;
                if tx
                    .send((accepted.0, accepted.1, configured.protocol))
                    .await
                    .is_err()
                {
                    return Ok::<_, io::Error>(());
                }
            }
        });
    }
    drop(accepted_tx);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    tracing::info!(listeners = config.listeners.len(), "TCP client started");
    loop {
        tokio::select! {
            result = &mut interrupt => { result?; break; }
            _ = terminate.recv() => break,
            result = &mut dns_task, if config.dns.enabled => {
                result.context("DNS task failed")??;
                anyhow::bail!("DNS service stopped unexpectedly");
            }
            Some(result) = acceptors.join_next() => {
                result.context("listener task failed")??;
                anyhow::bail!("listener stopped unexpectedly");
            }
            Some(result) = flows.join_next(), if !flows.is_empty() => {
                if let Err(error) = result { tracing::warn!(%error, "flow task failed"); }
            }
            Some((stream, peer, protocol)) = accepted_rx.recv() => {
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::debug!(%peer, "connection limit reached");
                    continue;
                };
                let client = client.clone();
                let config = config.clone();
                let outbound_permits = outbound_permits.clone();
                flows.spawn(async move {
                    let _permit = permit;
                    let result: Result<()> = async {
                        match protocol {
                            InboundProtocol::Tproxy => {
                                let destination = stream.local_addr()?;
                                stream.set_nodelay(true)?;
                                let (sent, received) = handle_flow(stream, destination, &config, &client).await?;
                                tracing::debug!(%peer, %destination, sent, received, "transparent flow completed");
                            }
                            InboundProtocol::Http => crate::inbound::http(stream, config, client, outbound_permits).await?,
                            InboundProtocol::Socks => crate::inbound::socks(stream, config, client, outbound_permits).await?,
                        }
                        Ok(())
                    }.await;
                    if let Err(error) = result { tracing::warn!(%peer, error = %format!("{error:#}"), "flow failed"); }
                });
            }
        }
    }
    acceptors.abort_all();
    dns_task.abort();
    tracing::info!(
        active = flows.len(),
        "draining active connections for up to 10 seconds"
    );
    if timeout(Duration::from_secs(10), async {
        while flows.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        flows.abort_all();
        while flows.join_next().await.is_some() {}
    }
    Ok(())
}
