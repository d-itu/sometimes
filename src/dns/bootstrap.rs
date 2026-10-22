use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ahash::RandomState as AHashState;
use anyhow::{Result, ensure};
use lru::LruCache;
use tokio::sync::Mutex as AsyncMutex;

use super::packet::{answer_ips, cache_ttls, make_query};
use super::{Config, upstream::query_udp};

pub(super) type BootstrapCache =
    LruCache<(Arc<str>, u16), Arc<AsyncMutex<Option<BootstrapEntry>>>, AHashState>;

pub(super) struct BootstrapEntry {
    addresses: Arc<[SocketAddr]>,
    expires: Instant,
}

pub(crate) enum Target {
    Ip(Arc<[SocketAddr]>),
    Domain((Arc<str>, u16)),
}

impl Target {
    pub(crate) fn new(host: &str, port: u16) -> Self {
        match host.parse::<IpAddr>() {
            Ok(ip) => Self::Ip(Arc::from([SocketAddr::new(ip, port)])),
            Err(_) => Self::Domain((
                crate::routing::normalize_domain(host)
                    .expect("validated upstream host")
                    .into(),
                port,
            )),
        }
    }

    pub(super) fn domain(&self) -> Option<&str> {
        match self {
            Self::Ip(_) => None,
            Self::Domain((name, _)) => Some(name),
        }
    }
}

/// Resolves internal hostnames through marked direct bootstrap DNS queries.
pub(crate) struct Resolver {
    servers: Vec<SocketAddr>,
    timeout: Duration,
    max_packet_bytes: usize,
    mark: Option<u32>,
    cache: Mutex<BootstrapCache>,
}

impl Resolver {
    pub(crate) fn from_config(config: &Config, mark: Option<u32>) -> Arc<Self> {
        Arc::new(Self {
            servers: config.bootstrap.clone(),
            timeout: Duration::from_millis(config.timeout_ms),
            max_packet_bytes: config.max_packet_bytes,
            mark,
            cache: Mutex::new(LruCache::with_hasher(
                NonZeroUsize::new(256).unwrap(),
                AHashState::default(),
            )),
        })
    }

    pub(crate) async fn resolve_host(&self, target: &Target) -> Result<Arc<[SocketAddr]>> {
        let (name, port) = match target {
            Target::Ip(addresses) => return Ok(addresses.clone()),
            Target::Domain(key) => key,
        };
        let entry = {
            let mut cache = self.cache.lock().unwrap();
            cache
                .get_or_insert_mut((name.clone(), *port), || Arc::new(AsyncMutex::new(None)))
                .clone()
        };
        let mut cached = entry.lock().await;
        if let Some(value) = cached
            .as_ref()
            .filter(|value| value.expires > Instant::now())
        {
            return Ok(value.addresses.clone());
        }
        let mut result = Vec::new();
        let mut expires = None;
        let timeout = self.timeout;
        let max_packet_bytes = self.max_packet_bytes;
        let mark = self.mark;
        let mut queries = tokio::task::JoinSet::new();
        let mut deadline = tokio::time::Instant::now() + timeout;
        for qtype in [1u16, 28] {
            for &server in &self.servers {
                let request = make_query(name, qtype);
                queries.spawn(async move {
                    let response = tokio::time::timeout(
                        timeout,
                        query_udp(&request, server, max_packet_bytes, mark),
                    )
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|response| response);
                    (response, Instant::now())
                });
            }
        }
        while let Ok(Some(query)) = tokio::time::timeout_at(deadline, queries.join_next()).await {
            if let Ok((Ok(response), received_at)) = query {
                let ips = answer_ips(&response);
                if !ips.is_empty() {
                    if result.is_empty() {
                        let now = tokio::time::Instant::now();
                        // Collect nearby answers without consuming the remaining query budget.
                        let grace = (deadline.saturating_duration_since(now) / 4)
                            .min(Duration::from_millis(50));
                        deadline = now + grace;
                    }
                    let ttl = cache_ttls(&response).map_or(0, |(seconds, _)| seconds);
                    let deadline = received_at + Duration::from_secs(ttl.into());
                    expires =
                        Some(expires.map_or(deadline, |previous: Instant| previous.min(deadline)));
                    for ip in ips {
                        let address = SocketAddr::new(ip, *port);
                        if !result.contains(&address) {
                            result.push(address);
                        }
                    }
                }
            }
        }
        ensure!(
            !result.is_empty(),
            "bootstrap resolver returned no address for DNS upstream"
        );
        let result: Arc<[SocketAddr]> = result.into();
        *cached = expires
            .filter(|&deadline| deadline > Instant::now())
            .map(|expires| BootstrapEntry {
                addresses: result.clone(),
                expires,
            });
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{net::UdpSocket, time::sleep};

    #[tokio::test]
    async fn unresponsive_bootstrap_queries_expire() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = Config {
            bootstrap: vec![server.local_addr().unwrap()],
            timeout_ms: 30,
            ..Config::default()
        };
        let resolver = Resolver::from_config(&config, None);
        let target = Target::new("dns.example", 53);
        let error = tokio::time::timeout(Duration::from_secs(2), resolver.resolve_host(&target))
            .await
            .expect("bootstrap queries must enforce their own deadline")
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("bootstrap resolver returned no address")
        );
    }

    fn answer(request: &[u8], addresses: &[[u8; 4]], ttl: u32) -> Vec<u8> {
        let mut response = request.to_vec();
        response[2] |= 0x80;
        response[6..8].copy_from_slice(&(addresses.len() as u16).to_be_bytes());
        for address in addresses {
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
            response.extend_from_slice(&ttl.to_be_bytes());
            response.extend_from_slice(&[0, 4]);
            response.extend_from_slice(address);
        }
        response
    }

    #[tokio::test]
    async fn concurrent_lookups_share_deduplicated_addresses() {
        let mut servers = Vec::new();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            servers.push(socket.local_addr().unwrap());
            tasks.spawn(async move {
                let mut buffer = [0; 512];
                for _ in 0..2 {
                    let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
                    let request = &buffer[..size];
                    let ips = if request[size - 4..size - 2] == [0, 1] {
                        &[[127, 0, 0, 1], [127, 0, 0, 2], [127, 0, 0, 1]][..]
                    } else {
                        &[]
                    };
                    socket
                        .send_to(&answer(request, ips, 60), peer)
                        .await
                        .unwrap();
                }
            });
        }
        let resolver = Resolver::from_config(
            &Config {
                bootstrap: servers,
                ..Config::default()
            },
            None,
        );
        let first = Target::new("Bootstrap.Example.", 443);
        let second = Target::new("bootstrap.example", 443);
        let (first, second) = tokio::join!(
            resolver.resolve_host(&first),
            resolver.resolve_host(&second)
        );
        let first = first.unwrap();
        assert_eq!(
            first.as_ref(),
            &[
                "127.0.0.1:443".parse::<SocketAddr>().unwrap(),
                "127.0.0.2:443".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert!(Arc::ptr_eq(&first, &second.unwrap()));
        assert!(Arc::ptr_eq(
            &first,
            &resolver
                .resolve_host(&Target::new("bootstrap.example", 443))
                .await
                .unwrap()
        ));
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    }

    #[tokio::test]
    async fn slow_secondary_answer_does_not_delay_addresses_or_extend_ttl() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Resolver::from_config(
            &Config {
                bootstrap: vec![socket.local_addr().unwrap()],
                ..Config::default()
            },
            None,
        );
        let server = tokio::spawn(async move {
            let mut buffer = [0; 512];
            let mut delayed = None;
            for _ in 0..2 {
                let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let request = &buffer[..size];
                if request[size - 4..size - 2] == [0, 1] {
                    socket
                        .send_to(&answer(request, &[[127, 0, 0, 1]], 1), peer)
                        .await
                        .unwrap();
                } else {
                    delayed = Some((request.to_vec(), peer));
                }
            }
            sleep(Duration::from_millis(1200)).await;
            let (request, peer) = delayed.unwrap();
            socket
                .send_to(&answer(&request, &[], 60), peer)
                .await
                .unwrap();
        });
        let target = Target::new("bootstrap.example", 53);
        let started = Instant::now();
        let addresses =
            tokio::time::timeout(Duration::from_millis(500), resolver.resolve_host(&target))
                .await
                .expect("a valid address must not wait for the slow secondary answer")
                .unwrap();
        assert_eq!(
            addresses.as_ref(),
            &["127.0.0.1:53".parse::<SocketAddr>().unwrap()]
        );
        let Target::Domain(key) = target else {
            unreachable!()
        };
        let entry = resolver.cache.lock().unwrap().peek(&key).unwrap().clone();
        let cached = entry.lock().await;
        let cached = cached.as_ref().expect("the valid answer must be cached");
        assert!(cached.expires <= started + Duration::from_millis(1100));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn literal_targets_reuse_prepared_addresses() {
        let resolver = Resolver::from_config(&Config::default(), None);
        for host in ["127.0.0.1", "::1"] {
            let target = Target::new(host, 443);
            let first = resolver.resolve_host(&target).await.unwrap();
            let second = resolver.resolve_host(&target).await.unwrap();
            assert!(Arc::ptr_eq(&first, &second));
            assert_eq!(
                first.as_ref(),
                &[SocketAddr::new(host.parse().unwrap(), 443)]
            );
            assert!(target.domain().is_none());
        }
    }
}
