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
use super::{Config, query_udp};

pub(super) type BootstrapCache =
    LruCache<(String, u16), Arc<AsyncMutex<Option<BootstrapEntry>>>, AHashState>;

pub(super) struct BootstrapEntry {
    addresses: Arc<[SocketAddr]>,
    expires: Instant,
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

    pub(crate) async fn resolve_host(&self, host: &str, port: u16) -> Result<Arc<[SocketAddr]>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Arc::from([SocketAddr::new(ip, port)]));
        }
        let name = crate::routing::normalize_domain(host).expect("validated DNS upstream host");
        let key = (name.clone(), port);
        let entry = {
            let mut cache = self.cache.lock().unwrap();
            cache
                .get_or_insert_mut(key, || Arc::new(AsyncMutex::new(None)))
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
        let mut ttl = u32::MAX;
        let timeout = self.timeout;
        let max_packet_bytes = self.max_packet_bytes;
        let mark = self.mark;
        let mut queries = tokio::task::JoinSet::new();
        for qtype in [1u16, 28] {
            for &server in &self.servers {
                let request = make_query(&name, qtype);
                queries.spawn(async move {
                    query_udp(&request, server, timeout, max_packet_bytes, mark).await
                });
            }
        }
        while let Some(query) = queries.join_next().await {
            if let Ok(Ok(response)) = query {
                let ips = answer_ips(&response);
                if !ips.is_empty() {
                    ttl = ttl.min(cache_ttls(&response).map_or(0, |(seconds, _)| seconds));
                    result.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, port)));
                }
            }
        }
        ensure!(
            !result.is_empty(),
            "bootstrap resolver returned no address for DNS upstream"
        );
        let result: Arc<[SocketAddr]> = result.into();
        *cached = (ttl > 0).then(|| BootstrapEntry {
            addresses: result.clone(),
            expires: Instant::now() + Duration::from_secs(ttl.into()),
        });
        Ok(result)
    }
}
