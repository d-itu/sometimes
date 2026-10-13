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
    Arc<Mutex<LruCache<(String, u16), Arc<AsyncMutex<Option<BootstrapEntry>>>, AHashState>>>;

pub(super) struct BootstrapEntry {
    addresses: Vec<SocketAddr>,
    expires: Instant,
}

pub(super) fn bootstrap_cache() -> BootstrapCache {
    Arc::new(Mutex::new(LruCache::with_hasher(
        NonZeroUsize::new(256).unwrap(),
        AHashState::default(),
    )))
}

pub(crate) async fn resolve_host(
    host: &str,
    port: u16,
    config: &Config,
    mark: Option<u32>,
) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let name = crate::routing::normalize_domain(host).expect("validated DNS upstream host");
    let key = (name.clone(), port);
    let entry = {
        let mut cache = config.bootstrap_cache.lock().unwrap();
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
    let mut queries = tokio::task::JoinSet::new();
    for qtype in [1u16, 28] {
        for &server in &config.bootstrap {
            let request = make_query(&name, qtype);
            let config = config.clone();
            queries.spawn(async move { query_udp(&request, server, &config, mark).await });
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
    *cached = (ttl > 0).then(|| BootstrapEntry {
        addresses: result.clone(),
        expires: Instant::now() + Duration::from_secs(ttl.into()),
    });
    Ok(result)
}
