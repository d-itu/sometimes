use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as AnyhowContext, Result, ensure};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::timeout,
};

use crate::{
    naive::client::Client,
    routing::{Routing, normalize_domain},
};

pub mod bootstrap;
mod cache;
mod packet;
mod upstream;

use bootstrap::Resolver;
use cache::ResponseCache;
use packet::{error_response, query};
use upstream::{PreparedUpstream, QueryClient};

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub listen: Vec<SocketAddr>,
    pub upstreams: Vec<Upstream>,
    pub bootstrap: Vec<SocketAddr>,
    pub timeout_ms: u64,
    pub max_packet_bytes: usize,
    pub cache_size: usize,
    pub max_tcp_connections: usize,
    pub tcp_idle_timeout_secs: u64,
    pub routing: DnsRouting,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: vec![],
            upstreams: vec![Upstream::default()],
            bootstrap: vec!["9.9.9.9:53".parse().unwrap()],
            timeout_ms: 2000,
            max_packet_bytes: 4096,
            cache_size: 4096,
            max_tcp_connections: 64,
            tcp_idle_timeout_secs: 30,
            routing: DnsRouting::default(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            name: "direct".into(),
            protocol: Protocol::Udp,
            host: "127.0.0.1".into(),
            port: 53,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    #[serde(rename = "udp")]
    #[default]
    Udp,
    #[serde(rename = "tcp")]
    Tcp,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsRouting {
    pub default: String,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub upstream: Option<String>,
    pub action: Option<Action>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Reject,
}

impl Default for DnsRouting {
    fn default() -> Self {
        Self {
            default: "direct".into(),
            rules: vec![],
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.timeout_ms > 0, "dns timeout_ms must be positive");
        ensure!(
            (512..=65535).contains(&self.max_packet_bytes),
            "dns max_packet_bytes must be in 512..=65535"
        );
        ensure!(self.cache_size > 0, "dns cache_size must be positive");
        ensure!(
            (1..=65_536).contains(&self.max_tcp_connections),
            "dns max_tcp_connections must be in 1..=65536"
        );
        ensure!(
            self.tcp_idle_timeout_secs > 0,
            "dns tcp_idle_timeout_secs must be positive"
        );
        if self.enabled {
            ensure!(
                !self.listen.is_empty(),
                "dns.listen is required when DNS is enabled"
            );
            ensure!(
                !self.upstreams.is_empty(),
                "dns.upstreams is required when DNS is enabled"
            );
            ensure!(
                !self.bootstrap.is_empty(),
                "dns.bootstrap is required when DNS is enabled"
            );
        }
        let mut names = HashSet::new();
        for upstream in &self.upstreams {
            ensure!(
                !upstream.name.is_empty(),
                "DNS upstream name must not be empty"
            );
            ensure!(
                names.insert(upstream.name.as_str()),
                "duplicate DNS upstream name"
            );
            ensure!(upstream.port != 0, "DNS upstream port must be nonzero");
            ensure!(
                upstream.host.parse::<IpAddr>().is_ok()
                    || normalize_domain(&upstream.host).is_some(),
                "invalid DNS upstream host"
            );
        }
        for rule in &self.routing.rules {
            ensure!(
                !rule.domain.is_empty() || !rule.domain_suffix.is_empty(),
                "DNS rules need a domain condition"
            );
            ensure!(
                rule.upstream.is_some() ^ rule.action.is_some(),
                "DNS rule needs exactly one upstream or action"
            );
            if let Some(name) = rule.upstream.as_deref() {
                ensure!(
                    names.contains(name),
                    "DNS rule references unknown upstream: {name}"
                );
            }
            for name in rule.domain.iter().chain(&rule.domain_suffix) {
                ensure!(
                    normalize_domain(name).is_some(),
                    "invalid DNS routing domain"
                );
            }
        }
        ensure!(
            self.upstreams
                .iter()
                .any(|u| u.name == self.routing.default),
            "DNS default upstream does not exist"
        );
        Ok(())
    }
}

struct PreparedRouting {
    rules: Vec<PreparedRule>,
    default: usize,
}

struct PreparedRule {
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    upstream: Option<usize>,
}

impl PreparedRouting {
    fn new(config: &Config) -> Self {
        let index = |name: &str| {
            config
                .upstreams
                .iter()
                .position(|upstream| upstream.name == name)
                .expect("validated DNS upstream name")
        };
        let domains = |names: &[String]| {
            names
                .iter()
                .map(|name| normalize_domain(name).expect("validated DNS routing domain"))
                .collect()
        };
        Self {
            default: index(&config.routing.default),
            rules: config
                .routing
                .rules
                .iter()
                .map(|rule| PreparedRule {
                    domain: domains(&rule.domain),
                    domain_suffix: domains(&rule.domain_suffix),
                    upstream: rule.upstream.as_deref().map(index),
                })
                .collect(),
        }
    }

    fn target(&self, name: &str) -> Option<usize> {
        let rule = self.rules.iter().find(|rule| {
            rule.domain.iter().any(|item| item == name)
                || rule.domain_suffix.iter().any(|item| {
                    name == item || name.strip_suffix(item).is_some_and(|p| p.ends_with('.'))
                })
        });
        rule.map_or(Some(self.default), |rule| rule.upstream)
    }
}

type Cache = Arc<ResponseCache>;

#[derive(Clone)]
struct Context {
    config: Arc<Config>,
    dns_routing: Arc<PreparedRouting>,
    upstreams: Arc<[PreparedUpstream]>,
    cache: Cache,
    queries: Arc<QueryClient>,
}

pub(crate) async fn run(
    config: Arc<Config>,
    mark: Option<u32>,
    routing: Routing,
    client: Arc<Client>,
    resolver: Arc<Resolver>,
) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    let cache = Arc::new(ResponseCache::new(
        NonZeroUsize::new(config.cache_size).expect("validated nonzero DNS cache size"),
    ));
    let context = Context::new(config, cache, routing, client, resolver, mark);
    context.run().await
}

impl Context {
    fn new(
        config: Arc<Config>,
        cache: Cache,
        routing: Routing,
        client: Arc<Client>,
        resolver: Arc<Resolver>,
        mark: Option<u32>,
    ) -> Self {
        Self {
            dns_routing: Arc::new(PreparedRouting::new(&config)),
            upstreams: config.upstreams.iter().map(PreparedUpstream::new).collect(),
            queries: Arc::new(QueryClient::new(&config, routing, client, resolver, mark)),
            config,
            cache,
        }
    }

    async fn run(&self) -> Result<()> {
        let mut tasks = JoinSet::new();
        for address in &self.config.listen {
            let udp = UdpSocket::bind(address)
                .await
                .context("bind DNS UDP listener")?;
            let tcp = TcpListener::bind(address)
                .await
                .context("bind DNS TCP listener")?;
            tasks.spawn(self.clone().serve_udp(udp));
            tasks.spawn(self.clone().serve_tcp(tcp));
        }
        let result = tasks.join_next().await.context("no DNS listener started")?;
        tasks.abort_all();
        result.context("DNS task failed")??;
        anyhow::bail!("DNS listener stopped unexpectedly")
    }

    async fn serve_udp(self, socket: UdpSocket) -> Result<()> {
        let socket = Arc::new(socket);
        let mut buffer = vec![0; self.config.max_packet_bytes];
        let mut requests = JoinSet::new();
        loop {
            if requests.len() >= 64
                && let Some(Err(error)) = requests.join_next().await
            {
                tracing::warn!(%error, "DNS UDP request task failed");
            }
            let (size, peer) = socket.recv_from(&mut buffer).await?;
            let request = buffer[..size].to_vec();
            let socket = socket.clone();
            let context = self.clone();
            requests.spawn(async move {
                let response = context.handle(&request).await.and_then(|response| {
                    packet::udp_response(&request, response, context.config.max_packet_bytes)
                });
                match response {
                    Ok(response) => {
                        if let Err(error) = socket.send_to(&response, peer).await {
                            tracing::warn!(%error, "DNS UDP reply failed");
                        }
                    }
                    Err(error) => tracing::debug!(%error, "DNS UDP query rejected"),
                }
            });
            while let Some(result) = requests.try_join_next() {
                if let Err(error) = result {
                    tracing::warn!(%error, "DNS UDP request task failed");
                }
            }
        }
    }

    async fn serve_tcp(self, listener: TcpListener) -> Result<()> {
        let mut connections = JoinSet::new();
        loop {
            if connections.len() >= self.config.max_tcp_connections
                && let Some(Err(error)) = connections.join_next().await
            {
                tracing::warn!(%error, "DNS TCP connection task failed");
            }
            let (stream, _) = listener.accept().await?;
            let context = self.clone();
            connections.spawn(async move {
                let _ = context.handle_tcp(stream).await;
            });
            while let Some(result) = connections.try_join_next() {
                if let Err(error) = result {
                    tracing::warn!(%error, "DNS TCP connection task failed");
                }
            }
        }
    }

    async fn handle_tcp(self, mut stream: TcpStream) -> Result<()> {
        let idle = Duration::from_secs(self.config.tcp_idle_timeout_secs);
        let mut request = Vec::new();
        loop {
            let size = timeout(idle, stream.read_u16()).await?? as usize;
            ensure!(
                size <= self.config.max_packet_bytes,
                "DNS TCP packet is too large"
            );
            request.resize(size, 0);
            timeout(idle, stream.read_exact(&mut request)).await??;
            let response = self.handle(&request).await?;
            ensure!(
                response.len() <= u16::MAX as usize,
                "DNS response is too large"
            );
            timeout(idle, async {
                stream.write_u16(response.len() as u16).await?;
                stream.write_all(&response).await
            })
            .await??;
        }
    }

    async fn handle(&self, request: &[u8]) -> Result<Vec<u8>> {
        let (name, _, _) = query(request).ok_or_else(|| anyhow::anyhow!("invalid DNS query"))?;
        if let Some(response) = self.cache.get(request) {
            return response;
        }
        let Some(index) = self.dns_routing.target(&name) else {
            return error_response(request, 5);
        };
        let upstream = &self.upstreams[index];
        let response = match self.queries.query(request, upstream).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(upstream = %upstream.name(), %error, "DNS upstream query failed");
                error_response(request, 2)?
            }
        };
        self.cache.insert(request, &response);
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
