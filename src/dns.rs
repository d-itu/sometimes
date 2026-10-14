use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as AnyhowContext, Result, ensure};
use rama::net::address::{Authority, Domain, HostWithPort};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::timeout,
};

use crate::{
    naive::client::Client,
    outbound::connect_outbound,
    relay::relay,
    routing::{Action as RouteAction, Routing, normalize_domain},
};

pub mod bootstrap;
mod cache;
mod packet;

use bootstrap::Resolver;
use cache::ResponseCache;
use packet::{query, refused, validate_response, with_id};

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
    #[serde(rename = "tcp+udp")]
    TcpUdp,
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

    fn target<'a>(&'a self, name: &str) -> Result<Option<&'a Upstream>> {
        let rule = self.routing.rules.iter().find(|rule| {
            rule.domain
                .iter()
                .any(|item| normalize_domain(item).as_deref() == Some(name))
                || rule.domain_suffix.iter().any(|item| {
                    normalize_domain(item).is_some_and(|suffix| {
                        name == suffix
                            || name.strip_suffix(&suffix).is_some_and(|p| p.ends_with('.'))
                    })
                })
        });
        match rule {
            Some(rule) if rule.action.is_some() => Ok(None),
            Some(rule) => self
                .upstreams
                .iter()
                .find(|u| Some(&u.name) == rule.upstream.as_ref())
                .map(Some)
                .context("DNS rule references unknown upstream"),
            None => self
                .upstreams
                .iter()
                .find(|u| u.name == self.routing.default)
                .map(Some)
                .context("DNS default upstream does not exist"),
        }
    }
}

type Cache = Arc<ResponseCache>;

#[derive(Clone)]
struct Context {
    config: Arc<Config>,
    cache: Cache,
    routing: Arc<Routing>,
    client: Arc<Client>,
    resolver: Arc<Resolver>,
    mark: Option<u32>,
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
            config,
            cache,
            routing: Arc::new(routing),
            client,
            resolver,
            mark,
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
                match context.handle(&request).await {
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
        loop {
            let size = timeout(idle, stream.read_u16()).await?? as usize;
            ensure!(
                size <= self.config.max_packet_bytes,
                "DNS TCP packet is too large"
            );
            let mut request = vec![0; size];
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
        let Some(upstream) = self.config.target(&name)? else {
            return refused(request);
        };
        let response = match self.query_upstream(request, upstream).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(upstream = %upstream.name, %error, "DNS upstream query failed");
                refused(request)?
            }
        };
        self.cache.insert(request, &response);
        with_id(&response, request)
    }

    async fn query_upstream(&self, request: &[u8], upstream: &Upstream) -> Result<Vec<u8>> {
        let domain = normalize_domain(&upstream.host);
        if let Some(name) = domain.as_deref()
            && self.routing.select_before_dns(name, upstream.port) == Some(RouteAction::Proxy)
        {
            ensure!(
                upstream.protocol != Protocol::Udp,
                "UDP DNS cannot use NaiveProxy"
            );
            let target = HostWithPort::new(
                Domain::try_from(name)
                    .expect("validated DNS upstream domain")
                    .into(),
                upstream.port,
            );
            tracing::info!(upstream = %upstream.name, %target, "DNS upstream routed through proxy");
            return self.query_tcp_proxy(request, target).await;
        }
        let addresses = self
            .resolver
            .resolve_host(&upstream.host, upstream.port)
            .await?;
        let mut last_error = None;
        for address in addresses {
            let (action, rule) = self
                .routing
                .select(address, normalize_domain(&upstream.host).as_deref());
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
                RouteAction::Reject => Err(anyhow::anyhow!("DNS upstream rejected by routing")),
                RouteAction::Direct => match upstream.protocol {
                    Protocol::Udp => {
                        query_udp(
                            request,
                            address,
                            Duration::from_millis(self.config.timeout_ms),
                            self.config.max_packet_bytes,
                            self.mark,
                        )
                        .await
                    }
                    Protocol::Tcp => self.query_tcp(request, address).await,
                    Protocol::TcpUdp => match query_udp(
                        request,
                        address,
                        Duration::from_millis(self.config.timeout_ms),
                        self.config.max_packet_bytes,
                        self.mark,
                    )
                    .await
                    {
                        Ok(response) if !response.get(2).is_some_and(|v| v & 2 != 0) => {
                            Ok(response)
                        }
                        _ => self.query_tcp(request, address).await,
                    },
                },
                RouteAction::Proxy => match upstream.protocol {
                    Protocol::Udp => Err(anyhow::anyhow!("UDP DNS cannot use NaiveProxy")),
                    Protocol::Tcp | Protocol::TcpUdp => {
                        self.query_tcp_proxy(request, address).await
                    }
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
        timeout(Duration::from_millis(self.config.timeout_ms), async {
            let mut stream = connect_outbound(address, self.mark).await?;
            query_tcp_stream(&mut stream, request, self.config.max_packet_bytes).await
        })
        .await?
    }

    async fn query_tcp_proxy(
        &self,
        request: &[u8],
        address: impl Into<Authority>,
    ) -> Result<Vec<u8>> {
        timeout(Duration::from_millis(self.config.timeout_ms), async {
            let mut tunnel = self.client.connect(address).await?;
            let (mut local, remote) = tokio::io::duplex(64 * 1024);
            let query = query_tcp_stream(&mut local, request, self.config.max_packet_bytes);
            tokio::pin!(query);
            tokio::select! {
                biased;
                result = &mut query => result,
                result = relay(remote, &mut tunnel.stream, tunnel.padded, Duration::from_millis(self.config.timeout_ms)) => {
                    result?;
                    query.await
                }
            }
        })
        .await?
    }
}

async fn query_udp(
    request: &[u8],
    address: SocketAddr,
    deadline: Duration,
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
    let size = timeout(deadline, socket.recv(&mut response)).await??;
    ensure!(
        size <= max_packet_bytes,
        "DNS UDP response exceeds max_packet_bytes"
    );
    response.truncate(size);
    validate_response(request, &response)?;
    Ok(response)
}

async fn query_tcp_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
    max_packet_bytes: usize,
) -> Result<Vec<u8>> {
    stream.write_u16(request.len() as u16).await?;
    stream.write_all(request).await?;
    let size = stream.read_u16().await? as usize;
    ensure!(size <= max_packet_bytes, "DNS response is too large");
    let mut response = vec![0; size];
    stream.read_exact(&mut response).await?;
    validate_response(request, &response)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_dns_upstream_references() {
        let mut config = Config::default();
        config.routing.rules.push(Rule {
            upstream: Some("missing".into()),
            action: None,
            domain: vec!["example.com".into()],
            domain_suffix: vec![],
        });
        assert!(config.validate().is_err());
        config.routing.rules[0].upstream = Some("direct".into());
        config.validate().unwrap();
        config.upstreams.push(config.upstreams[0].clone());
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn oversized_udp_response_is_not_forwarded() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut request = [0; 512];
            let (size, peer) = server.recv_from(&mut request).await.unwrap();
            let mut response = request[..size].to_vec();
            response[2] |= 0x80;
            response.resize(513, 0);
            server.send_to(&response, peer).await.unwrap();
        });
        let config = Config {
            max_packet_bytes: 512,
            ..Config::default()
        };
        let request = packet::make_query("example.com", 1);
        let error = query_udp(
            &request,
            address,
            Duration::from_millis(config.timeout_ms),
            config.max_packet_bytes,
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("exceeds max_packet_bytes"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn proxied_dns_domain_skips_local_bootstrap() {
        let config = Arc::new(Config {
            bootstrap: vec![],
            ..Config::default()
        });
        let upstream = Upstream {
            host: "dns.example.invalid".into(),
            protocol: Protocol::Udp,
            ..Upstream::default()
        };
        let client = Client::new(
            crate::config::Upstream {
                host: "127.0.0.1".into(),
                port: 443,
                server_name: None,
                username: "user".into(),
                password: "pass".into(),
                require_padding: true,
            },
            None,
        )
        .unwrap();
        let request = packet::make_query("example.com", 1);
        let resolver = Resolver::from_config(&config, None);
        let context = Context::new(
            config.clone(),
            Arc::new(ResponseCache::new(
                NonZeroUsize::new(config.cache_size).unwrap(),
            )),
            Routing::default(),
            Arc::new(client),
            resolver.clone(),
            None,
        );
        let error = context
            .query_upstream(&request, &upstream)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("UDP DNS cannot use NaiveProxy"));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
        });
        let proxy = crate::config::Upstream {
            host: "127.0.0.1".into(),
            port: proxy_address.port(),
            server_name: None,
            username: "user".into(),
            password: "pass".into(),
            require_padding: true,
        };
        let client = Client::new(proxy, None).unwrap();
        let upstream = Upstream {
            protocol: Protocol::Tcp,
            ..upstream
        };
        let context = Context::new(
            config.clone(),
            Arc::new(ResponseCache::new(
                NonZeroUsize::new(config.cache_size).unwrap(),
            )),
            Routing::default(),
            Arc::new(client),
            resolver,
            None,
        );
        assert!(context.query_upstream(&request, &upstream).await.is_err());
        timeout(Duration::from_secs(3), accepted)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn extracts_and_routes_names() {
        let mut packet = vec![0; 12];
        packet.extend_from_slice(&[7]);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[3]);
        packet.extend_from_slice(b"com");
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        let config: Config = toml::from_str("[routing]\ndefault = 'direct'\n[[routing.rules]]\ndomain_suffix = ['example.com']\naction = 'reject'\n[[upstreams]]\nname='direct'\nhost='127.0.0.1'\nport=53\nprotocol='udp'").unwrap();
        assert_eq!(packet::query_name(&packet).as_deref(), Some("example.com"));
        assert!(config.target("www.example.com").unwrap().is_none());
    }
}
