use std::{fs, net::SocketAddr, path::Path};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use crate::{routing::Routing, sniff::Sniff};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listeners: Vec<Listener>,
    pub upstream: Upstream,
    pub outbound_mark: Option<u32>,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub sniff: Sniff,
    #[serde(default)]
    pub routing: Routing,
    #[serde(default)]
    pub dns: crate::dns::Config,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InboundProtocol {
    Tproxy,
    Http,
    Socks,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub host: String,
    pub port: u16,
    pub protocol: InboundProtocol,
}

impl Listener {
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::new(
            self.host
                .parse()
                .context("listener host must be an IP address")?,
            self.port,
        ))
    }
}
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default)]
    pub level: LogLevel,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Hostname or IP without a port; IPv6 addresses are unbracketed.
    pub host: String,
    #[serde(default = "default_upstream_port")]
    pub port: u16,
    pub server_name: Option<String>,
    pub username: String,
    pub password: String,
    #[serde(default = "default_require_padding")]
    pub require_padding: bool,
}

impl Upstream {
    pub fn validate(&self) -> Result<()> {
        rama::tls::rustls::dep::rustls::pki_types::ServerName::try_from(self.host.as_str())
            .context("upstream host must be a hostname or unbracketed IP without a port")?;
        ensure!(self.port != 0, "upstream port must be nonzero");
        Ok(())
    }
}

const fn default_upstream_port() -> u16 {
    443
}

const fn default_max_connections() -> usize {
    256
}
const fn default_connect_timeout() -> u64 {
    15
}
const fn default_idle_timeout() -> u64 {
    300
}
const fn default_require_padding() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path).context("read configuration")?;
        // TOML diagnostics can echo the credential-bearing source line.
        let config: Self = toml::from_str(&source)
            .map_err(|_| anyhow::anyhow!("invalid TOML configuration or unknown/missing fields"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.listeners.is_empty(),
            "at least one listener is required"
        );
        for listener in &self.listeners {
            ensure!(listener.port != 0, "listener ports must be nonzero");
            listener.socket_addr()?;
        }
        ensure!(
            self.max_connections > 0 && self.max_connections <= 65_536,
            "max_connections must be in 1..=65536"
        );
        ensure!(
            self.connect_timeout_secs > 0 && self.idle_timeout_secs > 0,
            "timeouts must be positive"
        );
        self.dns.validate()?;
        self.sniff.validate()?;
        self.upstream.validate()?;
        ensure!(
            !self.upstream.username.contains(':'),
            "proxy username cannot contain a colon"
        );
        ensure!(
            self.outbound_mark != Some(0),
            "outbound_mark must be nonzero when configured"
        );
        ensure!(
            self.outbound_mark.is_some()
                || !self
                    .listeners
                    .iter()
                    .any(|listener| listener.protocol == InboundProtocol::Tproxy),
            "outbound_mark is required for tproxy listeners"
        );
        Ok(())
    }
}
