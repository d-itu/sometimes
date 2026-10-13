use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rama::{
    http::{
        Body, HeaderValue, Method, Request, Version,
        core::client::conn::http2,
        io::upgrade::{Upgraded, handle_upgrade},
    },
    net::{address::Authority, uri::Uri},
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
use tokio::task::JoinHandle;

use crate::{
    config::Upstream,
    dns::{self, bootstrap::Resolver},
    outbound::connect_outbound,
};

pub struct Client {
    upstream: Upstream,
    outbound_mark: Option<u32>,
    tls: TlsConnector,
    authorization: HeaderValue,
    server_name: ServerName<'static>,
    resolver: Arc<Resolver>,
}

/// Owns the H2 driver so cancellation cannot leak background connections.
pub struct Tunnel {
    pub stream: Upgraded,
    pub padded: bool,
    driver: JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

struct Driver(Option<JoinHandle<()>>);
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
            upstream,
            outbound_mark,
            tls: TlsConnector::from(Arc::new(tls)),
            authorization,
            server_name,
            resolver,
        })
    }

    pub async fn connect(&self, destination: impl Into<Authority>) -> Result<Tunnel> {
        let addresses = self
            .resolver
            .resolve_host(&self.upstream.host, self.upstream.port)
            .await
            .context("resolve upstream hostname")?;
        self.connect_addresses(addresses, destination.into()).await
    }

    async fn connect_addresses(
        &self,
        addresses: impl IntoIterator<Item = SocketAddr>,
        destination: Authority,
    ) -> Result<Tunnel> {
        let mut last_error = None;
        for address in addresses {
            match connect_outbound(address, self.outbound_mark).await {
                Ok(tcp) => match self
                    .handshake(TcpStream::new(tcp), destination.clone())
                    .await
                {
                    Ok(tunnel) => return Ok(tunnel),
                    Err(error) => last_error = Some(error.context(format!("upstream {address}"))),
                },
                Err(error) => last_error = Some(error.into()),
            }
        }
        match last_error {
            Some(error) => Err(error).context("connect to upstream addresses"),
            None => anyhow::bail!("upstream hostname resolved to no addresses"),
        }
    }

    async fn handshake(&self, tcp: TcpStream, destination: Authority) -> Result<Tunnel> {
        let tls = self
            .tls
            .connect(self.server_name.clone(), tcp)
            .await
            .context("upstream TLS handshake")?;
        ensure!(
            tls.get_ref().1.alpn_protocol() == Some(b"h2"),
            "upstream did not negotiate h2"
        );
        connect_h2(
            TlsStream::new(tls),
            destination,
            self.authorization.clone(),
            self.upstream.require_padding,
        )
        .await
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
    let (mut sender, connection) = http2::Builder::new(Executor::new())
        .with_enable_push(false)
        .with_max_send_buf_size(64 * 1024)
        .handshake::<_, Body>(stream)
        .await
        .context("H2 handshake")?;
    let mut driver = Driver(Some(tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "upstream H2 connection closed");
        }
    })));

    // Characters from the long-code region of the HPACK Huffman table.
    let padding: String = (0..rand::random_range(16..=32))
        .map(|_| ['!', '"', '#', '$', '\''][rand::random_range(0..5)])
        .collect();
    let mut padding = HeaderValue::from_str(&padding)?;
    padding.set_sensitive(true);
    let request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(Uri::from_authority_form(destination.into()))
        .header("proxy-authorization", authorization)
        .header("padding", padding)
        .body(Body::empty())?;
    let response = sender
        .send_request(request)
        .await
        .context("CONNECT request")?;
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
        driver: driver.0.take().expect("driver exists until transfer"),
    })
}
