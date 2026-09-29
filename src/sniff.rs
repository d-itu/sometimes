use std::{io, str, time::Duration};

use anyhow::{Result, ensure};
use rama::{
    io::{HeapReader, PrefixedIo},
    net::address::HostWithOptPort,
    tls::client::parse_client_hello,
};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout,
};

use crate::routing::normalize_domain;

#[cfg(test)]
mod tests;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sniff {
    pub enabled: bool,
    pub timeout_ms: u64,
    pub max_bytes: usize,
}

impl Default for Sniff {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_ms: 500,
            max_bytes: 16384,
        }
    }
}

impl Sniff {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.timeout_ms > 0, "sniff timeout_ms must be positive");
        ensure!(
            (1..=65536).contains(&self.max_bytes),
            "sniff max_bytes must be in 1..=65536"
        );
        Ok(())
    }
}

/// Replays consumed bytes before reading the socket; writes go straight through.
pub type Replay<S> = PrefixedIo<HeapReader, S>;

enum Probe {
    More,
    Done(Option<String>),
}

fn probe(bytes: &[u8]) -> Probe {
    if bytes.is_empty() {
        return Probe::More;
    }
    if bytes[0] == 22 {
        return tls(bytes);
    }
    // Stop early on protocols that cannot start an HTTP/1 request.
    if !bytes[0].is_ascii_uppercase() {
        return Probe::Done(None);
    }
    let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        if let Some(end) = bytes.windows(2).position(|w| w == b"\r\n")
            && !bytes[..end].ends_with(b" HTTP/1.1")
            && !bytes[..end].ends_with(b" HTTP/1.0")
        {
            return Probe::Done(None);
        }
        return Probe::More;
    };
    let Ok(header) = str::from_utf8(&bytes[..end]) else {
        return Probe::Done(None);
    };
    let mut lines = header.split("\r\n");
    let request = lines.next().unwrap_or_default();
    let parts: Vec<_> = request.split(' ').collect();
    if parts.len() != 3 || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1") {
        return Probe::Done(None);
    }
    let mut host = None;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            return Probe::Done(None);
        };
        if key.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Probe::Done(None);
            }
            let Ok(authority) = value.trim().parse::<HostWithOptPort>() else {
                return Probe::Done(None);
            };
            if authority.host.try_as_ip().is_ok() {
                return Probe::Done(None);
            }
            host = normalize_domain(&authority.host.to_string());
            if host.is_none() {
                return Probe::Done(None);
            }
        }
    }
    Probe::Done(host)
}

fn tls(bytes: &[u8]) -> Probe {
    let mut rest = bytes;
    let mut handshake = Vec::new();
    loop {
        if rest.len() < 5 {
            return Probe::More;
        }
        if rest[0] != 22 || rest[1] != 3 || rest[2] > 4 {
            return Probe::Done(None);
        }
        let size = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        if size == 0 || size > 16384 {
            return Probe::Done(None);
        }
        if rest.len() < 5 + size {
            return Probe::More;
        }
        handshake.extend_from_slice(&rest[5..5 + size]);
        rest = &rest[5 + size..];
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return Probe::Done(None);
            }
            let size = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            if handshake.len() >= 4 + size {
                return Probe::Done(parse_client_hello(&handshake[4..4 + size]).ok().and_then(
                    |hello| {
                        hello
                            .ext_server_name()
                            .and_then(|name| normalize_domain(name.as_str()))
                    },
                ));
            }
        }
    }
}

pub async fn inspect<S: AsyncRead + Unpin>(
    mut stream: S,
    config: &Sniff,
) -> io::Result<(Replay<S>, Option<String>)> {
    let mut prefix = Vec::new();
    let domain = if config.enabled {
        timeout(Duration::from_millis(config.timeout_ms), async {
            loop {
                match probe(&prefix) {
                    Probe::Done(domain) => return Ok::<_, io::Error>(domain),
                    Probe::More => {}
                }
                let remaining = config.max_bytes - prefix.len();
                if remaining == 0 {
                    return Ok(None);
                }
                let mut buffer = [0; 2048];
                let limit = remaining.min(buffer.len());
                let size = stream.read(&mut buffer[..limit]).await?;
                if size == 0 {
                    return Ok(None);
                }
                prefix.extend_from_slice(&buffer[..size]);
            }
        })
        .await
        .unwrap_or(Ok(None))?
    } else {
        None
    };
    Ok((PrefixedIo::new(HeapReader::from(prefix), stream), domain))
}
