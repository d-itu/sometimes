use super::*;
use std::{convert::Infallible, net::SocketAddr};

use rama::{
    http::{
        Response,
        core::{body::Incoming, server::conn::http2 as server_h2},
    },
    net::address::{Domain, HostWithPort},
    service::service_fn,
    tls::rustls::{
        dep::{
            rustls::{RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer},
            tokio_rustls::TlsAcceptor,
        },
        server::TlsStream as ServerTlsStream,
    },
};
use tokio::{
    net::TcpListener,
    time::{Duration, timeout},
};

async fn tls_case(trusted: bool, hostname: &str, h2: bool) -> Result<Tunnel> {
    tls_case_with_override(trusted, hostname, h2, true).await
}

async fn tls_case_with_override(
    trusted: bool,
    hostname: &str,
    h2: bool,
    override_name: bool,
) -> Result<Tunnel> {
    let certified = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
    if h2 {
        server_config.alpn_protocols = vec![b"h2".to_vec()];
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let Ok(tls) = TlsAcceptor::from(Arc::new(server_config))
            .accept(TcpStream::new(stream))
            .await
        else {
            return;
        };
        let _ = server_h2::Builder::new(Executor::new())
            .serve_connection(
                ServerTlsStream::new(tls),
                service_fn(|request: Request<Incoming>| async move {
                    assert_eq!(
                        request.headers()["proxy-authorization"],
                        "Basic dXNlcjpwYXNz"
                    );
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("padding", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                            .body(Body::empty())
                            .unwrap(),
                    )
                }),
            )
            .await;
    });
    let upstream = Upstream {
        host: if override_name {
            address.ip().to_string()
        } else {
            hostname.into()
        },
        port: address.port(),
        server_name: override_name.then(|| hostname.into()),
        username: "user".into(),
        password: "pass".into(),
        require_padding: true,
    };
    let mut client = Client::new(upstream, None).unwrap();
    if trusted {
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        client.tls = TlsConnector::from(Arc::new(tls));
    }
    let stream = TcpStream::new(tokio::net::TcpStream::connect(address).await.unwrap());
    let result = client
        .handshake(
            stream,
            "192.0.2.1:443".parse::<SocketAddr>().unwrap().into(),
        )
        .await;
    server.abort();
    result
}

#[tokio::test]
async fn retries_next_address_after_tls_failure() {
    timeout(Duration::from_secs(5), async {
        let certified = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key.into())
                .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let broken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let broken_address = broken.local_addr().unwrap();
        let good = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_address = good.local_addr().unwrap();
        let bad_server = tokio::spawn(async move {
            let (socket, _) = broken.accept().await.unwrap();
            drop(socket);
        });
        let good_server = tokio::spawn(async move {
            let (socket, _) = good.accept().await.unwrap();
            let tls = TlsAcceptor::from(Arc::new(server_config))
                .accept(TcpStream::new(socket))
                .await
                .unwrap();
            let _ = server_h2::Builder::new(Executor::new())
                .serve_connection(
                    ServerTlsStream::new(tls),
                    service_fn(|request: Request<Incoming>| async move {
                        assert_eq!(
                            request.uri().authority().unwrap().to_string(),
                            "example.com:443"
                        );
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    }),
                )
                .await;
        });
        let upstream = Upstream {
            host: "127.0.0.1".into(),
            port: good_address.port(),
            server_name: Some("proxy.test".into()),
            username: "user".into(),
            password: "pass".into(),
            require_padding: false,
        };
        let mut client = Client::new(upstream, None).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        client.tls = TlsConnector::from(Arc::new(tls));
        let destination = HostWithPort::new(Domain::try_from("example.com").unwrap().into(), 443);
        let tunnel = client
            .connect_addresses([broken_address, good_address], destination.into())
            .await
            .unwrap();
        drop(tunnel);
        bad_server.await.unwrap();
        good_server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connect_h2_preserves_domain_authority() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = server_h2::Builder::new(Executor::new())
            .serve_connection(
                TcpStream::new(socket),
                service_fn(|request: Request<Incoming>| async move {
                    assert_eq!(
                        request.uri().authority().unwrap().to_string(),
                        "www.google.com:443"
                    );
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                }),
            )
            .await;
    });
    let target = HostWithPort::new(Domain::try_from("www.google.com").unwrap().into(), 443);
    let tunnel = timeout(
        Duration::from_secs(3),
        connect_h2(
            TcpStream::new(tokio::net::TcpStream::connect(address).await.unwrap()),
            target,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
            false,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    drop(tunnel);
    server.await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated Linux network namespace and nftables rules"]
async fn proxy_route_replays_http_without_looping() {
    use crate::{
        config::Config,
        linux::{handle_flow, listen},
        naive::padding,
    };
    use std::process::Command;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    timeout(Duration::from_secs(5), async {
        let certified = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let mut tls = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let port = address.port().to_string();
        assert!(
            Command::new("nft")
                .args([
                    "insert",
                    "rule",
                    "inet",
                    "sometimes",
                    "output",
                    "ip",
                    "daddr",
                    "127.0.0.1",
                    "tcp",
                    "dport",
                    &port,
                    "meta",
                    "mark",
                    "!=",
                    "0x534f",
                    "meta",
                    "mark",
                    "set",
                    "0x5354",
                    "return",
                ])
                .status()
                .unwrap()
                .success()
        );
        let request_bytes = b"GET / HTTP/1.1\r\nHost: proxied.example\r\n\r\nbody";
        let server = tokio::spawn(async move {
            let (tcp, _) = upstream.accept().await.unwrap();
            let tls = TlsAcceptor::from(Arc::new(tls))
                .accept(TcpStream::new(tcp))
                .await
                .unwrap();
            server_h2::Builder::new(Executor::new())
                .serve_connection(
                    ServerTlsStream::new(tls),
                    service_fn(move |request: Request<Incoming>| async move {
                        assert_eq!(
                            request.uri().authority().unwrap().to_string(),
                            "198.18.0.1:80"
                        );
                        assert_eq!(
                            request.headers()["proxy-authorization"],
                            "Basic dXNlcjpwYXNz"
                        );
                        tokio::spawn(async move {
                            let mut stream = handle_upgrade(&request).await.unwrap();
                            let mut received = Vec::new();
                            padding::decode(&mut stream, &mut received, true)
                                .await
                                .unwrap();
                            assert_eq!(received, request_bytes);
                            padding::encode(&mut b"reply".as_slice(), &mut stream, true)
                                .await
                                .unwrap();
                        });
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("padding", "!!!")
                                .body(Body::empty())
                                .unwrap(),
                        )
                    }),
                )
                .await
                .unwrap();
        });
        let mut config: Config = toml::from_str(
            r#"
            listeners = [{ host = "0.0.0.0", port = 12345, protocol = "tproxy" }]
            outbound_mark = 21327
            [upstream]
            host = "127.0.0.1"
            server_name = "proxy.test"
            username = "user"
            password = "pass"
            [routing]
            default = "reject"
            [[routing.rules]]
            domain = ["proxied.example"]
            action = "proxy"
        "#,
        )
        .unwrap();
        config.upstream.port = address.port();
        config.routing.prepare().unwrap();
        let mut client = Client::new(config.upstream.clone(), config.outbound_mark).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        client.tls = TlsConnector::from(Arc::new(tls));
        let listener = listen("0.0.0.0:12345".parse().unwrap(), true).unwrap();
        let app = tokio::spawn(async move {
            let mut tcp = tokio::net::TcpStream::connect("198.18.0.1:80")
                .await
                .unwrap();
            tcp.write_all(request_bytes).await.unwrap();
            tcp.shutdown().await.unwrap();
            let mut reply = Vec::new();
            tcp.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply");
        });
        let (stream, _) = listener.accept().await.unwrap();
        let destination = stream.local_addr().unwrap();
        tokio::select! {
            result = handle_flow(stream, destination, &config, &client) => {
                assert_eq!(result.unwrap(), (request_bytes.len() as u64, 5));
            }
            _ = listener.accept() => panic!("upstream connection looped into TPROXY"),
        }
        app.await.unwrap();
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn hostname_without_override_verifies_tls_identity() {
    assert!(
        timeout(
            Duration::from_secs(5),
            tls_case_with_override(true, "proxy.test", true, false)
        )
        .await
        .unwrap()
        .is_ok()
    );
    assert!(
        timeout(
            Duration::from_secs(5),
            tls_case_with_override(true, "wrong.test", true, false)
        )
        .await
        .unwrap()
        .is_err()
    );
}

#[tokio::test]
async fn tls_h2_connect_with_trusted_certificate() {
    let tunnel = timeout(Duration::from_secs(5), tls_case(true, "proxy.test", true))
        .await
        .unwrap()
        .unwrap();
    assert!(tunnel.padded);
}

#[tokio::test]
async fn rejects_untrusted_certificate() {
    assert!(
        timeout(Duration::from_secs(5), tls_case(false, "proxy.test", true))
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn rejects_wrong_hostname() {
    assert!(
        timeout(Duration::from_secs(5), tls_case(true, "wrong.test", true))
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn requires_h2_alpn() {
    let error = timeout(Duration::from_secs(5), tls_case(true, "proxy.test", false))
        .await
        .unwrap()
        .err()
        .unwrap();
    assert!(error.to_string().contains("negotiate h2"));
}
