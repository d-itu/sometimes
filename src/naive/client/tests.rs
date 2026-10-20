use super::*;
use std::{convert::Infallible, future::poll_fn, net::SocketAddr};

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
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Notify, mpsc, oneshot},
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
    retry_next_address(FirstAddress::Close, false).await;
}

#[tokio::test]
async fn retries_next_address_after_connect_rejection() {
    retry_next_address(FirstAddress::Reject, false).await;
}

#[tokio::test]
async fn connect_rejection_with_zero_capacity_session_still_tries_next_address() {
    retry_next_address_with_zero_capacity(FirstAddress::Reject, false, true).await;
}

#[tokio::test]
async fn address_retry_retires_idle_session_when_pool_is_full() {
    retry_next_address(FirstAddress::Reject, true).await;
}

#[tokio::test]
async fn retries_next_address_after_tls_timeout() {
    retry_next_address(FirstAddress::StallTls, false).await;
}

#[tokio::test]
async fn retries_next_address_after_initial_settings_timeout() {
    retry_next_address(FirstAddress::StallSettings, false).await;
}

#[tokio::test]
async fn settings_timeout_releases_slot_for_retry_when_pool_is_full() {
    retry_next_address(FirstAddress::StallSettings, true).await;
}

enum FirstAddress {
    Close,
    Reject,
    StallTls,
    StallSettings,
}

async fn retry_next_address(first: FirstAddress, full_pool: bool) {
    retry_next_address_with_zero_capacity(first, full_pool, false).await;
}

async fn retry_next_address_with_zero_capacity(
    first: FirstAddress,
    full_pool: bool,
    zero_capacity: bool,
) {
    timeout(Duration::from_secs(5), async {
        let reject_connect = matches!(first, FirstAddress::Reject);
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
        let bad_config = server_config.clone();
        let bad_server = tokio::spawn(async move {
            let (mut socket, _) = broken.accept().await.unwrap();
            if matches!(first, FirstAddress::StallTls) {
                let _ = socket.read_to_end(&mut Vec::new()).await;
                return;
            }
            if matches!(first, FirstAddress::StallSettings) {
                let mut tls = TlsAcceptor::from(Arc::new(bad_config))
                    .accept(TcpStream::new(socket))
                    .await
                    .unwrap();
                let _ = tls.read_to_end(&mut Vec::new()).await;
                return;
            }
            if reject_connect {
                let tls = TlsAcceptor::from(Arc::new(bad_config))
                    .accept(TcpStream::new(socket))
                    .await
                    .unwrap();
                let _ = server_h2::Builder::new(Executor::new())
                    .serve_connection(
                        ServerTlsStream::new(tls),
                        service_fn(|request: Request<Incoming>| async move {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(
                                        if request.uri().authority().unwrap().to_string()
                                            == "example.com:443"
                                        {
                                            503
                                        } else {
                                            200
                                        },
                                    )
                                    .body(Body::empty())
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            }
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
        let reserved: Vec<_> = (0..if full_pool {
            PoolPolicy::CONNECTIONS - 1
        } else {
            0
        })
            .map(|_| client.slots.clone().try_acquire_owned().unwrap())
            .collect();
        let zero_session = if zero_capacity {
            let (session, server) = pooled_test_session(&client, 0).await;
            assert_eq!(session.max_streams.get(), 0);
            client.publish_session(session.clone()).await;
            Some((session, server))
        } else {
            None
        };
        let destination = HostWithPort::new(Domain::try_from("example.com").unwrap().into(), 443);
        let tunnel = ConnectRequest::new(&client, destination.into())
            .addresses(
                [broken_address, good_address],
                Slot {
                    permit: Some(client.slots.clone().try_acquire_owned().unwrap()),
                    changed: client.changed.clone(),
                },
            )
            .await
            .unwrap();
        let connections =
            if reject_connect && !full_pool { 2 } else { 1 } + usize::from(zero_capacity);
        assert_eq!(client.sessions.lock().await.len(), connections);
        assert_eq!(
            client.slots.available_permits(),
            PoolPolicy::CONNECTIONS - connections - reserved.len()
        );
        if reject_connect && !full_pool {
            let other = client
                .connect(HostWithPort::new(
                    Domain::try_from("other.example").unwrap().into(),
                    443,
                ))
                .await
                .unwrap();
            assert!(Arc::ptr_eq(
                &other._session,
                &client.sessions.lock().await[usize::from(zero_capacity)]
            ));
            drop(other);
        }
        drop(tunnel);
        if let Some((session, _)) = &zero_session {
            assert!(session.usable());
            assert_eq!(session.active(), 0);
            assert_eq!(session.max_streams.get(), 0);
        }
        drop(client);
        if let Some((session, server)) = zero_session {
            drop(session);
            server.await.unwrap();
        }
        bad_server.await.unwrap();
        good_server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn publishes_session_before_first_connect_completes() {
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests, mut received) = mpsc::unbounded_channel();
        let release = Arc::new(Notify::new());
        let server_release = release.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(Arc::new(server_config))
                .accept(TcpStream::new(socket))
                .await
                .unwrap();
            let _ = server_h2::Builder::new(Executor::new())
                .serve_connection(
                    ServerTlsStream::new(tls),
                    service_fn(move |request: Request<Incoming>| {
                        let requests = requests.clone();
                        let release = server_release.clone();
                        async move {
                            let slow = request.uri().authority().unwrap().to_string()
                                == "slow.example:443";
                            requests.send(slow).unwrap();
                            if slow {
                                release.notified().await;
                            }
                            Ok::<_, Infallible>(Response::new(Body::empty()))
                        }
                    }),
                )
                .await;
        });
        let upstream = Upstream {
            host: address.ip().to_string(),
            port: address.port(),
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
        let client = Arc::new(client);
        let first_client = client.clone();
        let first = tokio::spawn(async move {
            first_client
                .connect(HostWithPort::new(
                    Domain::try_from("slow.example").unwrap().into(),
                    443,
                ))
                .await
        });
        assert!(received.recv().await.unwrap());
        let second = client
            .connect(HostWithPort::new(
                Domain::try_from("fast.example").unwrap().into(),
                443,
            ))
            .await
            .unwrap();
        assert!(!received.recv().await.unwrap());
        assert_eq!(client.sessions.lock().await.len(), 1);
        assert_eq!(client.slots.available_permits(), 3);
        first.abort();
        assert!(matches!(first.await, Err(error) if error.is_cancelled()));
        release.notify_one();
        let third = client
            .connect(HostWithPort::new(
                Domain::try_from("later.example").unwrap().into(),
                443,
            ))
            .await
            .unwrap();
        assert!(!received.recv().await.unwrap());
        assert_eq!(client.sessions.lock().await.len(), 1);
        assert_eq!(client.slots.available_permits(), 3);
        drop(third);
        drop(second);
        drop(client);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn full_session_does_not_block_replacement() {
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(Arc::new(server_config))
                .accept(TcpStream::new(socket))
                .await
                .unwrap();
            let _ = server_h2::Builder::new(Executor::new())
                .serve_connection(
                    ServerTlsStream::new(tls),
                    service_fn(|_: Request<Incoming>| async {
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    }),
                )
                .await;
        });
        let upstream = Upstream {
            host: address.ip().to_string(),
            port: address.port(),
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

        let old_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_address = old_listener.local_addr().unwrap();
        let old_server = tokio::spawn(async move {
            let (socket, _) = old_listener.accept().await.unwrap();
            let _ = server_h2::Builder::new(Executor::new())
                .serve_connection(
                    TcpStream::new(socket),
                    service_fn(|_: Request<Incoming>| async {
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    }),
                )
                .await;
        });
        let old = Session::handshake(
            TcpStream::new(tokio::net::TcpStream::connect(old_address).await.unwrap()),
            client.changed.clone(),
        )
        .await
        .unwrap();
        let mut permits = Vec::new();
        for _ in 0..64 {
            permits.push(old.streams.clone().acquire_owned().await.unwrap());
        }
        client.sessions.lock().await.push(old.clone());
        let destination: Authority =
            HostWithPort::new(Domain::try_from("example.com").unwrap().into(), 443).into();
        let tunnel = client.connect(destination).await.unwrap();
        drop(tunnel);
        drop(permits);
        drop(old);
        drop(client);
        server.await.unwrap();
        old_server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reuses_session_and_obeys_peer_stream_limit() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests, mut received) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = server_h2::Builder::new(Executor::new())
                .with_max_concurrent_streams(1)
                .serve_connection(
                    TcpStream::new(socket),
                    service_fn(move |request: Request<Incoming>| {
                        let requests = requests.clone();
                        async move {
                            let _ = requests.send(());
                            tokio::spawn(async move {
                                let _tunnel = handle_upgrade(&request).await.unwrap();
                                std::future::pending::<()>().await;
                            });
                            Ok::<_, Infallible>(Response::new(Body::empty()))
                        }
                    }),
                )
                .await;
        });
        let upstream = Upstream {
            host: "127.0.0.1".into(),
            port: address.port(),
            server_name: None,
            username: "user".into(),
            password: "pass".into(),
            require_padding: false,
        };
        let client = Client::new(upstream, None).unwrap();
        let session = Session::handshake_reserved(
            TcpStream::new(tokio::net::TcpStream::connect(address).await.unwrap()),
            client.changed.clone(),
            Some(address),
            Some(Slot {
                permit: Some(client.slots.clone().try_acquire_owned().unwrap()),
                changed: client.changed.clone(),
            }),
        )
        .await
        .unwrap();
        client.sessions.lock().await.push(session.clone());
        let destination: Authority =
            HostWithPort::new(Domain::try_from("example.com").unwrap().into(), 443).into();
        let first = client.connect(destination.clone()).await.unwrap();
        received.recv().await.unwrap();
        assert_eq!(session.max_streams.get(), 1);
        assert!(session.try_acquire().is_none());
        drop(first);
        let second = client.connect(destination).await.unwrap();
        received.recv().await.unwrap();
        assert_eq!(client.sessions.lock().await.len(), 1);
        drop(second);
        drop(client);
        drop(session);
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn initial_zero_stream_limit_recovers_after_settings_increase() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (resume, updated) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut preface = [0; 24];
            socket.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            // SETTINGS_MAX_CONCURRENT_STREAMS: zero initially, then one.
            socket
                .write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0])
                .await
                .unwrap();
            updated.await.unwrap();
            socket
                .write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1])
                .await
                .unwrap();
            loop {
                let mut header = [0; 9];
                socket.read_exact(&mut header).await.unwrap();
                let len = usize::from(header[0]) << 16
                    | usize::from(header[1]) << 8
                    | usize::from(header[2]);
                let mut payload = vec![0; len];
                socket.read_exact(&mut payload).await.unwrap();
                if header[3] == 1 {
                    assert_eq!(&header[5..], &[0, 0, 0, 1]);
                    // HEADERS on stream 1 with an indexed :status 200.
                    socket
                        .write_all(&[0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88])
                        .await
                        .unwrap();
                    break;
                }
            }
        });
        let session = Session::handshake(
            TcpStream::new(tokio::net::TcpStream::connect(address).await.unwrap()),
            Arc::new(Notify::new()),
        )
        .await
        .unwrap();
        assert!(session.try_acquire().is_none());
        let connect = tokio::spawn({
            let session = session.clone();
            async move {
                let permit = session.acquire().await.unwrap();
                session
                    .connect(
                        HostWithPort::new(Domain::try_from("example.com").unwrap().into(), 443)
                            .into(),
                        HeaderValue::from_static("Basic dXNlcjpwYXNz"),
                        false,
                        permit,
                    )
                    .await
            }
        });
        resume.send(()).unwrap();
        let tunnel = connect.await.unwrap().unwrap();
        drop(tunnel);
        drop(session);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamic_settings_control_admission_and_wake_waiters() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (updates, mut commands) = mpsc::unbounded_channel::<u32>();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut preface = [0; 24];
            socket.read_exact(&mut preface).await.unwrap();
            // Keep reading to let the client flush its SETTINGS and ACK frames.
            let (mut read, mut write) = socket.into_split();
            let reader = tokio::spawn(async move {
                let mut buffer = [0; 1024];
                while read.read(&mut buffer).await.unwrap_or(0) != 0 {}
            });
            while let Some(limit) = commands.recv().await {
                let mut frame = vec![0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3];
                frame.extend_from_slice(&limit.to_be_bytes());
                write.write_all(&frame).await.unwrap();
            }
            reader.abort();
        });
        updates.send(0).unwrap();
        let session = Session::handshake(
            TcpStream::new(tokio::net::TcpStream::connect(address).await.unwrap()),
            Arc::new(Notify::new()),
        )
        .await
        .unwrap();
        assert!(session.try_acquire().is_none());
        let first = session.acquire();
        tokio::pin!(first);
        assert!(
            timeout(Duration::from_millis(20), &mut first)
                .await
                .is_err()
        );
        updates.send(1).unwrap();
        let first = first.await.unwrap();
        assert!(session.try_acquire().is_none());

        updates.send(64).unwrap();
        wait_for_limit(&session, 64).await;
        let others: Vec<_> = (1..64).map(|_| session.try_acquire().unwrap()).collect();
        assert!(session.try_acquire().is_none());

        updates.send(0).unwrap();
        wait_for_limit(&session, 0).await;
        drop(others);
        drop(first);
        assert!(session.try_acquire().is_none());
        let mut canceled = tokio::spawn({
            let session = session.clone();
            async move { session.acquire().await }
        });
        assert!(
            timeout(Duration::from_millis(20), &mut canceled)
                .await
                .is_err()
        );
        canceled.abort();
        assert!(matches!(canceled.await, Err(error) if error.is_cancelled()));
        assert_eq!(session.active(), 0);

        let resumed = session.acquire();
        tokio::pin!(resumed);
        assert!(
            timeout(Duration::from_millis(20), &mut resumed)
                .await
                .is_err()
        );
        updates.send(1).unwrap();
        drop(resumed.await.unwrap());
        drop(updates);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

async fn wait_for_limit(session: &Session, limit: usize) {
    loop {
        let notified = session.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if session.max_streams.get() == limit {
            return;
        }
        notified.await;
    }
}

#[tokio::test]
async fn concurrent_connection_attempts_are_bounded_and_cancel_safe() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted, mut incoming) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut sockets = Vec::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                sockets.push(socket);
                accepted.send(()).unwrap();
            }
        });
        let client = Arc::new(
            Client::new(
                Upstream {
                    host: address.ip().to_string(),
                    port: address.port(),
                    server_name: None,
                    username: "user".into(),
                    password: "pass".into(),
                    require_padding: false,
                },
                None,
            )
            .unwrap(),
        );
        let spawn_connect = || {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .connect(HostWithPort::new(
                        Domain::try_from("example.com").unwrap().into(),
                        443,
                    ))
                    .await
            })
        };
        let mut attempts: Vec<_> = (0..PoolPolicy::CONNECTIONS)
            .map(|_| spawn_connect())
            .collect();
        for _ in 0..PoolPolicy::CONNECTIONS {
            incoming.recv().await.unwrap();
        }
        assert_eq!(client.slots.available_permits(), 0);
        let mut waiting = spawn_connect();
        assert!(
            timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        assert!(incoming.try_recv().is_err());
        let canceled = attempts.pop().unwrap();
        canceled.abort();
        assert!(matches!(canceled.await, Err(error) if error.is_cancelled()));
        incoming.recv().await.unwrap();
        assert_eq!(client.slots.available_permits(), 0);
        attempts.push(waiting);
        for attempt in attempts {
            attempt.abort();
            assert!(matches!(attempt.await, Err(error) if error.is_cancelled()));
        }
        assert_eq!(client.slots.available_permits(), PoolPolicy::CONNECTIONS);
        assert_eq!(client.pending.available_permits(), PoolPolicy::PENDING);
        assert!(client.sessions.lock().await.is_empty());
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stream_reset_is_isolated_and_goaway_stops_admission() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (goaway, send_goaway) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut preface = [0; 24];
            socket.read_exact(&mut preface).await.unwrap();
            socket
                .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut requests = 0;
            while requests < 2 {
                let mut header = [0; 9];
                socket.read_exact(&mut header).await.unwrap();
                let len = usize::from(header[0]) << 16
                    | usize::from(header[1]) << 8
                    | usize::from(header[2]);
                let mut payload = vec![0; len];
                socket.read_exact(&mut payload).await.unwrap();
                if header[3] != 1 {
                    continue;
                }
                requests += 1;
                if requests == 1 {
                    // RST_STREAM(CANCEL) for stream 1.
                    socket
                        .write_all(&[0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8])
                        .await
                        .unwrap();
                } else {
                    // Successful CONNECT on stream 3, kept open across GOAWAY.
                    socket
                        .write_all(&[0, 0, 1, 1, 4, 0, 0, 0, 3, 0x88])
                        .await
                        .unwrap();
                }
            }
            send_goaway.await.unwrap();
            socket
                .write_all(&[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0])
                .await
                .unwrap();
            released.await.unwrap();
        });
        let session = Session::handshake(
            TcpStream::new(tokio::net::TcpStream::connect(address).await.unwrap()),
            Arc::new(Notify::new()),
        )
        .await
        .unwrap();
        let destination: Authority =
            HostWithPort::new(Domain::try_from("example.com").unwrap().into(), 443).into();
        let failed = session
            .clone()
            .connect(
                destination.clone(),
                HeaderValue::from_static("Basic dXNlcjpwYXNz"),
                false,
                session.acquire().await.unwrap(),
            )
            .await;
        assert!(failed.is_err());
        assert!(session.usable());
        assert_eq!(session.active(), 0);
        let tunnel = session
            .clone()
            .connect(
                destination,
                HeaderValue::from_static("Basic dXNlcjpwYXNz"),
                false,
                session.acquire().await.unwrap(),
            )
            .await
            .unwrap();
        goaway.send(()).unwrap();
        loop {
            let notified = session.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !session.usable() {
                break;
            }
            notified.await;
        }
        assert!(session.try_acquire().is_none());
        assert!(session.acquire().await.is_err());
        assert_eq!(session.active(), 1);
        drop(tunnel);
        assert_eq!(session.active(), 0);
        release.send(()).unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn zero_capacity_session_waiter_reuses_other_session() {
    timeout(Duration::from_secs(5), async {
        let client = test_pool();
        let (busy, busy_server) = pooled_test_session(&client, 1).await;
        let occupied = busy.try_acquire().unwrap();
        client.sessions.lock().await.push(busy.clone());
        let (zero, zero_server) = pooled_test_session(&client, 0).await;
        client.publish_session(zero.clone()).await;
        let request = ConnectRequest::new(&client, "example.com:443".parse().unwrap());
        let mut waiting = Box::pin(request.stream());
        assert!(
            timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        assert_eq!(client.sessions.lock().await.len(), 2);
        drop(occupied);
        let (assigned, permit) = waiting.await.unwrap();
        assert!(Arc::ptr_eq(&assigned, &busy));
        assert_eq!(zero.max_streams.get(), 0);
        assert_eq!(zero.active(), 0);
        drop(permit);
        drop(assigned);
        drop(request);
        drop(busy);
        drop(zero);
        drop(client);
        busy_server.await.unwrap();
        zero_server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn address_retry_waits_for_zero_capacity_without_reusing_rejected_sessions() {
    retry_published_session(true, true, false).await;
}

#[tokio::test]
async fn last_address_tries_published_session_after_pooled_sessions_reject() {
    retry_published_session(false, true, false).await;
}

#[tokio::test]
async fn connect_rejection_preserves_upstream_address_context() {
    retry_published_session(false, false, false).await;
}

#[tokio::test]
async fn last_address_failure_waits_for_published_zero_capacity_session() {
    retry_published_session(true, true, true).await;
}

#[tokio::test]
async fn reused_session_error_uses_its_address_after_last_address_failure() {
    retry_published_session(true, false, true).await;
}

async fn retry_published_session(prefailed: bool, succeeds: bool, last_fails: bool) {
    timeout(Duration::from_secs(5), async {
        let (tls, acceptor) = test_tls_configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let failing_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let failing_address = failing_listener.local_addr().unwrap();
        let failing_server = tokio::spawn(async move {
            if last_fails {
                let (socket, _) = failing_listener.accept().await.unwrap();
                drop(socket);
            }
        });
        let (resume, resumed) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(TcpStream::new(socket)).await.unwrap();
            let mut preface = [0; 24];
            stream.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            // Admit no streams until the request has started waiting on the pool.
            stream.write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0]).await.unwrap();
            resumed.await.unwrap();
            stream.write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1]).await.unwrap();
            loop {
                let mut header = [0; 9];
                stream.read_exact(&mut header).await.unwrap();
                let len = usize::from(header[0]) << 16
                    | usize::from(header[1]) << 8
                    | usize::from(header[2]);
                stream.read_exact(&mut vec![0; len]).await.unwrap();
                if header[3] == 1 {
                    // Indexed :status 200 or 500 on the first CONNECT.
                    let status = if succeeds { 0x88 } else { 0x8e };
                    stream.write_all(&[0, 0, 1, 1, 4, 0, 0, 0, 1, status]).await.unwrap();
                    break;
                }
            }
        });
        let mut client = test_pool();
        client.server_name = ServerName::try_from("proxy.test").unwrap();
        client.tls = tls;
        let (first, first_server) = pooled_test_session_with_status(&client, 1, 503).await;
        let (second, second_server) = pooled_test_session_with_status(&client, 1, 503).await;
        client.publish_session(first.clone()).await;
        client.publish_session(second.clone()).await;
        let mut request = ConnectRequest::new(&client, "example.com:443".parse().unwrap());
        if prefailed {
            for session in [&first, &second] {
                assert!(request.send(session.clone(), session.try_acquire().unwrap()).await.is_err());
                assert!(session.usable());
            }
            // No eligible session remains for this request, but another request can use them.
            assert!(request.stream().await.is_err());
            let other = ConnectRequest::new(&client, "other.example:443".parse().unwrap());
            let (selected, permit) = other.stream().await.unwrap();
            assert!(Arc::ptr_eq(&selected, &first));
            drop(permit);
            drop(selected);
            drop(other);
        }
        let busy = [first.try_acquire().unwrap(), second.try_acquire().unwrap()];
        let slot = Slot {
            permit: Some(client.slots.clone().try_acquire_owned().unwrap()),
            changed: client.changed.clone(),
        };
        let addresses = if last_fails {
            vec![address, failing_address]
        } else {
            vec![address]
        };
        let mut connecting = Box::pin(request.addresses(addresses, slot));
        // Drive establishment until the zero-capacity session is published.
        loop {
            let notified = client.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if client.sessions.lock().await.len() == 3 {
                break;
            }
            tokio::select! {
                result = &mut connecting => panic!("retry completed before capacity recovered: {}", result.is_ok()),
                _ = notified => {}
            }
        }
        drop(busy);
        assert!(timeout(Duration::from_millis(20), &mut connecting).await.is_err());
        // The last TLS attempt has failed while the earlier session is still at zero capacity.
        failing_server.await.unwrap();
        {
            let sessions = client.sessions.lock().await;
            assert_eq!(sessions.len(), 3);
            assert_eq!(sessions[2].max_streams.get(), 0);
            assert_eq!(first.active(), 0);
            assert_eq!(second.active(), 0);
        }
        resume.send(()).unwrap();
        match connecting.await {
            Ok(tunnel) => {
                assert!(succeeds);
                assert!(!Arc::ptr_eq(&tunnel._session, &first));
                assert!(!Arc::ptr_eq(&tunnel._session, &second));
            }
            Err(error) => {
                assert!(!succeeds);
                let message = format!("{error:#}");
                assert!(message.contains(&format!("upstream {address}")), "{message}");
                assert!(message.contains("upstream CONNECT rejected: 500"), "{message}");
                assert!(!message.contains(&format!("upstream {failing_address}")), "{message}");
            }
        }
        drop(first);
        drop(second);
        drop(client);
        server.await.unwrap();
        first_server.await.unwrap();
        second_server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn retry_waiting_for_connection_budget_reuses_released_stream() {
    timeout(Duration::from_secs(5), async {
        let client = test_pool();
        let (healthy, healthy_server) = pooled_test_session(&client, 1).await;
        let (failed, failed_server) = pooled_test_session_with_status(&client, 1, 503).await;
        client.publish_session(healthy.clone()).await;
        client.publish_session(failed.clone()).await;
        let reserved: Vec<_> = (0..PoolPolicy::CONNECTIONS - 2)
            .map(|_| client.slots.clone().try_acquire_owned().unwrap())
            .collect();
        let healthy_active = healthy.try_acquire().unwrap();
        let failed_active = failed.try_acquire().unwrap();
        let mut request = ConnectRequest::new(&client, "example.com:443".parse().unwrap());
        request.failed.push(Arc::downgrade(&failed));
        let mut waiting = Box::pin(request.assign(Allocation::Retry));
        assert!(
            timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        assert_eq!(client.slots.available_permits(), 0);
        drop(healthy_active);
        let Assignment::Stream(session, permit) = waiting.await else {
            panic!("retry must use released stream capacity")
        };
        assert!(Arc::ptr_eq(&session, &healthy));
        let tunnel = request.send(session, permit).await.unwrap();
        assert_eq!(client.slots.available_permits(), 0);
        assert!(!healthy.draining.load(Ordering::Relaxed));
        assert!(!failed.draining.load(Ordering::Relaxed));
        drop(tunnel);
        drop(failed_active);
        drop(reserved);
        drop(request);
        drop(healthy);
        drop(failed);
        drop(client);
        healthy_server.await.unwrap();
        failed_server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn transport_retains_stream_permit_until_dropped() {
    let client = test_pool();
    let (session, server) = pooled_test_session(&client, 64).await;
    let tunnel = session
        .clone()
        .connect(
            "example.com:443".parse().unwrap(),
            client.authorization.clone(),
            false,
            session.try_acquire().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.active(), 1);
    let owners = Arc::strong_count(&session);
    let transport = crate::inbound::tunnel_transport(tunnel, Duration::from_secs(60));
    assert_eq!(session.active(), 1);
    assert_eq!(Arc::strong_count(&session), owners);
    drop(transport);
    assert_eq!(session.active(), 0);
    assert_eq!(Arc::strong_count(&session), owners - 1);
    drop(session);
    server.await.unwrap();
}

#[tokio::test]
async fn last_tcp_failure_releases_unused_slot_before_waiting() {
    let client = test_pool();
    let (session, server) = pooled_test_session(&client, 0).await;
    client.publish_session(session.clone()).await;
    let other_slots: Vec<_> = (0..PoolPolicy::CONNECTIONS - 2)
        .map(|_| client.slots.clone().try_acquire_owned().unwrap())
        .collect();
    let slot = Slot {
        permit: Some(client.slots.clone().try_acquire_owned().unwrap()),
        changed: client.changed.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let request = ConnectRequest::new(&client, "example.com:443".parse().unwrap());
    let mut pending = Box::pin(request.addresses([address], slot));
    assert!(
        timeout(Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );
    assert_eq!(client.slots.available_permits(), 1);
    let released = client.slots.clone().try_acquire_owned().unwrap();
    drop(pending);
    drop(released);
    drop(other_slots);
    drop(session);
    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn dns_failure_reuses_recovered_pool_capacity() {
    dns_failure_with_pooled_session(true).await;
}

#[tokio::test]
async fn dns_failure_without_available_capacity_preserves_error() {
    dns_failure_with_pooled_session(false).await;
}

async fn dns_failure_with_pooled_session(available: bool) {
    timeout(Duration::from_secs(5), async {
        let mut client = test_pool();
        client.upstream.host = "proxy.test".into();
        let dns_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.resolver = Resolver::from_config(
            &dns::Config {
                bootstrap: vec![dns_socket.local_addr().unwrap()],
                timeout_ms: 10,
                ..dns::Config::default()
            },
            None,
        );
        let (session, server) = pooled_test_session(&client, 1).await;
        let busy = session.try_acquire().unwrap();
        client.publish_session(session.clone()).await;
        let mut pending = Box::pin(client.connect("example.com:443".parse::<Authority>().unwrap()));
        assert!(
            poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        // Let DNS finish while the request is unpolled, then make capacity ready too.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let busy = if available {
            drop(busy);
            None
        } else {
            Some(busy)
        };
        let result = pending.await;
        match result {
            Ok(tunnel) => {
                assert!(available);
                assert!(Arc::ptr_eq(&tunnel._session, &session));
            }
            Err(error) => {
                assert!(!available, "{error:#}");
                assert!(format!("{error:#}").contains("resolve upstream hostname"));
            }
        }
        assert_eq!(
            client.slots.available_permits(),
            PoolPolicy::CONNECTIONS - 1
        );
        drop(busy);
        drop(session);
        drop(client);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn address_retry_prefers_its_failed_session_and_waits_for_transport_close() {
    retry_failed_session(false).await;
}

#[tokio::test]
async fn address_retry_waits_for_broken_transport_without_retiring_healthy_session() {
    retry_failed_session(true).await;
}

async fn retry_failed_session(broken: bool) {
    timeout(Duration::from_secs(5), async {
        let client = test_pool();
        let (healthy, healthy_server) = pooled_test_session(&client, 1).await;
        let (failed, failed_server) = pooled_test_session(&client, 1).await;
        client
            .sessions
            .lock()
            .await
            .extend([healthy.clone(), failed.clone()]);
        let reserved: Vec<_> = (0..PoolPolicy::CONNECTIONS - 2)
            .map(|_| client.slots.clone().try_acquire_owned().unwrap())
            .collect();
        let active = failed.try_acquire().unwrap();
        let healthy_active = healthy.try_acquire().unwrap();
        let excluded = [Arc::downgrade(&failed)];
        let mut retry = Box::pin(client.assign(Allocation::Retry, &excluded));
        assert!(
            timeout(Duration::from_millis(20), &mut retry)
                .await
                .is_err()
        );
        assert!(!healthy.draining.load(Ordering::Relaxed));
        assert_eq!(client.sessions.lock().await.len(), 2);
        drop(active);
        if broken {
            failed.health.mark_broken();
        }
        assert!(
            timeout(Duration::from_millis(20), &mut retry)
                .await
                .is_err()
        );
        assert!(!failed.usable());
        {
            let sessions = client.sessions.lock().await;
            assert_eq!(sessions.len(), 1);
            assert!(Arc::ptr_eq(&sessions[0], &healthy));
        }
        drop(failed);
        // Aborting the outer driver cannot synchronously close Rama's IO task.
        assert_eq!(client.slots.available_permits(), 0);
        let Assignment::Connection(slot) = retry.await else {
            panic!("retry must reserve a connection slot")
        };
        failed_server.await.unwrap();
        assert!(!healthy.draining.load(Ordering::Relaxed));
        drop(slot);
        drop(healthy_active);
        drop(reserved);
        drop(healthy);
        drop(client);
        healthy_server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn published_session_waiter_wakes_when_all_sessions_break() {
    timeout(Duration::from_secs(5), async {
        let client = test_pool();
        let (zero, server) = pooled_test_session(&client, 0).await;
        client.publish_session(zero.clone()).await;
        let request = ConnectRequest::new(&client, "example.com:443".parse().unwrap());
        let mut waiting = Box::pin(request.stream());
        assert!(
            timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        zero.health.mark_broken();
        assert!(matches!(waiting.await, Err(error) if error.is::<UnsentConnect>()));
        assert!(client.sessions.lock().await.is_empty());
        drop(request);
        drop(zero);
        drop(client);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn warm_pool_retries_other_sessions_after_connect_rejection() {
    timeout(Duration::from_secs(5), async {
        let client = test_pool();
        let (first, first_server) = pooled_test_session_with_status(&client, 1, 503).await;
        let (second, second_server) = pooled_test_session_with_status(&client, 1, 502).await;
        let (healthy, healthy_server) = pooled_test_session(&client, 1).await;
        for session in [&first, &second, &healthy] {
            client.publish_session(session.clone()).await;
        }

        let tunnel = client
            .connect("example.com:443".parse::<Authority>().unwrap())
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&tunnel._session, &healthy));
        assert!(first.usable());
        assert!(second.usable());
        assert_eq!(client.sessions.lock().await.len(), 3);
        assert_eq!(client.slots.available_permits(), 1);

        drop(tunnel);
        drop(first);
        drop(second);
        drop(healthy);
        drop(client);
        first_server.await.unwrap();
        second_server.await.unwrap();
        healthy_server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn warm_pool_rejection_establishes_replacement() {
    warm_pool_replacement(false).await;
}

#[tokio::test]
async fn warm_pool_rejection_retires_failed_session_when_full() {
    warm_pool_replacement(true).await;
}

async fn warm_pool_replacement(full_pool: bool) {
    timeout(Duration::from_secs(5), async {
        let (tls, acceptor) = test_tls_configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(TcpStream::new(socket)).await.unwrap();
            let _ = server_h2::Builder::new(Executor::new())
                .serve_connection(
                    ServerTlsStream::new(stream),
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
        let mut client = test_pool();
        client.upstream.port = address.port();
        client.server_name = ServerName::try_from("proxy.test").unwrap();
        client.tls = tls;
        let (rejected, rejected_server) = pooled_test_session_with_status(&client, 1, 503).await;
        client.publish_session(rejected).await;
        let reserved: Vec<_> = (0..if full_pool {
            PoolPolicy::CONNECTIONS - 1
        } else {
            0
        })
            .map(|_| client.slots.clone().try_acquire_owned().unwrap())
            .collect();

        let tunnel = client
            .connect("example.com:443".parse::<Authority>().unwrap())
            .await
            .unwrap();
        assert_eq!(tunnel._session.address, Some(address));
        assert_eq!(
            client.sessions.lock().await.len(),
            if full_pool { 1 } else { 2 }
        );

        drop(tunnel);
        drop(reserved);
        drop(client);
        rejected_server.await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

fn test_pool() -> Client {
    Client::new(
        Upstream {
            host: "127.0.0.1".into(),
            port: 443,
            server_name: None,
            username: "user".into(),
            password: "pass".into(),
            require_padding: false,
        },
        None,
    )
    .unwrap()
}

async fn pooled_test_session(client: &Client, limit: u32) -> (Arc<Session>, JoinHandle<()>) {
    pooled_test_session_with_status(client, limit, 200).await
}

async fn pooled_test_session_with_status(
    client: &Client,
    limit: u32,
    status: u16,
) -> (Arc<Session>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = server_h2::Builder::new(Executor::new())
            .with_max_concurrent_streams(limit)
            .serve_connection(
                TcpStream::new(socket),
                service_fn(move |_: Request<Incoming>| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Body::empty())
                            .unwrap(),
                    )
                }),
            )
            .await;
    });
    let session = Session::handshake_reserved(
        TcpStream::new(tokio::net::TcpStream::connect(address).await.unwrap()),
        client.changed.clone(),
        Some(address),
        Some(Slot {
            permit: Some(client.slots.clone().try_acquire_owned().unwrap()),
            changed: client.changed.clone(),
        }),
    )
    .await
    .unwrap();
    (session, server)
}

fn test_tls_configs() -> (TlsConnector, TlsAcceptor) {
    let certified = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut server = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    (
        TlsConnector::from(Arc::new(client)),
        TlsAcceptor::from(Arc::new(server)),
    )
}

#[tokio::test]
async fn stalled_tls_reuses_released_pool_capacity() {
    stalled_establishment(false, false, false).await;
}

#[tokio::test]
async fn stalled_initial_settings_reuses_released_pool_capacity() {
    stalled_establishment(true, false, false).await;
}

#[tokio::test]
async fn cancelled_tls_attempt_releases_connection_budget() {
    stalled_establishment(false, true, false).await;
}

#[tokio::test]
async fn cancelled_initial_settings_attempt_releases_connection_budget() {
    stalled_establishment(true, true, false).await;
}

#[tokio::test]
async fn released_session_rejection_preserves_current_address_attempt() {
    stalled_establishment(true, false, true).await;
}

async fn stalled_establishment(settings: bool, cancel: bool, reject_reuse: bool) {
    timeout(Duration::from_secs(5), async {
        let (tls, acceptor) = test_tls_configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = test_pool();
        client.upstream.port = listener.local_addr().unwrap().port();
        client.server_name = ServerName::try_from("proxy.test").unwrap();
        client.tls = tls;
        let (session, pooled_server) = pooled_test_session_with_status(
            &client, 1, if reject_reuse { 503 } else { 200 },
        ).await;
        let busy = session.try_acquire().unwrap();
        client.sessions.lock().await.push(session.clone());
        let (ready, accepted) = oneshot::channel();
        let slow_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            if settings {
                let mut tls = acceptor.accept(TcpStream::new(socket)).await.unwrap();
                ready.send(()).unwrap();
                let _ = tls.read_to_end(&mut Vec::new()).await;
            } else {
                ready.send(()).unwrap();
                let _ = socket.read_to_end(&mut Vec::new()).await;
            }
            if reject_reuse {
                let (socket, _) = listener.accept().await.unwrap();
                let tls = acceptor.accept(TcpStream::new(socket)).await.unwrap();
                let _ = server_h2::Builder::new(Executor::new())
                    .serve_connection(
                        ServerTlsStream::new(tls),
                        service_fn(|_: Request<Incoming>| async {
                            Ok::<_, Infallible>(Response::new(Body::empty()))
                        }),
                    ).await;
            }
        });
        let mut request = Box::pin(client.connect("example.com:443".parse::<Authority>().unwrap()));
        tokio::select! {
            result = &mut request => panic!("CONNECT completed before capacity was released: {}", result.is_ok()),
            result = accepted => result.unwrap(),
        }
        assert_eq!(client.slots.available_permits(), PoolPolicy::CONNECTIONS - 2);
        if cancel {
            drop(request);
            drop(busy);
        } else {
            drop(busy);
            let tunnel = timeout(Duration::from_secs(1), request).await.unwrap().unwrap();
            assert_eq!(Arc::ptr_eq(&tunnel._session, &session), !reject_reuse);
            drop(tunnel);
        }
        if !reject_reuse {
            slow_server.await.unwrap();
            assert_eq!(client.slots.available_permits(), PoolPolicy::CONNECTIONS - 1);
            assert_eq!(client.sessions.lock().await.len(), 1);
            assert_eq!(session.active(), 0);
        } else {
            assert_eq!(client.sessions.lock().await.len(), 2);
            drop(client);
            slow_server.await.unwrap();
            drop(session);
            pooled_server.await.unwrap();
            return;
        }
        drop(client);
        drop(session);
        pooled_server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn draining_session_keeps_connection_slot_until_last_owner_drops() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = server_h2::Builder::new(Executor::new())
                .serve_connection(
                    TcpStream::new(socket),
                    service_fn(|_: Request<Incoming>| async {
                        Ok::<_, Infallible>(Response::new(Body::empty()))
                    }),
                )
                .await;
        });
        let client = Client::new(
            Upstream {
                host: "127.0.0.1".into(),
                port: address.port(),
                server_name: None,
                username: "user".into(),
                password: "pass".into(),
                require_padding: false,
            },
            None,
        )
        .unwrap();
        let session = Session::handshake_reserved(
            TcpStream::new(tokio::net::TcpStream::connect(address).await.unwrap()),
            client.changed.clone(),
            Some(address),
            Some(Slot {
                permit: Some(client.slots.clone().try_acquire_owned().unwrap()),
                changed: client.changed.clone(),
            }),
        )
        .await
        .unwrap();
        let other_slots: Vec<_> = (0..3)
            .map(|_| client.slots.clone().try_acquire_owned().unwrap())
            .collect();
        client.sessions.lock().await.push(session.clone());
        let stream = session.try_acquire().unwrap();
        session.draining.store(true, Ordering::Relaxed);
        assert!(client.slots.clone().try_acquire_owned().is_err());
        let last_owner = session.clone();
        drop(session);
        let assignment = client.assign(Allocation::Retry, &[]);
        tokio::pin!(assignment);
        assert!(
            timeout(Duration::from_millis(20), &mut assignment)
                .await
                .is_err()
        );
        drop(stream);
        assert!(
            timeout(Duration::from_millis(20), &mut assignment)
                .await
                .is_err()
        );
        assert!(client.sessions.lock().await.is_empty());
        assert_eq!(client.slots.available_permits(), 0);
        drop(last_owner);
        assert_eq!(client.slots.available_permits(), 0);
        let Assignment::Connection(slot) = assignment.await else {
            panic!("retry must reserve a connection slot")
        };
        assert!(client.sessions.lock().await.is_empty());
        assert_eq!(client.slots.available_permits(), 0);
        drop(slot);
        assert_eq!(client.slots.available_permits(), 1);
        drop(other_slots);
        server.await.unwrap();
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
