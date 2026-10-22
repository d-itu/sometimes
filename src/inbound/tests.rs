use super::*;
use rama::http::{
    HeaderValue,
    body::util::BodyExt,
    core::{
        client::conn::http2 as client_h2,
        server::conn::{http1 as server_h1, http2 as server_h2},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

#[tokio::test]
async fn socks_handshake_deadline_releases_connections_without_limiting_tunnels() {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut config = config(Action::Direct);
        config.max_connections = 1;
        config.connect_timeout_secs = 1;
        config.listeners[0].port = address.port();
        config.listeners[0].protocol = crate::config::InboundProtocol::Socks;
        let server = tokio::spawn(crate::linux::run(Arc::new(config)));
        let mut stalled = loop {
            match TcpStream::connect(address).await {
                Ok(stream) => break stream,
                Err(_) => tokio::task::yield_now().await,
            }
        };
        stalled.write_all(&[5]).await.unwrap();
        assert_eq!(stalled.read(&mut [0]).await.unwrap(), 0);

        let mut stalled = TcpStream::connect(address).await.unwrap();
        stalled.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        stalled.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        stalled.write_all(&[5, 1, 0, 1, 127]).await.unwrap();
        assert_eq!(stalled.read(&mut [0]).await.unwrap(), 0);

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&target.local_addr().unwrap().port().to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        let (mut peer, _) = target.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        stream.write_all(b"alive").await.unwrap();
        let mut payload = [0; 5];
        peer.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"alive");
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_handshake_deadline_releases_connections_without_limiting_tunnels() {
    timeout(Duration::from_secs(10), async {
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_address = http_listener.local_addr().unwrap();
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_address = socks_listener.local_addr().unwrap();
        drop((http_listener, socks_listener));
        let mut config = config(Action::Direct);
        config.max_connections = 1;
        config.connect_timeout_secs = 1;
        config.listeners[0].port = http_address.port();
        config.listeners.push(crate::config::Listener {
            host: socks_address.ip().to_string(),
            port: socks_address.port(),
            protocol: crate::config::InboundProtocol::Socks,
        });
        let server = tokio::spawn(crate::linux::run(Arc::new(config)));
        for prefix in [
            b"".as_slice(),
            b"PRI * HTTP/2.0\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\n",
        ] {
            let mut stalled = loop {
                match TcpStream::connect(http_address).await {
                    Ok(stream) => break stream,
                    Err(_) => tokio::task::yield_now().await,
                }
            };
            let started = tokio::time::Instant::now();
            let middle = prefix.len() / 2;
            stalled.write_all(&prefix[..middle]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            stalled.write_all(&prefix[middle..]).await.unwrap();
            let mut response = Vec::new();
            stalled.read_to_end(&mut response).await.unwrap();
            assert!(started.elapsed() >= Duration::from_millis(900));
            let mut socks = TcpStream::connect(socks_address).await.unwrap();
            socks.write_all(&[5, 1, 0]).await.unwrap();
            let mut greeting = [0; 2];
            socks.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            socks.shutdown().await.unwrap();
            assert_eq!(socks.read(&mut [0]).await.unwrap(), 0);
        }
        let (origin_address, origin_task) = origin("slow").await;
        let mut upload = TcpStream::connect(http_address).await.unwrap();
        upload
            .write_all(
                format!(
                    concat!(
                        "POST http://{0}/ HTTP/1.1\r\nHost: {0}\r\n",
                        "Content-Length: 5\r\nConnection: close\r\n\r\n"
                    ),
                    origin_address
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        upload.write_all(b"alive").await.unwrap();
        let mut reply = String::new();
        upload.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(reply.contains("slow POST / alive"), "{reply}");
        origin_task.abort();

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let mut stream = TcpStream::connect(http_address).await.unwrap();
        stream
            .write_all(
                format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        assert!(headers(&mut stream).await.starts_with("HTTP/1.1 200"));
        let (mut peer, _) = target.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        stream.write_all(b"alive").await.unwrap();
        let mut payload = [0; 5];
        peer.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"alive");
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn resolved_addresses_retry_direct_and_recheck_routing() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let unavailable = SocketAddr::new("127.0.0.2".parse().unwrap(), destination.port());
        let config = config(Action::Direct);
        let client = Arc::new(Client::new(config.upstream.clone(), None).unwrap());
        let state = State {
            config: Arc::new(config),
            client: client.clone(),
            permits: Arc::new(Semaphore::new(1)),
        };
        let transport = state
            .connect_resolved([unavailable, destination], Some("example.test"))
            .await
            .unwrap();
        assert!(matches!(transport, Transport::Direct(_)));
        let (stream, _) = listener.accept().await.unwrap();
        drop((transport, stream));

        let mut config = self::config(Action::Direct);
        config.routing = toml::from_str(&format!(
            "default = 'direct'\n[[rules]]\nip_cidr = ['{}/32']\naction = 'reject'",
            destination.ip()
        ))
        .unwrap();
        let state = State {
            config: Arc::new(config),
            client,
            permits: Arc::new(Semaphore::new(1)),
        };
        let error = state
            .connect_resolved([unavailable, destination], Some("example.test"))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let proxy_address = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = self::config(Action::Direct);
        config.upstream.port = proxy_address.local_addr().unwrap().port();
        drop(proxy_address);
        config.routing = toml::from_str(
            "default = 'direct'\n[[rules]]\nip_cidr = ['127.0.0.2/32']\naction = 'proxy'",
        )
        .unwrap();
        let client = Arc::new(Client::new(config.upstream.clone(), None).unwrap());
        let state = State {
            config: Arc::new(config),
            client,
            permits: Arc::new(Semaphore::new(1)),
        };
        assert!(
            state
                .connect_resolved([unavailable, destination], Some("example.test"))
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn single_connection_limit_can_forward_http() {
    timeout(Duration::from_secs(5), async {
        let (origin_address, origin_task) = origin("single").await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut config = config(Action::Direct);
        config.max_connections = 1;
        config.listeners[0].port = address.port();
        let config = Arc::new(config);
        let server = tokio::spawn(crate::linux::run(config));
        let mut stream = loop {
            match TcpStream::connect(address).await {
                Ok(stream) => break stream,
                Err(_) => tokio::task::yield_now().await,
            }
        };
        stream
            .write_all(
                format!(
                    "GET http://{origin_address}/ HTTP/1.1\r\nHost: {origin_address}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("single GET /"), "{response}");
        server.abort();
        origin_task.abort();
    })
    .await
    .unwrap();
}

async fn headers(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn continue_upload_connection_errors_and_ipv6_socks() {
    timeout(Duration::from_secs(10), async {
        let (address, origin) = origin("upload").await;
        let (mut stream, server) = inbound(false, Action::Direct).await;
        stream.write_all(format!("POST http://{address}/expect HTTP/1.1\r\nHost: {address}\r\nExpect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        assert!(headers(&mut stream).await.starts_with("HTTP/1.1 100"));
        stream.write_all(b"data").await.unwrap();
        let mut reply = String::new(); stream.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}"); assert!(reply.contains("upload POST /expect data"));
        server.await.unwrap(); origin.abort();
        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = unavailable.local_addr().unwrap(); drop(unavailable);
        let (mut stream, server) = inbound(false, Action::Direct).await;
        stream.write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()).await.unwrap();
        assert!(headers(&mut stream).await.starts_with("HTTP/1.1 502"));
        drop(stream); server.await.unwrap();
        let target = TcpListener::bind("[::1]:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let (mut stream, server) = inbound(true, Action::Direct).await;
        stream.write_all(&[5, 1, 0]).await.unwrap(); let mut greeting = [0; 2]; stream.read_exact(&mut greeting).await.unwrap();
        let mut request = vec![5, 1, 0, 4]; request.extend_from_slice(&1u128.to_be_bytes()); request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap(); let mut reply = [0; 10]; stream.read_exact(&mut reply).await.unwrap(); assert_eq!(reply[1], 0);
        let (mut peer, _) = target.accept().await.unwrap(); stream.write_all(b"ipv6").await.unwrap(); let mut payload = [0; 4]; peer.read_exact(&mut payload).await.unwrap(); assert_eq!(&payload, b"ipv6");
        drop((peer, stream)); server.await.unwrap();
    }).await.unwrap();
}

fn config(action: Action) -> Config {
    let mut config: Config = toml::from_str(
        r#"
        listeners = [{ host = "127.0.0.1", port = 8080, protocol = "http" }]
        idle_timeout_secs = 3
        connect_timeout_secs = 2
        [upstream]
        host = "127.0.0.1"
        username = "user"
        password = "pass"
    "#,
    )
    .unwrap();
    config.routing.default = action;
    config
}
async fn inbound(socks_protocol: bool, action: Action) -> (TcpStream, JoinHandle<()>) {
    let config = Arc::new(config(action));
    let client = Arc::new(Client::new(config.upstream.clone(), config.outbound_mark).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let permits = Arc::new(tokio::sync::Semaphore::new(256));
        let _ = if socks_protocol {
            socks(stream, config, client, permits).await
        } else {
            http(stream, config, client, permits).await
        };
    });
    (TcpStream::connect(address).await.unwrap(), server)
}
async fn origin(label: &'static str) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            connections.spawn(async move {
                server_h1::Builder::new()
                    .serve_connection(
                        RamaTcpStream::new(socket),
                        service_fn(move |req: Request<Incoming>| async move {
                            assert!(req.uri().authority().is_none());
                            assert!(!req.headers().contains_key("proxy-authorization"));
                            assert!(!req.headers().contains_key("x-hop"));
                            let prefix = format!("{label} {} {} ", req.method(), req.uri());
                            let bytes = req.into_body().collect().await.unwrap().to_bytes();
                            let mut payload = prefix.into_bytes();
                            payload.extend_from_slice(&bytes);
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header("connection", "x-origin-hop")
                                    .header("x-origin-hop", "secret")
                                    .body(Body::from(payload))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
    });
    (address, task)
}
fn forward(req: Request<Body>) -> Request<Body> {
    req.extensions()
        .insert(rama::net::client::ProxyRoute::Proxy(
            "http://127.0.0.1:8080".parse().unwrap(),
        ));
    req
}
async fn body(reply: Response<Incoming>) -> String {
    assert_eq!(reply.status(), StatusCode::OK);
    assert!(!reply.headers().contains_key("x-origin-hop"));
    String::from_utf8(
        reply
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn http_and_socks_reject_before_success() {
    timeout(Duration::from_secs(8), async {
        let (stream, server) = inbound(false, Action::Reject).await;
        let (mut sender, conn) = http1::handshake(RamaTcpStream::new(stream)).await.unwrap();
        let driver = tokio::spawn(conn);
        for (method, uri, status) in [
            (Method::GET, "http://127.0.0.1/", StatusCode::FORBIDDEN),
            (
                Method::CONNECT,
                "https://127.0.0.1:80",
                StatusCode::FORBIDDEN,
            ),
            (Method::GET, "/missing-authority", StatusCode::BAD_REQUEST),
        ] {
            let reply = sender
                .send_request(forward(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("host", "127.0.0.1")
                        .body(Body::empty())
                        .unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(reply.status(), status);
            reply.into_body().collect().await.unwrap();
        }
        drop(sender);
        driver.await.unwrap().unwrap();
        server.await.unwrap();
        let (mut stream, server) = inbound(true, Action::Reject).await;
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        stream
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 5);
        assert_ne!(reply[1], 0);
        drop(stream);
        server.await.unwrap();
        let (mut stream, server) = inbound(true, Action::Reject).await;
        stream.write_all(&[5, 1, 2]).await.unwrap();
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 255]);
        drop(stream);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_per_request_routing_h1_h2_and_chunked_body() {
    timeout(Duration::from_secs(10), async {
        let (a, origin_a) = origin("a").await;
        let (b, origin_b) = origin("b").await;
        let (stream, server) = inbound(false, Action::Direct).await;
        let (mut sender, conn) = http1::handshake(RamaTcpStream::new(stream)).await.unwrap();
        let driver = tokio::spawn(conn);
        for (target, label) in [(a, "a"), (b, "b")] {
            let reply = sender.send_request(forward(Request::builder().method("POST").uri(format!("http://{target}/path?q=1")).header("host", "wrong.example").header("connection", "x-hop").header("x-hop", "secret").header("proxy-authorization", "secret").body(Body::from("upload")).unwrap())).await.unwrap();
            assert_eq!(body(reply).await, format!("{label} POST /path?q=1 upload"));
        }
        drop(sender); driver.await.unwrap().unwrap(); server.await.unwrap();
        let (stream, server) = inbound(false, Action::Direct).await;
        let (sender, conn) = client_h2::Builder::new(Executor::default()).handshake(RamaTcpStream::new(stream)).await.unwrap();
        let driver = tokio::spawn(conn);
        let mut first = sender.clone(); let mut second = sender.clone();
        let req = |target| Request::builder().uri(format!("http://{target}/h2")).version(Version::HTTP_2).body(Body::empty()).unwrap();
        let (one, two) = tokio::join!(first.send_request(req(a)), second.send_request(req(b)));
        assert_eq!(body(one.unwrap()).await, "a GET /h2 ");
        assert_eq!(body(two.unwrap()).await, "b GET /h2 ");
        drop((sender, first, second)); driver.abort(); server.abort();
        let (mut stream, server) = inbound(false, Action::Direct).await;
        stream.write_all(format!("POST http://{a}/chunk HTTP/1.1\r\nHost: {a}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n").as_bytes()).await.unwrap();
        let mut reply = String::new(); stream.read_to_string(&mut reply).await.unwrap();
        assert!(reply.contains("a POST /chunk onetwo"), "{reply}");
        server.await.unwrap(); origin_a.abort(); origin_b.abort();
    }).await.unwrap();
}

#[tokio::test]
async fn http_connect_h1_h2_and_socks_half_close() {
    timeout(Duration::from_secs(10), async {
        for protocol in ["http1", "http2", "socks"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let (mut io, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                io.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"ping");
                io.write_all(b"pong").await.unwrap();
                io.shutdown().await.unwrap();
            });
            let (stream, server) = inbound(protocol == "socks", Action::Direct).await;
            let mut tunnel: Box<dyn TestIo> = match protocol {
                "http1" => {
                    let (mut sender, conn) =
                        http1::handshake(RamaTcpStream::new(stream)).await.unwrap();
                    tokio::spawn(conn.with_upgrades());
                    let reply = sender
                        .send_request(
                            Request::builder()
                                .method(Method::CONNECT)
                                .uri(format!("https://{address}"))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(reply.status(), StatusCode::OK);
                    Box::new(handle_upgrade(&reply).await.unwrap())
                }
                "http2" => {
                    let (mut sender, conn) = client_h2::Builder::new(Executor::default())
                        .handshake(RamaTcpStream::new(stream))
                        .await
                        .unwrap();
                    tokio::spawn(conn);
                    let reply = sender
                        .send_request(
                            Request::builder()
                                .method(Method::CONNECT)
                                .uri(format!("https://{address}"))
                                .version(Version::HTTP_2)
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(reply.status(), StatusCode::OK);
                    Box::new(handle_upgrade(&reply).await.unwrap())
                }
                _ => {
                    let mut stream = stream;
                    stream.write_all(&[5, 1, 0]).await.unwrap();
                    let mut buf = [0; 2];
                    stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(buf, [5, 0]);
                    let mut bytes = vec![5, 1, 0, 3, 9];
                    bytes.extend_from_slice(b"127.0.0.1");
                    bytes.extend_from_slice(&address.port().to_be_bytes());
                    stream.write_all(&bytes).await.unwrap();
                    let mut reply = [0; 10];
                    stream.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply[1], 0);
                    Box::new(stream)
                }
            };
            tunnel.write_all(b"ping").await.unwrap();
            tunnel.shutdown().await.unwrap();
            let mut reply = Vec::new();
            tunnel.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"pong");
            drop(tunnel);
            echo.await.unwrap();
            server.await.unwrap();
        }
    })
    .await
    .unwrap();
}
trait TestIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TestIo for T {}

#[tokio::test]
async fn http_over_padded_naive_transport() {
    timeout(Duration::from_secs(8), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(|req: Request<Incoming>| async move {
                tokio::spawn(async move {
                    let mut tunnel = handle_upgrade(&req).await.unwrap();
                    let mut request = Vec::new();
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        let size = tunnel.read_u16().await.unwrap() as usize;
                        let padding = tunnel.read_u8().await.unwrap() as usize;
                        let mut record = vec![0; size + padding];
                        tunnel.read_exact(&mut record).await.unwrap();
                        request.extend_from_slice(&record[..size]);
                    }
                    assert!(request.starts_with(b"GET /padding HTTP/1.1\r\n"));
                    let reply =
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\npadded";
                    tunnel.write_u16(reply.len() as u16).await.unwrap();
                    tunnel.write_u8(2).await.unwrap();
                    tunnel.write_all(reply).await.unwrap();
                    tunnel.write_all(&[0, 0]).await.unwrap();
                    tunnel.shutdown().await.unwrap();
                    let mut tail = Vec::new();
                    tunnel.read_to_end(&mut tail).await.unwrap();
                    assert!(tail.is_empty());
                });
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("padding", "yes")
                        .body(Body::empty())
                        .unwrap(),
                )
            });
            server_h2::Builder::new(Executor::default())
                .serve_connection(RamaTcpStream::new(stream), service)
                .await
                .unwrap();
        });
        let tunnel = crate::naive::client::connect_h2(
            RamaTcpStream::new(TcpStream::connect(address).await.unwrap()),
            "127.0.0.1:80".parse::<SocketAddr>().unwrap(),
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
            true,
        )
        .await
        .unwrap();
        let transport = tunnel_transport(tunnel, Duration::from_secs(3));
        let upstream = Egress {
            transport,
            extensions: Extensions::new(),
            _permit: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        };
        let (mut sender, conn) = http1::handshake(upstream).await.unwrap();
        let driver = tokio::spawn(conn);
        let request = Request::builder()
            .uri("/padding")
            .header("host", "example.test")
            .body(Body::empty())
            .unwrap();
        let reply = sender.send_request(request).await.unwrap();
        assert_eq!(body(reply).await, "padded");
        drop(sender);
        driver.await.unwrap().unwrap();
        server.abort();
    })
    .await
    .unwrap();
}
