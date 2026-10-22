use std::io;

use super::upstream::{query_tcp_stream, query_udp};
use super::*;
use crate::routing::Action as RouteAction;

fn direct_context(upstream: Upstream) -> Context {
    direct_context_with_config(Config {
        upstreams: vec![upstream],
        ..Config::default()
    })
}

fn direct_context_with_config(config: Config) -> Context {
    let config = Arc::new(config);
    Context::new(
        config.clone(),
        Arc::new(ResponseCache::new(NonZeroUsize::new(2).unwrap())),
        Routing::new(RouteAction::Direct),
        Arc::new(
            Client::new(
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
            .unwrap(),
        ),
        Resolver::from_config(&config, None),
        None,
    )
}

#[tokio::test]
async fn rejects_truncated_queries_before_upstream_lookup() {
    let context = direct_context(Upstream::default());
    let request = packet::make_query("example.com", 1);
    for len in 0..request.len() {
        let error = context.handle(&request[..len]).await.unwrap_err();
        assert_eq!(error.to_string(), "invalid DNS query", "query length {len}");
    }
}

#[tokio::test]
async fn udp_truncation_preserves_full_tcp_and_cached_replies() {
    timeout(Duration::from_secs(5), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let context = direct_context(Upstream {
            port: upstream.local_addr().unwrap().port(),
            protocol: Protocol::Tcp,
            ..Upstream::default()
        });
        let server = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let size = stream.read_u16().await.unwrap();
            let mut response = vec![0; usize::from(size)];
            stream.read_exact(&mut response).await.unwrap();
            response[2..4].copy_from_slice(&[0x81, 0x80]);
            response[6..8].copy_from_slice(&40u16.to_be_bytes());
            for _ in 0..40 {
                response
                    .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            }
            stream.write_u16(response.len() as u16).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let udp = tokio::spawn(context.clone().serve_udp(socket));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut request = packet::make_query("example.com", 1);
        let mut buffer = [0; 4096];
        for id in [1u16, 2] {
            request[..2].copy_from_slice(&id.to_be_bytes());
            client.send_to(&request, address).await.unwrap();
            let (size, _) = client.recv_from(&mut buffer).await.unwrap();
            let response = &buffer[..size];
            packet::validate_response(&request, response).unwrap();
            assert_eq!(response[2] & 2, 2);
            assert_eq!(&response[6..12], &[0; 6]);
            assert!(size <= 512);
        }
        server.await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let tcp = tokio::spawn(context.handle_tcp(stream));
        let response = query_tcp_stream(&mut client, &request, 4096).await.unwrap();
        assert_eq!(response[2] & 2, 0);
        assert_eq!(u16::from_be_bytes(response[6..8].try_into().unwrap()), 40);
        assert_eq!(packet::answer_ips(&response).len(), 40);
        assert!(response.len() > 512);
        udp.abort();
        tcp.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_queries_preserve_ids_across_sizes_and_cache_hits() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 512];
        for _ in 0..4 {
            let (size, peer) = upstream.recv_from(&mut buffer).await.unwrap();
            let mut response = buffer[..size].to_vec();
            response[2] |= 0x80;
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&[0, 4, 127, 0, 0, 1]);
            upstream.send_to(&response, peer).await.unwrap();
        }
    });
    let context = direct_context(Upstream {
        port: upstream_address.port(),
        ..Upstream::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let connection = tokio::spawn(context.handle_tcp(stream));
    for (id, name) in [
        (1u16, "a.test"),
        (2, "longer.example.test"),
        (3, "a.test"),
        (4, "."),
        (5, "127.0.0.1"),
    ] {
        let mut request = packet::make_query(name, 1);
        request[..2].copy_from_slice(&id.to_be_bytes());
        let response = timeout(
            Duration::from_secs(2),
            query_tcp_stream(&mut client, &request, 512),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[..2], &id.to_be_bytes());
        assert_eq!(
            packet::answer_ips(&response),
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }
    server.await.unwrap();
    client.shutdown().await.unwrap();
    assert!(connection.await.unwrap().is_err());
}

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

#[test]
fn rejects_zero_dns_listener_and_bootstrap_ports() {
    let mut config = Config {
        enabled: true,
        listen: vec!["127.0.0.1:1053".parse().unwrap()],
        ..Config::default()
    };
    config.validate().unwrap();

    config.listen.push("127.0.0.1:0".parse().unwrap());
    assert_eq!(
        config.validate().unwrap_err().to_string(),
        "dns.listen ports must be nonzero"
    );
    config.listen.pop();

    config.bootstrap.push("127.0.0.1:0".parse().unwrap());
    assert_eq!(
        config.validate().unwrap_err().to_string(),
        "dns.bootstrap ports must be nonzero"
    );
}

#[tokio::test]
async fn valid_bootstrap_address_survives_unresponsive_queries() {
    timeout(Duration::from_secs(3), async {
        for extra_server in [false, true] {
            let bootstrap = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let upstream = Upstream {
                host: "resolver.example".into(),
                port: origin.local_addr().unwrap().port(),
                ..Upstream::default()
            };
            let mut servers = vec![bootstrap.local_addr().unwrap()];
            if extra_server {
                servers.push(silent.local_addr().unwrap());
            }
            let context = direct_context_with_config(Config {
                upstreams: vec![upstream.clone()],
                bootstrap: servers,
                timeout_ms: 300,
                ..Config::default()
            });
            let bootstrap_task = tokio::spawn(async move {
                let mut buffer = [0; 512];
                for _ in 0..2 {
                    let (size, peer) = bootstrap.recv_from(&mut buffer).await.unwrap();
                    let mut response = buffer[..size].to_vec();
                    if response[size - 4..size - 2] == [0, 1] {
                        response[2] |= 0x80;
                        response[6..8].copy_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&[
                            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1,
                        ]);
                        bootstrap.send_to(&response, peer).await.unwrap();
                    } else if extra_server {
                        response[2] |= 0x80;
                        bootstrap.send_to(&response, peer).await.unwrap();
                    }
                }
                bootstrap
            });
            let origin_task = tokio::spawn(async move {
                let mut buffer = [0; 512];
                for _ in 0..2 {
                    let (size, peer) = origin.recv_from(&mut buffer).await.unwrap();
                    buffer[2] |= 0x80;
                    origin.send_to(&buffer[..size], peer).await.unwrap();
                }
            });
            let prepared = PreparedUpstream::new(&upstream);
            let request = packet::make_query("example.com", 1);
            for _ in 0..2 {
                let response = context.queries.query(&request, &prepared).await.unwrap();
                packet::validate_response(&request, &response).unwrap();
            }
            let bootstrap = bootstrap_task.await.unwrap();
            assert!(matches!(
                bootstrap.try_recv_from(&mut [0; 512]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock
            ));
            origin_task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn multiple_unresponsive_addresses_share_one_query_deadline() {
    let bootstrap = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bootstrap_address = bootstrap.local_addr().unwrap();
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = first.local_addr().unwrap().port();
    let second = UdpSocket::bind(("127.0.0.2", port)).await.unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let mut buffer = [0; 512];
            let (size, peer) = bootstrap.recv_from(&mut buffer).await.unwrap();
            let mut response = buffer[..size].to_vec();
            response[2] |= 0x80;
            if response[size - 4..size - 2] == [0, 1] {
                response[6..8].copy_from_slice(&2u16.to_be_bytes());
                for ip in [[127, 0, 0, 1], [127, 0, 0, 2]] {
                    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
                    response.extend_from_slice(&60u32.to_be_bytes());
                    response.extend_from_slice(&[0, 4]);
                    response.extend_from_slice(&ip);
                }
            }
            bootstrap.send_to(&response, peer).await.unwrap();
        }
    });
    let config = Arc::new(Config {
        bootstrap: vec![bootstrap_address],
        timeout_ms: 80,
        ..Config::default()
    });
    let upstream = Upstream {
        host: "multi.example".into(),
        port,
        ..Upstream::default()
    };
    let client = Arc::new(
        Client::new(
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
        .unwrap(),
    );
    let context = Context::new(
        config.clone(),
        Arc::new(ResponseCache::new(NonZeroUsize::new(1).unwrap())),
        Routing::new(RouteAction::Direct),
        client,
        Resolver::from_config(&config, None),
        None,
    );
    let request = packet::make_query("example.com", 1);
    let result = timeout(
        Duration::from_millis(150),
        context
            .queries
            .query(&request, &PreparedUpstream::new(&upstream)),
    )
    .await
    .expect("all addresses must share the configured deadline");
    assert!(result.is_err());
    server.await.unwrap();
    drop((first, second));
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
    let error = timeout(
        Duration::from_millis(config.timeout_ms),
        query_udp(&request, address, config.max_packet_bytes, None),
    )
    .await
    .unwrap()
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
        .queries
        .query(&request, &PreparedUpstream::new(&upstream))
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
    assert!(
        context
            .queries
            .query(&request, &PreparedUpstream::new(&upstream))
            .await
            .is_err()
    );
    timeout(Duration::from_secs(3), accepted)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn prepared_routing_preserves_normalization_order_and_suffix_boundaries() {
    let config: Config = toml::from_str(
        r#"
            [routing]
            default = 'direct'
            [[routing.rules]]
            domain = ['Allowed.Example.COM.']
            domain_suffix = ['Other.TEST.']
            upstream = 'other'
            [[routing.rules]]
            domain_suffix = ['Example.COM.']
            action = 'reject'
            [[upstreams]]
            name = 'other'
            host = '127.0.0.2'
            port = 53
            protocol = 'udp'
            [[upstreams]]
            name = 'direct'
            host = '127.0.0.1'
            port = 53
            protocol = 'udp'
        "#,
    )
    .unwrap();
    config.validate().unwrap();
    let routing = PreparedRouting::new(&config);
    assert_eq!(routing.target("allowed.example.com"), Some(0));
    assert_eq!(routing.target("other.test"), Some(0));
    assert_eq!(routing.target("www.other.test"), Some(0));
    assert_eq!(routing.target("example.com"), None);
    assert_eq!(routing.target("www.example.com"), None);
    assert_eq!(routing.target("notexample.com"), Some(1));
    assert_eq!(routing.target("example.com.evil"), Some(1));
    assert_eq!(routing.target("notother.test"), Some(1));
    assert_eq!(routing.target("unmatched.test"), Some(1));
}

#[test]
fn extracts_and_routes_names() {
    let mut packet = vec![0; 12];
    packet.extend_from_slice(&[7]);
    packet.extend_from_slice(b"example");
    packet.extend_from_slice(&[3]);
    packet.extend_from_slice(b"com");
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    let config: Config = toml::from_str(concat!(
        "[routing]\ndefault = 'direct'\n",
        "[[routing.rules]]\ndomain_suffix = ['example.com']\naction = 'reject'\n",
        "[[upstreams]]\nname='direct'\nhost='127.0.0.1'\nport=53\nprotocol='udp'"
    ))
    .unwrap();
    assert_eq!(packet::query_name(&packet).as_deref(), Some("example.com"));
    assert!(
        PreparedRouting::new(&config)
            .target("www.example.com")
            .is_none()
    );
}
