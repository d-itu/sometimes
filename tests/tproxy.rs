//! Run only inside the isolated namespace created by scripts/test-netns.sh.
use std::{net::SocketAddr, process::Command, time::Duration};

use rama::net::socket::SocketOptions;
use sometimes::{
    config::Config,
    linux::{handle_flow, listen},
    naive::client::Client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

async fn intercepted(target: SocketAddr, listener: SocketAddr) {
    let listener = listen(listener, true).unwrap();
    let (source_tx, source_rx) = tokio::sync::oneshot::channel();
    let app = tokio::spawn(async move {
        let mut stream = TcpStream::connect(target).await.unwrap();
        source_tx.send(stream.local_addr().unwrap()).unwrap();
        stream.write_all(b"intercepted").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
    });
    let (mut stream, peer) = listener.accept().await.unwrap();
    assert_eq!(stream.local_addr().unwrap(), target);
    assert_eq!(peer, source_rx.await.unwrap());
    let mut request = Vec::new();
    stream.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"intercepted");
    stream.write_all(b"reply").await.unwrap();
    stream.shutdown().await.unwrap();
    app.await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated Linux network namespace and nftables rules"]
async fn original_destination_v4_and_v6() {
    timeout(Duration::from_secs(5), async {
        intercepted(
            "198.18.0.1:80".parse().unwrap(),
            "0.0.0.0:12345".parse().unwrap(),
        )
        .await;
        intercepted(
            "[2001:db8::1]:443".parse().unwrap(),
            "[::]:12345".parse().unwrap(),
        )
        .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires isolated Linux network namespace and nftables rules"]
async fn direct_route_bypasses_interception_and_replays_http() {
    timeout(Duration::from_secs(5), async {
        for (target, inbound, family, ip) in [
            ("127.0.0.1:18080", "0.0.0.0:12345", "ip", "127.0.0.1"),
            ("[::1]:18080", "[::]:12345", "ip6", "::1"),
        ] {
            // Force this local test destination through TPROXY unless marked.
            let status = Command::new("nft")
                .args([
                    "insert",
                    "rule",
                    "inet",
                    "sometimes",
                    "output",
                    family,
                    "daddr",
                    ip,
                    "tcp",
                    "dport",
                    "18080",
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
                .unwrap();
            assert!(status.success());
            let server = tokio::net::TcpListener::bind(target).await.unwrap();
            let listener = listen(inbound.parse().unwrap(), true).unwrap();
            let request = b"GET / HTTP/1.1\r\nHost: direct.example\r\n\r\npayload";
            let app = tokio::spawn(async move {
                let mut stream = TcpStream::connect(target).await.unwrap();
                stream.write_all(request).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"response");
            });
            let (stream, _) = listener.accept().await.unwrap();
            let destination = stream.local_addr().unwrap();
            assert_eq!(destination, target.parse::<SocketAddr>().unwrap());
            let mut config: Config = toml::from_str(
                r#"
                listeners = [{ host = "127.0.0.1", port = 12345, protocol = "tproxy" }]
                outbound_mark = 21327
                [upstream]
                host = "invalid.example"
                username = "user"
                password = "pass"
                [routing]
                default = "reject"
                [[routing.rules]]
                domain = ["direct.example"]
                action = "direct"
            "#,
            )
            .unwrap();
            config.routing.prepare().unwrap();
            let client = Client::new(config.upstream.clone(), config.outbound_mark).unwrap();
            let flow = tokio::spawn(async move {
                handle_flow(stream, destination, &config, &client)
                    .await
                    .unwrap()
            });
            // An unmarked direct connection would arrive at listener again.
            let (mut stream, _) = tokio::select! {
                accepted = server.accept() => accepted.unwrap(),
                _ = listener.accept() => panic!("direct connection looped into TPROXY"),
            };
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, request);
            stream.write_all(b"response").await.unwrap();
            stream.shutdown().await.unwrap();
            assert_eq!(flow.await.unwrap(), (request.len() as u64, 8));
            app.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[test]
#[ignore = "requires CAP_NET_ADMIN in an isolated namespace"]
fn upstream_mark_is_applied() {
    let socket = SocketOptions {
        mark: Some(0x534f),
        ..SocketOptions::default_tcp()
    }
    .try_build_socket("127.0.0.1:443".parse::<SocketAddr>().unwrap().into())
    .unwrap();
    assert_eq!(socket.mark().unwrap(), 0x534f);
}
