#![cfg(target_os = "linux")]

use sometimes::{config::Config, linux::handle_flow, naive::client::Client};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

#[tokio::test]
async fn rejection_closes_without_connecting_to_destination_or_upstream() {
    timeout(Duration::from_secs(2), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let config: Config = toml::from_str(
            r#"
            listeners = [{ host = "127.0.0.1", port = 12345, protocol = "tproxy" }]
            outbound_mark = 21327
            [upstream]
            host = "unresolvable.invalid"
            username = "user"
            password = "pass"
            [[routing.rules]]
            domain_suffix = ["blocked.example"]
            action = "reject"
        "#,
        )
        .unwrap();
        let client = Client::new(config.upstream.clone(), config.outbound_mark).unwrap();
        let (mut app, stream) = tokio::io::duplex(1024);
        app.write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();
        let result = tokio::select! {
            result = handle_flow(stream, destination, &config, &client) => result.unwrap(),
            _ = listener.accept() => panic!("rejected flow connected to destination"),
        };
        assert_eq!(result, (0, 0));
        assert_eq!(app.read(&mut [0; 1]).await.unwrap(), 0);
    })
    .await
    .unwrap();
}
