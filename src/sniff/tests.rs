use super::*;
use rama::tls::rustls::dep::rustls::{ClientConfig, ClientConnection, RootCertStore, crypto::ring};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

fn client_hello() -> Vec<u8> {
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let mut client =
        ClientConnection::new(Arc::new(config), "Example.COM".try_into().unwrap()).unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    bytes
}

fn record(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![22, 3, 3];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn tls_client_hello_across_every_record_boundary() {
    let hello = client_hello();
    let size = usize::from(u16::from_be_bytes([hello[3], hello[4]]));
    let handshake = &hello[5..5 + size];
    for split in 1..handshake.len() {
        let mut wire = record(&handshake[..split]);
        assert!(matches!(probe(&wire), Probe::More));
        wire.extend_from_slice(&record(&handshake[split..]));
        assert!(matches!(probe(&wire), Probe::Done(Some(name)) if name == "example.com"));
    }
    for split in 0..5 + size {
        assert!(matches!(probe(&hello[..split]), Probe::More));
    }
}

#[test]
fn http_host_and_malformed_inputs() {
    for authority in ["Example.COM:8080", "example.com."] {
        let request = format!("GET / HTTP/1.1\r\nhOsT: {authority}\r\n\r\nbody");
        assert!(
            matches!(probe(request.as_bytes()), Probe::Done(Some(name)) if name == "example.com")
        );
    }
    for bytes in [
        b"GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
        b"GET / HTTP/1.1\r\nBroken header\r\n\r\n",
        b"SSH-2.0-test\r\n",
        b"\x16\x03\x03\x00\x01\x02\x00\x00\x00\x00\x00",
    ] {
        assert!(matches!(probe(bytes), Probe::Done(None)));
    }
}

#[tokio::test]
async fn fragmented_http_replays_exactly_and_preserves_half_close() {
    let request = b"GET / HTTP/1.1\r\nHost: Example.com\r\n\r\nbody";
    let (mut app, socket) = tokio::io::duplex(2);
    let sender = tokio::spawn(async move {
        for byte in request {
            app.write_all(&[*byte]).await.unwrap();
        }
        app.shutdown().await.unwrap();
        let mut reply = Vec::new();
        app.read_to_end(&mut reply).await.unwrap();
        reply
    });
    let (mut stream, name) = inspect(socket, &Sniff::default()).await.unwrap();
    assert_eq!(name.as_deref(), Some("example.com"));
    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, request);
    stream.write_all(b"reply").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(sender.await.unwrap(), b"reply");
}

#[tokio::test]
async fn timeout_limit_disabled_and_eof_keep_all_bytes() {
    for config in [
        Sniff {
            timeout_ms: 10,
            ..Sniff::default()
        },
        Sniff {
            max_bytes: 3,
            ..Sniff::default()
        },
        Sniff {
            enabled: false,
            ..Sniff::default()
        },
    ] {
        let (mut app, socket) = tokio::io::duplex(64);
        app.write_all(b"GET /").await.unwrap();
        let (mut stream, name) = inspect(socket, &config).await.unwrap();
        assert!(name.is_none());
        app.write_all(b"remaining").await.unwrap();
        app.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"GET /remaining");
    }
    let (mut app, socket) = tokio::io::duplex(16);
    app.write_all(b"\x16\x03").await.unwrap();
    app.shutdown().await.unwrap();
    let (mut stream, name) = inspect(socket, &Sniff::default()).await.unwrap();
    assert!(name.is_none());
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"\x16\x03");
}
