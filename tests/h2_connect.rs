use std::net::SocketAddr;

use rama::{
    http::{
        Body, HeaderValue, Method, Request, Response, Version,
        core::{body::Incoming, server::conn::http2},
        io::upgrade::handle_upgrade,
    },
    rt::Executor,
    service::service_fn,
    tcp::TcpStream,
};
use sometimes::{naive::client::connect_h2, relay::relay};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
    time::{Duration, timeout},
};

async fn exercise(status: u16, advertised_padding: bool, required_padding: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (completed_tx, mut completed_rx) = mpsc::channel(1);
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        http2::Builder::new(Executor::new())
            .serve_connection(
                TcpStream::new(socket),
                service_fn(move |request: Request<Incoming>| {
                    let completed = completed_tx.clone();
                    async move {
                        assert_eq!(request.method(), Method::CONNECT);
                        assert_eq!(request.version(), Version::HTTP_2);
                        assert_eq!(
                            request.uri().authority().unwrap().to_string(),
                            "[2001:db8::1]:443"
                        );
                        assert_eq!(
                            request.headers()["proxy-authorization"],
                            "Basic dXNlcjpwYXNz"
                        );
                        assert!((16..=32).contains(&request.headers()["padding"].as_bytes().len()));
                        if status == 200 && (advertised_padding || !required_padding) {
                            tokio::spawn(async move {
                                let mut tunnel = handle_upgrade(&request).await.unwrap();
                                let mut wire = Vec::new();
                                tunnel.read_to_end(&mut wire).await.unwrap();
                                if advertised_padding {
                                    assert_eq!(&wire[..2], &[0, 7]);
                                    assert_eq!(&wire[3..10], b"request");
                                    assert_eq!(wire.len(), 10 + usize::from(wire[2]));
                                    assert!(wire[10..].iter().all(|byte| *byte == 0));
                                    // Handwritten protocol fixture, independent of the client codec.
                                    tunnel.write_all(&[0, 8, 2]).await.unwrap();
                                    tunnel.write_all(b"response\0\0").await.unwrap();
                                } else {
                                    assert_eq!(wire, b"request");
                                    tunnel.write_all(b"response").await.unwrap();
                                }
                                tunnel.shutdown().await.unwrap();
                                completed.send(()).await.unwrap();
                            });
                        }
                        let mut response = Response::builder().status(status);
                        if advertised_padding {
                            response = response.header("padding", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                        }
                        Ok(response.body(Body::empty()).unwrap())
                    }
                }),
            )
            .await
    });
    let stream = TcpStream::new(tokio::net::TcpStream::connect(address).await.unwrap());
    let result = connect_h2(
        stream,
        "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
        HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        required_padding,
    )
    .await;
    if status != 200 || (!advertised_padding && required_padding) {
        assert!(result.is_err());
    } else {
        let mut tunnel = result.unwrap();
        let (mut app, local) = tokio::io::duplex(32);
        let application = tokio::spawn(async move {
            app.write_all(b"request").await.unwrap();
            app.shutdown().await.unwrap();
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response");
        });
        assert_eq!(
            relay(
                local,
                &mut tunnel.stream,
                tunnel.padded,
                Duration::from_secs(3)
            )
            .await
            .unwrap(),
            (7, 8)
        );
        application.await.unwrap();
        completed_rx.recv().await.unwrap();
    }
    server.abort();
}

#[tokio::test]
async fn h2_connect_with_padding_and_half_close() {
    timeout(Duration::from_secs(5), exercise(200, true, true))
        .await
        .unwrap();
}

#[tokio::test]
async fn padding_is_required_by_default() {
    timeout(Duration::from_secs(5), exercise(200, false, true))
        .await
        .unwrap();
}

#[tokio::test]
async fn explicit_unpadded_fallback() {
    timeout(Duration::from_secs(5), exercise(200, false, false))
        .await
        .unwrap();
}

#[tokio::test]
async fn authentication_rejection() {
    timeout(Duration::from_secs(5), exercise(407, false, true))
        .await
        .unwrap();
}
