use std::{io, net::SocketAddr};

use rama::net::socket::SocketOptions;
use tokio::net::{TcpSocket, TcpStream};

/// Apply the bypass mark before connect when interception is configured.
pub async fn connect_outbound(destination: SocketAddr, mark: Option<u32>) -> io::Result<TcpStream> {
    let socket = SocketOptions {
        mark,
        tcp_no_delay: Some(true),
        ..SocketOptions::default_tcp()
    }
    .try_build_socket(destination.into())?;
    socket.set_nonblocking(true)?;
    TcpSocket::from_std_stream(socket.into())
        .connect(destination)
        .await
}
