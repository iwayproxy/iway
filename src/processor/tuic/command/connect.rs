use anyhow::{Context as AnyhowContext, Result, bail};
use socket2::{Domain, Socket, TcpKeepalive, Type};
use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use quinn::{RecvStream, SendStream};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, copy, sink},
    net::TcpStream,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::debug;

use crate::protocol::tuic::command::connect::Connect;

pub struct ConnectProcessor {}

impl ConnectProcessor {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn process(
        &self,
        send: SendStream,
        recv: RecvStream,
        connect: Connect,
    ) -> Result<()> {
        let socket_addr = connect
            .address()
            .to_socket_address()
            .await
            .context(format!("Failed to resolve address {}", &connect.address()))?;

        let mut tcp_stream = match connect_with_keepalive(
            socket_addr,
            Duration::from_secs(5),
            Duration::from_secs(2),
            1,
        )
        .await
        {
            Ok(stream) => stream,
            Err(e) => {
                debug!("Failed to connect to {}, error:{}", &socket_addr, e);
                bail!("Failed to connect to {}, error:{}", &socket_addr, e);
            }
        };

        let quinn_compat = QuinnCompat { send, recv };
        let mut bidirectional_stream = quinn_compat.compat();

        let copy_result = io::copy_bidirectional_with_sizes(
            &mut bidirectional_stream.get_mut(),
            &mut tcp_stream,
            8 * 1024 * 1024,
            8 * 1024 * 1024,
        )
        .await;

        match copy_result {
            Ok((from_client, to_client)) => {
                debug!(
                    "TCP connection to {} completed. Bytes: client→target: {}, target→client: {}",
                    &socket_addr, &from_client, &to_client
                );
            }
            Err(e) => {
                // surface as debug but attach context when returning
                debug!(
                    "Error during TCP communication with {}: {}",
                    &socket_addr, e
                );
            }
        };

        let bytes_copied = copy(&mut tcp_stream, &mut sink()).await?;
        debug!(
            "Droped {} bytes from {:?}",
            bytes_copied,
            &tcp_stream.peer_addr()
        );

        if let Err(e) = tcp_stream.flush().await {
            debug!("tcp_stream.flush() error: {}", e);
        }

        if let Err(e) = tcp_stream.shutdown().await {
            debug!("tcp_stream.shutdown() error: {}", e);
        }

        Ok(())
    }
}

pub async fn connect_with_keepalive(
    addr: SocketAddr,
    keepalive_idle: Duration,
    keepalive_interval: Duration,
    retries: u32,
) -> std::io::Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    socket.set_nonblocking(true)?;

    let keepalive = TcpKeepalive::new()
        .with_time(keepalive_idle)
        .with_interval(keepalive_interval)
        .with_retries(retries);

    socket.set_tcp_keepalive(&keepalive)?;

    match socket.connect(&addr.into()) {
        Ok(_) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }

    socket.set_linger(Some(Duration::ZERO))?;

    let stream = TcpStream::from_std(socket.into())?;
    if let Err(e) = stream.writable().await {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            format!("Connect failed target:{:?} error: {}", &addr, e),
        ));
    };

    Ok(stream)
}

struct QuinnCompat {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl AsyncRead for QuinnCompat {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for QuinnCompat {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}
