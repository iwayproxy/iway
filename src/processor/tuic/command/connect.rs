use anyhow::{Context as AnyhowContext, Result};
use socket2::{Domain, Socket, TcpKeepalive, Type};
use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use async_trait::async_trait;
use log::debug;
use quinn::{RecvStream, SendStream};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::protocol::tuic::command::connect::Connect;

use super::Processor;

pub struct ConnectProcessor {
    send: SendStream,
    recv: RecvStream,
    connect: Connect,
}

impl ConnectProcessor {
    pub fn new(send: SendStream, recv: RecvStream, connect: Connect) -> Self {
        Self {
            send,
            recv,
            connect,
        }
    }
}

impl AsyncRead for ConnectProcessor {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for ConnectProcessor {
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

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

#[async_trait]
impl Processor for ConnectProcessor {
    async fn process(&mut self) -> Result<()> {
        let socket_addr = self
            .connect
            .address()
            .to_socket_address()
            .await
            .context(format!("Failed to resolve address {}", self.connect.address()))?;

        let mut tcp_stream = match connect_with_keepalive(
            socket_addr,
            Duration::from_secs(5),
            Duration::from_secs(2),
            2
        )
        .await
        {
            Ok(stream) => stream,
            Err(e) => {
                debug!("Failed to connect to {}: {}", socket_addr, e);
                return Err(e.into());
            }
        };

        let mut bidirectional_stream = self.compat();

        let copy_result = io::copy_bidirectional_with_sizes(
            &mut bidirectional_stream.get_mut(),
            &mut tcp_stream,
            2 * 1024 * 1024,
            2 * 1024 * 1024,
        )
        .await;

        match copy_result {
            Ok((from_client, to_client)) => {
                debug!(
                    "TCP connection to {} completed. Bytes: client→target: {}, target→client: {}",
                    socket_addr, from_client, to_client
                );
            }
            Err(e) => {
                // surface as debug but attach context when returning
                debug!("Error during TCP communication with {}: {}", socket_addr, e);
            }
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
    retries: u32) -> std::io::Result<TcpStream> {
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

    let stream = TcpStream::from_std(socket.into())?;
    stream.writable().await?;

    if let Err(e) = stream.peer_addr() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            format!("Connect failed target:{:?} error: {}", addr, e),
        ));
    }

    Ok(stream)
}
