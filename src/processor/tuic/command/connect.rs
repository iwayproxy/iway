use anyhow::{Context as AnyhowContext, Result, bail};
use quinn::{RecvStream, SendStream};
use socket2::{Domain, Socket, Type};
use std::{net::SocketAddr, time::Duration};
use tokio::{io, net::TcpStream};
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

        let tcp_stream = match connect_with_keepalive(
            socket_addr,
            Duration::from_secs(5),
            Duration::from_secs(2),
            1,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to connect to {}, error:{}", &socket_addr, e);
                bail!("Failed to connect to {}, error:{}", &socket_addr, e);
            }
        };

        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

        let mut quic_recv = recv;
        let mut quic_send = send;

        let quic_to_tcp = async {
            let n = io::copy(&mut quic_recv, &mut tcp_write).await?;
            Ok::<_, std::io::Error>(n)
        };

        let tcp_to_quic = async {
            let n = io::copy(&mut tcp_read, &mut quic_send).await?;
            Ok::<_, std::io::Error>(n)
        };

        let result = tokio::try_join!(quic_to_tcp, tcp_to_quic);

        match result {
            Ok((from_client, to_client)) => {
                debug!(
                    "TCP connection to {} completed. Bytes: client→target: {}, target→client: {}",
                    &socket_addr, &from_client, &to_client
                );
            }
            Err(e) => {
                debug!(
                    "Error during TCP communication with {}: {}",
                    &socket_addr, e
                );
            }
        }

        Ok(())
    }
}

pub async fn connect_with_keepalive(
    addr: SocketAddr,
    _keepalive_idle: Duration,
    _keepalive_interval: Duration,
    _retries: u32,
) -> Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_linger(Some(Duration::ZERO))?;

    match socket.connect(&addr.into()) {
        Ok(_) => {}
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.raw_os_error() == Some(libc::EINPROGRESS) =>
        {
            debug!("Non-blocking connect in progress to {}", addr);
        }
        Err(err) => return Err(anyhow::Error::new(err).context("Connect failed")),
    }

    let stream = TcpStream::from_std(socket.into())?;

    stream.writable().await?;

    match stream.take_error()? {
        None => Ok(stream),
        Some(e) => Err(anyhow::Error::new(e).context("Async connect failed")),
    }
}
