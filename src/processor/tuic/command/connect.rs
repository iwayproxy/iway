use anyhow::{Context as AnyhowContext, Result, bail};
use async_trait::async_trait;
use quinn::Connection;
use socket2::{Domain, Socket, TcpKeepalive, Type};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
};
use tracing::debug;

use crate::{
    processor::tuic::{CommandProcessor, context::RuntimeContext},
    protocol::tuic::command::Command,
};

pub struct ConnectProcessor {}

#[async_trait]
impl CommandProcessor for ConnectProcessor {
    async fn process(
        &self,
        context: Arc<RuntimeContext>,
        connection: Connection,
        command: Option<Command>,
    ) -> Result<bool> {
        context.wait_for_auth().await;

        match command {
            None => {}
            _ => {
                bail!("This must not happen! command: {:?}", command)
            }
        };

        while let Ok((send, mut recv)) = connection.accept_bi().await {
            let connection = connection.clone();

            let connect = match Command::read_from(&mut recv).await {
                Ok(Command::Connect(connect)) => connect,
                _ => {
                    bail!(
                        "Faile to parse command from client: {}",
                        &connection.remote_address()
                    );
                }
            };

            let exchange = async move {
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
                    let r = io::copy(&mut quic_recv, &mut tcp_write).await;
                    let _ = tcp_write.shutdown().await;
                    r
                };

                let tcp_to_quic = async {
                    let r = io::copy(&mut tcp_read, &mut quic_send).await;
                    let _ = quic_send.finish();
                    r
                };

                tokio::select! {
                    _ = quic_to_tcp => {
                        let _ = quic_send.finish();
                    }
                    _ = tcp_to_quic => {
                        let _ = tcp_write.shutdown().await;
                    }
                }

                drop(tcp_write);
                drop(tcp_read);

                anyhow::Ok(())
            };

            let _ = tokio::spawn(async { exchange.await });
        }

        Ok(false)
    }
}

pub async fn connect_with_keepalive(
    addr: SocketAddr,
    keepalive_idle: Duration,
    keepalive_interval: Duration,
    retries: u32,
) -> Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_linger(Some(Duration::ZERO))?;
    let keepalive = TcpKeepalive::new()
        .with_time(keepalive_idle)
        .with_interval(keepalive_interval)
        .with_retries(retries);
    socket.set_tcp_keepalive(&keepalive)?;

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
