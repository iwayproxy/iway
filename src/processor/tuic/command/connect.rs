use crate::net::tcp as net_tcp;
use anyhow::{Context as AnyhowContext, Result, bail};
use async_trait::async_trait;
use quinn::Connection;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        connection: Arc<Connection>,
        command: Option<Command>,
    ) -> Result<bool> {
        let auth_result = context.wait_for_auth().await;
        if auth_result != Some(true) {
            bail!("Authentication failed or timed out");
        }

        match command {
            None => {}
            _ => {
                bail!("This must not happen! command: {:?}", command)
            }
        };

        while let Ok((send, mut recv)) = connection.accept_bi().await {
            let connection = Arc::clone(&connection);

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

                let tcp_stream = match net_tcp::connect(socket_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("Failed to connect to {}, error:{}", &socket_addr, e);
                        bail!("Failed to connect to {}, error:{}", &socket_addr, e);
                    }
                };

                let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

                let mut quic_recv = recv;
                let mut quic_send = send;

                let mut quic_to_tcp = Box::pin(async {
                    let r = copy_with_buf(&mut quic_recv, &mut tcp_write, 16 * 1024).await;
                    let _ = tcp_write.shutdown().await;
                    r
                });

                let mut tcp_to_quic = Box::pin(async {
                    let r = copy_with_buf(&mut tcp_read, &mut quic_send, 16 * 1024).await;
                    let _ = quic_send.finish();
                    r
                });

                let _first = tokio::select! {
                    r = &mut quic_to_tcp => (Some(r), None),
                    r = &mut tcp_to_quic => (None, Some(r)),
                };

                // let (_r1, _r2) = match first {
                //     (Some(r1), None) => {
                //         let r2 = tcp_to_quic.await;
                //         (r1?, r2?)
                //     }
                //     (None, Some(r2)) => {
                //         let r1 = quic_to_tcp.await;
                //         (r1?, r2?)
                //     }
                //     _ => unreachable!(),
                // };

                anyhow::Ok(())
            };

            std::mem::drop(tokio::spawn(exchange));
        }

        Ok(false)
    }
}

pub async fn copy_with_buf<R, W>(
    mut reader: R,
    mut writer: W,
    buf_size: usize,
) -> std::io::Result<u64>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = bytes::BytesMut::with_capacity(buf_size);
    let mut total = 0;

    loop {
        let n = reader.read_buf(&mut buf).await?;
        if n == 0 {
            break;
        }

        writer.write_all(&buf).await?;
        buf.clear();
        total += n as u64;
    }

    Ok(total)
}
