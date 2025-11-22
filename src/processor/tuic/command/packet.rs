use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use tokio::time::timeout;

use crate::processor::tuic::udp_session_manager::{UdpFragment, UdpSessionManager};
use crate::protocol::tuic::address::Address;
use crate::protocol::tuic::command::packet::Packet;
use bytes::BytesMut;
use quinn::Connection;
use tokio::net::UdpSocket;
use tracing::debug;

const UDP_BUFFER_SIZE: usize = 2048;

pub struct PacketProcessor {
    udp_session_manager: Arc<UdpSessionManager>,
}

impl PacketProcessor {
    pub fn new(udp_session_manager: Arc<UdpSessionManager>) -> Self {
        Self {
            udp_session_manager,
        }
    }

    pub async fn process(&self, connection: Connection, packet: Packet) -> Result<()> {
        let fragment = UdpFragment::from_packet(&packet);

        if let Some(reassembled) = &self
            .udp_session_manager
            .receive_fragment(fragment, connection.remote_address())
        {
            let dest_addr = packet.address;

            let response = send_and_receive(&dest_addr, &reassembled)
                .await
                .context("Failed to send and receive UDP packet")?;

            let assoc_id = packet.assoc_id;
            let pkt_id = packet.pkt_id;
            let packets = Packet::get_packets_from(&response, assoc_id, pkt_id, &dest_addr);
            if packets.is_empty() {
                bail!("No data packet is present at the moment.");
            }

            for packet in packets {
                let mut bytes = BytesMut::with_capacity(UDP_BUFFER_SIZE);
                packet.write_to_buf(&mut bytes);
                connection.send_datagram(bytes.freeze()).context(format!(
                    "Failed to send data to client: {}",
                    connection.remote_address()
                ))?;
            }
            debug!(
                "✅ Successfully processed UDP packet, dest: {} size: {}",
                dest_addr,
                response.len()
            );
        }

        Ok(())
    }
}

async fn send_and_receive(dest: &Address, data: &[u8]) -> Result<Vec<u8>> {
    let Some(dest_socket_addr) = dest.to_socket_address().await else {
        bail!("Failed to resolve address to dest socket address {}", dest);
    };

    let bind_addr = match dest_socket_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    let socket = UdpSocket::bind(bind_addr).await?;

    let sent = socket.send_to(data, dest_socket_addr).await?;
    debug!("Has sent {} data to {}", sent, dest_socket_addr);

    let mut all_packets = vec![0];
    let mut buf = vec![0u8; 4 * 1024];

    loop {
        let n = {
            match timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
                Ok(Ok((n, _addr))) => Some(n),
                Ok(Err(e)) => {
                    debug!("Error while receiving from socket: {}", e);
                    None
                }
                Err(_) => {
                    debug!("Timed out waiting for socket to receive data");
                    None
                }
            }
        };

        match n {
            Some(n) => {
                all_packets.extend_from_slice(&buf[..n]);
            }
            None => {
                break;
            }
        }
    }

    Ok(all_packets)
}
