use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use tokio::time::timeout;

use super::Processor;
use crate::processor::tuic::udp_session_manager::{UdpFragment, UdpSessionManager};
use crate::protocol::tuic::address::Address;
use crate::protocol::tuic::command::packet::Packet;
use async_trait::async_trait;
use bytes::BytesMut;
use log::debug;
use quinn::Connection;
use tokio::net::UdpSocket;

const UDP_BUFFER_SIZE: usize = 2048;

pub struct PacketProcessor {
    pub packet: Packet,
    udp_session_manager: Arc<UdpSessionManager>,
    connection: Arc<Connection>,
}

impl PacketProcessor {
    pub fn new(
        packet: Packet,
        udp_session_manager: Arc<UdpSessionManager>,
        connection: Arc<Connection>,
    ) -> Self {
        Self {
            packet,
            udp_session_manager,
            connection,
        }
    }

    pub async fn send_and_receive(&mut self, dest: Address, data: &[u8]) -> Result<Vec<u8>> {
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

        let mut all_packets = Vec::new();
        let mut buf = vec![0u8; 65536];

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
}

#[async_trait]
impl Processor for PacketProcessor {
    async fn process(&mut self) -> Result<()> {
        let dest_addr = self.packet.address.clone();
        let fragment = UdpFragment::from_packet(&self.packet);

        let udp_session_manager = self.udp_session_manager.clone();
        let connection = self.connection.clone();
        let packet = self.packet.clone();

        let fut = async move {
            if let Some(reassembled) =
                udp_session_manager.receive_fragment(fragment, connection.remote_address())
            {
                let connection_for_processor = connection.clone();
                let response = PacketProcessor::new(
                    packet.clone(),
                    udp_session_manager,
                    connection_for_processor,
                )
                .send_and_receive(dest_addr.clone(), &reassembled)
                .await
                .context("Failed to send and receive UDP packet")?;

                let assoc_id = packet.assoc_id;
                let pkt_id = packet.pkt_id;
                let packets =
                    Packet::get_packets_from(&response, assoc_id, pkt_id, dest_addr.clone());
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
        };

        tokio::spawn(fut);

        Ok(())
    }
}
