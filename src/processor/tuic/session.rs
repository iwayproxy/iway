use std::{collections::HashMap, sync::Arc};

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use tokio::net::UdpSocket;

use crate::protocol::tuic::command::packet::Packet;

#[derive(Clone)]
pub struct UdpSession {
    inner: Arc<UdpSessionInner>,
}

pub struct UdpSessionInner {
    pakets: RwLock<HashMap<u16, FragmentedPacket>>,
}

pub struct FragmentedPacket {
    fragment_count: u8,
    received_bitmap: u128,
    received: Vec<Option<Bytes>>,
}

impl UdpSession {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(UdpSessionInner {
                pakets: RwLock::new(HashMap::new()),
            }),
        }
    }

    pub async fn send_and_recv(
        &self,
        remote_addr: std::net::SocketAddr,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        // Create a new socket for each request (don't reuse)
        let bind_addr = match remote_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr).await?;

        // Send data
        socket.send_to(data, remote_addr).await?;

        // Receive response with timeout
        let mut buf = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            socket.recv_from(&mut buf),
        )
        .await??;

        buf.truncate(n);
        Ok(buf)
    }

    pub async fn close_socket(&self) {
        // Socket is no longer stored, nothing to clean up
        // Sockets are created and destroyed per request
    }

    pub fn accept(&self, packet: Packet) -> Option<u16> {
        // Single fragment never goes here
        let mut packets = self.inner.pakets.write();

        match packets.get_mut(&packet.pkt_id) {
            Some(frag_pkt) => {
                // Packet already exists — mark this fragment as received
                if (packet.frag_id as usize) < frag_pkt.received.len() {
                    let bit = 1u128 << packet.frag_id;

                    // Only store if not already received
                    if (frag_pkt.received_bitmap & bit) == 0 {
                        frag_pkt.received[packet.frag_id as usize] = Some(packet.payload);
                        frag_pkt.received_bitmap |= bit;
                    }
                }

                // Check if all fragments received using bitmap
                if frag_pkt.received_bitmap.count_ones() as u8 == frag_pkt.fragment_count {
                    return Some(packet.pkt_id);
                }

                None
            }
            None => {
                // New fragmented packet — create entry
                let mut received = vec![None; packet.frag_total as usize];
                received[packet.frag_id as usize] = Some(packet.payload);

                let bit = 1u128 << packet.frag_id;

                packets.insert(
                    packet.pkt_id,
                    FragmentedPacket {
                        fragment_count: packet.frag_total,
                        received_bitmap: bit,
                        received,
                    },
                );

                None
            }
        }
    }

    pub fn take_fragmented_packet(&self, pkt_id: u16) -> Option<Bytes> {
        let mut packets = self.inner.pakets.write();
        if let Some(frag_pkt) = packets.remove(&pkt_id) {
            // Assemble all fragments into one payload
            let mut assembled = BytesMut::new();
            for opt_bytes in frag_pkt.received {
                if let Some(bytes) = opt_bytes {
                    assembled.extend_from_slice(&bytes);
                }
            }
            Some(assembled.freeze())
        } else {
            None
        }
    }
}
