use std::{collections::HashMap, sync::Arc};

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use tokio::net::UdpSocket;

use crate::protocol::tuic::{address::Address, command::packet::Packet};

#[derive(Clone)]
pub struct UdpSession {
    inner: Arc<UdpSessionInner>,
}

pub struct UdpSessionInner {
    pakets: RwLock<HashMap<u16, FragmentedPacket>>,
    address: RwLock<Option<Arc<Address>>>,
}

pub struct FragmentedPacket {
    fragment_count: u8,
    received_bitmap: u128,
    received: Vec<Option<Bytes>>,
}

impl Default for UdpSession {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpSession {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(UdpSessionInner {
                pakets: RwLock::new(HashMap::new()),
                address: RwLock::new(None),
            }),
        }
    }

    pub fn get_address(&self) -> Option<Arc<Address>> {
        self.inner.address.read().as_ref().map(Arc::clone)
    }

    pub fn set_address(&self, addr: Arc<Address>) {
        *self.inner.address.write() = Some(addr);
    }

    pub async fn send_and_recv(
        &self,
        remote_addr: std::net::SocketAddr,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let bind_addr = match remote_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr).await?;

        socket.send_to(data, remote_addr).await?;

        let mut buf = vec![0u8; 4096];

        loop {
            let (n, _) = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                socket.recv_from(&mut buf),
            )
            .await??;

            if n == buf.len() && buf.len() < 65535 {
                buf.resize(buf.len() * 2, 0);
                continue;
            }

            buf.truncate(n);
            return Ok(buf);
        }
    }

    pub async fn close_socket(&self) {}

    pub fn accept(&self, packet: Packet) -> Option<u16> {
        if !matches!(*packet.address, Address::None) {
            self.set_address(Arc::clone(&packet.address));
        }

        let mut packets = self.inner.pakets.write();

        match packets.get_mut(&packet.pkt_id) {
            Some(frag_pkt) => {
                let bit = 1u128 << packet.frag_id;

                if (frag_pkt.received_bitmap & bit) == 0 {
                    frag_pkt.received[packet.frag_id as usize] = Some(packet.payload);
                    frag_pkt.received_bitmap |= bit;
                }

                if frag_pkt.received_bitmap.count_ones() as u8 == frag_pkt.fragment_count {
                    return Some(packet.pkt_id);
                }

                None
            }
            None => {
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
            if frag_pkt.received.is_empty() {
                return None;
            }

            if frag_pkt.received.len() == 1 {
                if let Some(bytes) = frag_pkt.received.into_iter().next().unwrap() {
                    return Some(bytes);
                }
                return None;
            }

            let total_size: usize = frag_pkt
                .received
                .iter()
                .filter_map(|b| b.as_ref().map(|x| x.len()))
                .sum();

            let mut assembled = BytesMut::with_capacity(total_size);
            for bytes in frag_pkt.received.into_iter().flatten() {
                assembled.extend_from_slice(&bytes);
            }
            Some(assembled.freeze())
        } else {
            None
        }
    }
}
