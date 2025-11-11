use anyhow::{Context, Result};

use bytes::{BufMut, Bytes, BytesMut};
use std::fmt::Display;

use crate::protocol::tuic::{address::Address, header::Header};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::command_type::CommandType;

const MAX_PAYLOAD_PER_PACKET: usize = 1200;

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub assoc_id: u16,
    pub pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub size: u16,
    pub address: Address,
    pub payload: Bytes,
}

impl Packet {
    pub fn get_packets_from(
        full_payload: &[u8],
        assoc_id: u16,
        pkt_id: u16,
        address: Address,
    ) -> Vec<Packet> {
        let mut packets = Vec::new();
        let total_len = full_payload.len();
        let frag_total = ((total_len + MAX_PAYLOAD_PER_PACKET - 1) / MAX_PAYLOAD_PER_PACKET) as u8;

        for (frag_id, chunk) in full_payload.chunks(MAX_PAYLOAD_PER_PACKET).enumerate() {
            packets.push(Packet {
                header: Header::new(CommandType::Packet),
                assoc_id,
                pkt_id,
                frag_total,
                frag_id: frag_id as u8,
                size: chunk.len() as u16,
                address: address.clone(),
                payload: BytesMut::from(chunk).freeze(),
            });
        }

        packets
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        self.header.write_to(buf);
        buf.put_u16(self.assoc_id);
        buf.put_u16(self.pkt_id);
        buf.put_u8(self.frag_total);
        buf.put_u8(self.frag_id);
        buf.put_u16(self.size);
        self.address.write_to_buf(buf);
        buf.put_slice(&self.payload);
    }

    pub async fn read_from<R>(header: Header, r: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let assoc_id = r
            .read_u16()
            .await
            .context("Failed to read ASSOC_ID from stream!")?;
        let pkt_id = r
            .read_u16()
            .await
            .context("Failed to read PKT_ID from stream!")?;
        let frag_total = r
            .read_u8()
            .await
            .context("Failed to read FRAG_TOTAL from stream!")?;
        let frag_id = r
            .read_u8()
            .await
            .context("Failed to read FRAG_ID from stream!")?;
        let size = r
            .read_u16()
            .await
            .context("Failed to read size from stream")?;
        let address = Address::read_from(r).await?;

        let mut payload_vec = vec![0u8; size as usize];
        r.read_exact(&mut payload_vec)
            .await
            .context("Failed to read payload from stream")?;
        let payload = Bytes::from(payload_vec);

        Ok(Self {
            header,
            assoc_id,
            pkt_id,
            frag_total,
            frag_id,
            size,
            address,
            payload,
        })
    }
}

impl Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Header: {} [assoc_id: {} pkt_id: {} frag_total: {} frag_id:{} size: {} addr: {} data_size: {}]",
            self.header,
            self.assoc_id,
            self.pkt_id,
            self.frag_total,
            self.frag_id,
            self.size,
            self.address,
            self.payload.len()
        )
    }
}
