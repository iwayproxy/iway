use anyhow::{Context, Result};
use core::fmt;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::protocol::tuic::header::Header;

#[derive(Debug)]
pub struct Dissociate {
    header: Header,
    asso_id: u16,
}

impl Dissociate {
    pub async fn read_from<R>(header: Header, read: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let asso_id = read
            .read_u16()
            .await
            .context("Failed to read ASSO_ID from stream!")?;
        Ok(Self { header, asso_id })
    }

    pub fn read_from_buf<B: bytes::Buf>(header: Header, buf: &mut B) -> Result<Self> {
        if buf.remaining() < 2 {
            anyhow::bail!(
                "Not enough data to read dissociate command (need 2 bytes, have {})",
                buf.remaining()
            );
        }
        let asso_id = buf.get_u16();
        Ok(Self { header, asso_id })
    }

    pub fn assoc_id(&self) -> u16 {
        self.asso_id
    }
}

impl fmt::Display for Dissociate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Header: {} Command: Dissociate {}",
            &self.header, &self.asso_id
        )
    }
}
