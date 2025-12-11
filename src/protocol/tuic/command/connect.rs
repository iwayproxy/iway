use core::fmt;

use anyhow::{Context, Result};

use tokio::io::AsyncRead;

use crate::protocol::tuic::{address::Address, header::Header};

#[derive(Debug)]
pub struct Connect {
    header: Header,
    address: Address,
}

impl Connect {
    pub fn address(&self) -> &Address {
        &self.address
    }

    pub async fn read_from<R>(header: Header, mut read: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let address: Address = Address::read_from(&mut read)
            .await
            .context("Failed to parse Address from stream.")?;
        Ok(Self { header, address })
    }

    pub fn read_from_buf<B: bytes::Buf>(header: Header, buf: &mut B) -> Result<Self> {
        let address: Address =
            Address::read_from_buf(buf).context("Failed to parse Address from buffer")?;
        Ok(Self { header, address })
    }
}

impl fmt::Display for Connect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "header:{} address:{}", &self.header, &self.address)
    }
}
