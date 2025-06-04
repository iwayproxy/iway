use anyhow::Result;
use core::fmt;

use tokio::io::AsyncRead;

use crate::protocol::tuic::header::Header;

#[derive(Debug)]
pub struct Heartbeat {
    header: Header,
}

impl Heartbeat {
    pub async fn read_from<R>(header: Header, mut _read: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        Ok(Self { header })
    }
}

impl fmt::Display for Heartbeat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Command: Heartbeat {}", self.header)
    }
}
