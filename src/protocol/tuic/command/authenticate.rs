use core::fmt;

use anyhow::Result;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

use crate::protocol::tuic::header::Header;

const UUID_LEN: usize = 16;
const TOKEN_LEN: usize = 32;

#[derive(Debug)]
pub struct Authenticate {
    header: Header,
    uuid: Uuid,
    token: [u8; 32],
}

impl Authenticate {
    pub async fn read_from<R>(header: Header, read: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut uuid_buf: [u8; UUID_LEN] = [0; UUID_LEN];
        read.read(&mut uuid_buf)
            .await
            .context("Failed to read uuid from stream")?;

        let uuid = Uuid::from_bytes(uuid_buf);

        let mut token: [u8; TOKEN_LEN] = [0; TOKEN_LEN];
        read.read(&mut token)
            .await
            .context("Failed to read token(password) from stream")?;

        Ok(Self {
            header,
            uuid,
            token,
        })
    }

    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub fn token(&self) -> [u8; 32] {
        self.token
    }
}

impl fmt::Display for Authenticate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "header:{} uuid:{:?} token len: {:?}",
            self.header, self.uuid, self.token,
        )
    }
}
