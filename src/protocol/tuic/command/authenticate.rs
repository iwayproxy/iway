use std::fmt;
use zeroize::Zeroize;

use anyhow::Context;
use anyhow::Result;
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

impl Drop for Authenticate {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl Authenticate {
    pub async fn read_from<R>(header: Header, read: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut uuid_buf: [u8; UUID_LEN] = [0; UUID_LEN];

        read.read_exact(&mut uuid_buf)
            .await
            .context("Failed to read uuid from stream")?;

        let uuid = Uuid::from_bytes(uuid_buf);

        let mut token: [u8; TOKEN_LEN] = [0; TOKEN_LEN];

        read.read_exact(&mut token)
            .await
            .context("Failed to read token(password) from stream")?;

        Ok(Self {
            header,
            uuid,
            token,
        })
    }

    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    pub fn verify_token(&self, expected: &[u8; TOKEN_LEN]) -> Result<bool> {
        use subtle::ConstantTimeEq;
        Ok(self.token.ct_eq(expected).into())
    }
}

impl fmt::Display for Authenticate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "header:{} uuid:{} token_len:{}",
            &self.header,
            &self.uuid,
            &self.token.len(),
        )
    }
}
