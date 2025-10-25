use std::fmt;
use zeroize::Zeroize;

use anyhow::Context;
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

use crate::protocol::tuic::header::Header;

const UUID_LEN: usize = 16;
const TOKEN_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct Authenticate {
    header: Header,
    uuid: Uuid,
    token: [u8; 32],
}

impl Drop for Authenticate {
    fn drop(&mut self) {
        // zeroize the sensitive token on drop
        self.token.zeroize();
    }
}

impl Authenticate {
    pub async fn read_from<R>(header: Header, read: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut uuid_buf: [u8; UUID_LEN] = [0; UUID_LEN];
        // read_exact ensures we get the full UUID (16 bytes) or error out
        read.read_exact(&mut uuid_buf)
            .await
            .context("Failed to read uuid from stream")?;

        let uuid = Uuid::from_bytes(uuid_buf);

        let mut token: [u8; TOKEN_LEN] = [0; TOKEN_LEN];
        // token must be exactly TOKEN_LEN bytes
        read.read_exact(&mut token)
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

    // private, only used internally
    fn token(&self) -> &[u8; 32] {
        &self.token
    }

    /// Securely verify if the provided token matches this instance's token.
    /// This method should be used instead of accessing the raw token bytes.
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_token(&self, expected: &[u8; TOKEN_LEN]) -> bool {
        use subtle::ConstantTimeEq;
        // ct_eq returns Choice(1) for equality, Choice(0) for inequality
        self.token().ct_eq(expected).into()
    }
}

impl fmt::Display for Authenticate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid printing raw token bytes in logs; show header, uuid, and token length
        write!(
            f,
            "header:{} uuid:{} token_len:{}",
            self.header,
            self.uuid,
            self.token.len(),
        )
    }
}
