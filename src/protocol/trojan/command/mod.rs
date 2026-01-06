use anyhow::{Context, Result, bail};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::address::Address;
use crate::authenticate::trojan::TrojanAuthenticationManager;

const CRLF: &[u8] = b"\r\n";
const PASSWORD_HASH_LENGTH: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandType {
    Connect = 0x01,
    UdpAssociate = 0x03,
}

impl CommandType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(CommandType::Connect),
            0x03 => Ok(CommandType::UdpAssociate),
            _ => bail!("Invalid command type: 0x{:02x}", value),
        }
    }
}

impl fmt::Display for CommandType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandType::Connect => write!(f, "CONNECT"),
            CommandType::UdpAssociate => write!(f, "UDP_ASSOCIATE"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrojanRequest {
    pub command: CommandType,
    pub address: Address,
}

impl TrojanRequest {
    pub async fn read_from<R: AsyncRead + Unpin>(
        reader: &mut R,
        auth_manager: &TrojanAuthenticationManager,
    ) -> Result<Option<Self>> {
        let mut hash_buf = [0u8; PASSWORD_HASH_LENGTH];
        match reader.read_exact(&mut hash_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(e) => {
                return Err(e).context("Failed to read password hash");
            }
        }

        let received_hash =
            String::from_utf8(hash_buf.to_vec()).context("Invalid password hash encoding")?;

        let mut crlf = [0u8; 2];
        match reader.read_exact(&mut crlf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e).context("Failed to read CRLF after hash"),
        }

        if crlf != *CRLF {
            return Ok(None);
        }

        if !auth_manager.verify_password_hash(&received_hash) {
            return Ok(None);
        }

        let cmd_byte = match reader.read_u8().await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e).context("Failed to read command type"),
        };

        let command = CommandType::from_u8(cmd_byte)?;

        let address = Address::read_from(reader).await?;

        let mut end_crlf = [0u8; 2];
        match reader.read_exact(&mut end_crlf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e).context("Failed to read CRLF after request"),
        }

        if end_crlf != *CRLF {
            return Ok(None);
        }

        Ok(Some(TrojanRequest { command, address }))
    }
}

impl fmt::Display for TrojanRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TrojanRequest({} -> {})", self.command, self.address)
    }
}
