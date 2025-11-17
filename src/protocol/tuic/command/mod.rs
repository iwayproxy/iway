pub mod authenticate;
pub mod command;
pub mod connect;
pub mod dissociate;
pub mod heartbeat;
pub mod packet;

use anyhow::{Context, Result};
use bytes::BufMut;
use std::{convert::TryFrom, fmt};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
#[repr(u8)]
pub enum CommandType {
    Authenticate = 0x00,
    Connect = 0x01,
    Packet = 0x02,
    Dissociate = 0x03,
    Heartbeat = 0x04,
}

impl CommandType {
    pub async fn read_from<R>(r: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let value = r
            .read_u8()
            .await
            .context("Failed to read command type from stream")?;
        CommandType::try_from(value).context(format!(
            "Failed to parse CommandType from byte: 0x{value:02x}"
        ))
    }

    pub fn write_to<W: BufMut>(&self, w: &mut W) {
        let v = match self {
            CommandType::Authenticate => 0x00,
            CommandType::Connect => 0x01,
            CommandType::Packet => 0x02,
            CommandType::Dissociate => 0x03,
            CommandType::Heartbeat => 0x04,
        };
        w.put_u8(v);
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CommandType::Authenticate => "Authenticate",
            CommandType::Connect => "Connect",
            CommandType::Packet => "Packet",
            CommandType::Dissociate => "Dissociate",
            CommandType::Heartbeat => "Heartbeat",
        }
    }
}

impl TryFrom<u8> for CommandType {
    type Error = CommandTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(CommandType::Authenticate),
            0x01 => Ok(CommandType::Connect),
            0x02 => Ok(CommandType::Packet),
            0x03 => Ok(CommandType::Dissociate),
            0x04 => Ok(CommandType::Heartbeat),
            _ => Err(CommandTypeError::UnknownCommandType(value)),
        }
    }
}

impl fmt::Display for CommandType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[Command: {}]", self.as_str())
    }
}

#[derive(Debug, Error)]
pub enum CommandTypeError {
    #[error("Unknown command type: 0x{0:02x}")]
    UnknownCommandType(u8),
}
