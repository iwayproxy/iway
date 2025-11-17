use anyhow::{Context, Result};
use std::fmt;

use bytes::BufMut;
use tokio::io::AsyncRead;

use super::{command::CommandType, version::Version};

#[derive(Debug)]
pub struct Header {
    version: Version,
    command_type: CommandType,
}
impl Header {
    pub fn new(command_type: CommandType) -> Self {
        Self {
            version: Version::V5,
            command_type,
        }
    }

    pub fn command_type(&self) -> &CommandType {
        &self.command_type
    }

    pub fn write_to<W: BufMut>(&self, w: &mut W) {
        self.version.write_to(w);
        self.command_type.write_to(w);
    }

    pub async fn read_from<R>(mut read: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let version = Version::read_from(&mut read)
            .await
            .context("Failed to parse version!")?;
        let command_type = CommandType::read_from(&mut read)
            .await
            .context("Failed to parse command type")?;

        Ok(Self {
            version,
            command_type,
        })
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.version, self.command_type)
    }
}
