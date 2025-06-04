use std::convert::TryFrom;
use std::fmt;

use anyhow::{Context, Result};
use thiserror::Error;

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum Version {
    V5 = 0x05,
}

impl Version {
    pub async fn read_from<R>(r: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let version_value = r
            .read_u8()
            .await
            .context("Failed to read version from stream")?;
        Version::try_from(version_value).context(format!(
            "Failed to parse version from value: 0x{:02X}",
            version_value
        ))
    }

    pub fn write_to<W: BufMut>(&self, w: &mut W) {
        w.put_u8((*self).into());
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::V5 => write!(f, "[Version: V5]"),
        }
    }
}

impl From<Version> for u8 {
    fn from(v: Version) -> Self {
        v as u8
    }
}

impl TryFrom<u8> for Version {
    type Error = VersionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x05 => Ok(Version::V5),
            _ => Err(VersionError::InvalidVersion(value)),
        }
    }
}

#[derive(Error, Debug)]
pub enum VersionError {
    #[error("Invalid version value found: 0x{0:02X}")]
    InvalidVersion(u8),
}
