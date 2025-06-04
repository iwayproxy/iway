use std::{fmt, net::SocketAddr};

use anyhow::{Context, Result};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::address::Address;

#[derive(Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AddressType {
    Domain = 0x00,
    IpV4 = 0x01,
    IpV6 = 0x02,
    None = 0xFF,
}

impl AddressType {
    pub async fn read_from<R>(r: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let value: u8 = r
            .read_u8()
            .await
            .context("failed to read address type from stream")?;
        AddressType::try_from(value).map_err(Into::into)
    }

    pub async fn from_address(value: Address) -> Self {
        let address_type = match value {
            Address::SocketAddress(socket_address, _) => match socket_address {
                SocketAddr::V4(_) => AddressType::IpV4,
                SocketAddr::V6(_) => AddressType::IpV6,
            },
            Address::DomainAddress(_, _, _) => AddressType::Domain,
            Address::None => AddressType::None,
        };
        address_type
    }
}

impl TryFrom<u8> for AddressType {
    type Error = AddressTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(AddressType::Domain),
            0x01 => Ok(AddressType::IpV4),
            0x02 => Ok(AddressType::IpV6),
            0xFF => Ok(AddressType::None),
            _ => Err(AddressTypeError::InvalidAddressType(value)),
        }
    }
}

impl From<AddressType> for u8 {
    fn from(v: AddressType) -> Self {
        v as u8
    }
}

#[derive(Error, Debug)]
pub enum AddressTypeError {
    #[error("Invalid address type value found: 0x{0:02X}")]
    InvalidAddressType(u8),
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressType::Domain => write!(f, "{}", "Domain"),
            AddressType::IpV4 => write!(f, "{}", "IpV4"),
            AddressType::IpV6 => write!(f, "{}", "IpV6"),
            AddressType::None => write!(f, "{}", "None"),
        }
    }
}
