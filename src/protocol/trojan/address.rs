use anyhow::{Context, Result, anyhow, bail};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::lookup_host,
};

use crate::net::util::is_local_addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 0x01,
    DomainName = 0x03,
    IPv6 = 0x04,
}

impl AddressType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(AddressType::IPv4),
            0x03 => Ok(AddressType::DomainName),
            0x04 => Ok(AddressType::IPv6),
            _ => bail!("Invalid address type: 0x{:02x}", value),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Address {
    Socket(std::net::SocketAddr),
    Domain(String, u16),
}

impl Address {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let addr_type_byte = reader
            .read_u8()
            .await
            .context("Failed to read address type")?;
        let addr_type = AddressType::from_u8(addr_type_byte)?;
        let address = match addr_type {
            AddressType::IPv4 => {
                let mut buf = [0u8; 4];
                reader
                    .read_exact(&mut buf)
                    .await
                    .context("Failed to read IPv4 address")?;
                let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(buf));
                let port = reader.read_u16().await.context("Failed to read port")?;
                Address::Socket(std::net::SocketAddr::new(ip, port))
            }
            AddressType::DomainName => {
                let len = reader
                    .read_u8()
                    .await
                    .context("Failed to read domain name length")?;
                let mut buf = vec![0u8; len as usize];
                reader
                    .read_exact(&mut buf)
                    .await
                    .context("Failed to read domain name")?;
                let domain = String::from_utf8(buf).context("Invalid domain name encoding")?;
                let port = reader.read_u16().await.context("Failed to read port")?;
                Address::Domain(domain, port)
            }
            AddressType::IPv6 => {
                let mut buf = [0u8; 16];
                reader
                    .read_exact(&mut buf)
                    .await
                    .context("Failed to read IPv6 address")?;
                let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(buf));
                let port = reader.read_u16().await.context("Failed to read port")?;
                Address::Socket(std::net::SocketAddr::new(ip, port))
            }
        };

        Ok(address)
    }

    pub async fn to_socket_addrs(&self) -> Result<SocketAddr> {
        let mut sa = match self {
            Address::Socket(sa) => Ok(*sa),
            Address::Domain(domain, port) => {
                let mut addrs = lookup_host((domain.as_str(), *port)).await?;
                addrs.next().ok_or_else(|| anyhow!("no addresses found"))
            }
        }?;

        if is_local_addr(&sa) {
            sa = match sa.ip() {
                std::net::IpAddr::V4(_) => {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), sa.port())
                }
                std::net::IpAddr::V6(_) => {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), sa.port())
                }
            };
        }

        Ok(sa)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Socket(sa) => write!(f, "{}", sa),
            Address::Domain(d, p) => write!(f, "{}:{}", d, p),
        }
    }
}
