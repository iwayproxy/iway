use anyhow::{Context, Result, bail};
use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::lookup_host,
};

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
pub struct Address {
    pub addr_type: AddressType,
    pub host: String,
    pub port: u16,
}

impl Address {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let addr_type_byte = reader
            .read_u8()
            .await
            .context("Failed to read address type")?;
        let addr_type = AddressType::from_u8(addr_type_byte)?;

        let host = match addr_type {
            AddressType::IPv4 => {
                let mut buf = [0u8; 4];
                reader
                    .read_exact(&mut buf)
                    .await
                    .context("Failed to read IPv4 address")?;
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(buf)).to_string()
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
                String::from_utf8(buf).context("Invalid domain name encoding")?
            }
            AddressType::IPv6 => {
                let mut buf = [0u8; 16];
                reader
                    .read_exact(&mut buf)
                    .await
                    .context("Failed to read IPv6 address")?;
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(buf)).to_string()
            }
        };

        let port = reader.read_u16().await.context("Failed to read port")?;

        Ok(Address {
            addr_type,
            host,
            port,
        })
    }

    pub fn to_address_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub async fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match self.addr_type {
            AddressType::IPv4 => {
                let ip: Ipv4Addr = self
                    .host
                    .parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                Ok(vec![SocketAddr::new(ip.into(), self.port)])
            }
            AddressType::IPv6 => {
                let ip: Ipv6Addr = self
                    .host
                    .parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                Ok(vec![SocketAddr::new(ip.into(), self.port)])
            }
            AddressType::DomainName => {
                let addrs = lookup_host((self.host.as_str(), self.port)).await?;
                Ok(addrs.collect())
            }
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addr_type {
            AddressType::IPv4 => write!(f, "IPv4({}:{})", self.host, self.port),
            AddressType::DomainName => write!(f, "Domain({}:{})", self.host, self.port),
            AddressType::IPv6 => write!(f, "IPv6([{}]:{})", self.host, self.port),
        }
    }
}
