use core::str;
use std::{
    fmt::{self},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    result,
};

use anyhow::{Context, Ok, Result, bail};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;

use crate::net::util::is_local_addr;

type Port = u16;

#[derive(Debug)]
pub enum Address {
    Socket(SocketAddr),
    Domain(String, Port),
    None,
}

impl Address {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match self {
            Address::Socket(socket_addr) => match socket_addr {
                SocketAddr::V4(v4) => {
                    buf.put_u8(AddressType::IpV4 as u8);
                    let octets = v4.ip().octets();
                    buf.put_slice(&octets);
                    buf.put_u16(v4.port());
                }
                SocketAddr::V6(v6) => {
                    buf.put_u8(AddressType::IpV6 as u8);
                    let segments = v6.ip().octets();
                    buf.put_slice(&segments);
                    buf.put_u16(v6.port());
                }
            },
            Address::Domain(domain, port) => {
                buf.put_u8(AddressType::Domain as u8);
                let domain_bytes = domain.as_bytes();
                buf.put_u8(domain_bytes.len() as u8);
                buf.put_slice(domain_bytes);
                buf.put_u16(*port);
            }
            Address::None => buf.put_u8(AddressType::None as u8),
        }
    }

    pub async fn to_socket_address(&self) -> Option<SocketAddr> {
        let socket_addr = match self {
            Address::Socket(socket_addr) => Some(*socket_addr),
            Address::Domain(domain, port) => (self.resolve(domain, port).await).ok(),
            Address::None => None,
        };

        let socket_addr = if let Some(addr) = socket_addr {
            if is_local_addr(&addr) {
                let local = match addr {
                    SocketAddr::V4(_) => {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
                    }
                    SocketAddr::V6(_) => {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
                    }
                };
                if tracing::enabled!(tracing::Level::DEBUG) {
                    debug!("Using local address for socket: {:?}", local);
                }
                Some(local)
            } else {
                Some(addr)
            }
        } else {
            None
        };

        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!("Resolved address to {:?}", socket_addr);
        }
        socket_addr
    }

    async fn resolve(&self, domain: &str, port: &Port) -> Result<SocketAddr> {
        let query_host = format!("{}:{}", domain, port);
        let mut addr_itr = tokio::net::lookup_host(&query_host).await?;

        let addr = addr_itr
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve address: {}", domain))?;

        Ok(addr)
    }

    pub async fn read_from<R>(read: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let address_type = AddressType::read_from(read).await?;

        match address_type {
            AddressType::Domain => {
                let len = read.read_u8().await?;

                let mut domain_buf = BytesMut::with_capacity(len as usize);
                domain_buf.resize(len as usize, 0);
                read.read_exact(&mut domain_buf).await?;

                let address = String::from_utf8(domain_buf.to_vec())?;

                let port = read.read_u16().await?;

                Ok(Address::Domain(address, port))
            }
            AddressType::IpV4 => {
                let ip_value = read.read_u32().await?;

                let port = read.read_u16().await?;

                let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_value)), port);
                Ok(Address::Socket(socket_addr))
            }
            AddressType::IpV6 => {
                let ip_value = read.read_u128().await?;

                let port = read.read_u16().await?;

                let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_value)), port);
                Ok(Address::Socket(socket_addr))
            }
            AddressType::None => Ok(Address::None),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(addr, port) => write!(f, "{addr}:{port}"),
            Self::Socket(socket_addr) => write!(f, "{socket_addr}"),
            Self::None => write!(f, "None"),
        }
    }
}

impl AddressType {
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

// local ip utilities are provided by `crate::net::util`

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
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
        AddressType::try_from(value)
    }

    pub async fn from_address(value: Address) -> Self {
        match value {
            Address::Socket(socket_address) => match socket_address {
                SocketAddr::V4(_) => AddressType::IpV4,
                SocketAddr::V6(_) => AddressType::IpV6,
            },
            Address::Domain(_, _) => AddressType::Domain,
            Address::None => AddressType::None,
        }
    }
}

impl TryFrom<u8> for AddressType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(AddressType::Domain),
            0x01 => Ok(AddressType::IpV4),
            0x02 => Ok(AddressType::IpV6),
            0xFF => Ok(AddressType::None),
            _ => bail!(
                "Try to convert Address Type from invalid address type value: {}!",
                value
            ),
        }
    }
}

impl From<AddressType> for u8 {
    fn from(v: AddressType) -> Self {
        v as u8
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressType::Domain => write!(f, "Domain"),
            AddressType::IpV4 => write!(f, "IpV4"),
            AddressType::IpV6 => write!(f, "IpV6"),
            AddressType::None => write!(f, "None"),
        }
    }
}
