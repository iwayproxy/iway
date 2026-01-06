use core::str;
use std::{
    fmt::{self},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    result,
};

use anyhow::{Context, Ok, Result, bail};
use bytes::{BufMut, Bytes, BytesMut};
use once_cell::sync::Lazy;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;

use super::dns_cache::DnsResolver;

type Port = u16;

static GLOBAL_DNS_RESOLVER: Lazy<DnsResolver> = Lazy::new(|| DnsResolver::with_config(2000, 300));

#[derive(Debug)]
pub enum Address {
    Socket(SocketAddr, Bytes),
    Domain(String, Port, Bytes),
    None,
}

impl Address {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match self {
            Address::Socket(_, cache) => buf.put(cache.as_ref()),
            Address::Domain(_, _, cache) => buf.put(cache.as_ref()),
            Address::None => buf.put_u8(0xFF),
        }
    }

    pub async fn to_socket_address(&self) -> Option<SocketAddr> {
        let socket_addr = match self {
            Address::Socket(socket_addr, _) => Some(*socket_addr),
            Address::Domain(domain, port, _) => (self.resolve(domain, port).await).ok(),
            Address::None => None,
        };

        let socket_addr = if is_local_addr(socket_addr).await {
            if let Some(addr) = socket_addr {
                let addr = match addr {
                    SocketAddr::V4(_) => {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
                    }
                    SocketAddr::V6(_) => {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
                    }
                };
                if tracing::enabled!(tracing::Level::DEBUG) {
                    debug!("Using local address for socket: {:?}", addr);
                }
                Some(addr)
            } else {
                unreachable!("Socket address should not be None if is_local_addr is true");
            }
        } else {
            socket_addr
        };

        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!("Resolved address to {:?}", socket_addr);
        }
        socket_addr
    }

    async fn resolve(&self, domain: &str, port: &Port) -> Result<SocketAddr> {
        GLOBAL_DNS_RESOLVER.resolve(domain, *port).await
    }

    pub async fn read_from<R>(read: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let address_type = AddressType::read_from(read).await?;

        match address_type {
            AddressType::Domain => {
                let len = read.read_u8().await?;

                let mut cache = BytesMut::with_capacity(1 + 1 + len as usize + 2);
                cache.put_u8(address_type as u8);
                cache.put_u8(len);

                let mut domain_buf = BytesMut::with_capacity(len as usize);
                domain_buf.resize(len as usize, 0);
                read.read_exact(&mut domain_buf).await?;

                let address = String::from_utf8(domain_buf.to_vec())?;
                cache.put_slice(&domain_buf);

                let port = read.read_u16().await?;
                cache.put_u16(port);

                Ok(Address::Domain(address, port, cache.freeze()))
            }
            AddressType::IpV4 => {
                let mut cache = BytesMut::with_capacity(1 + 4 + 2);
                cache.put_u8(address_type as u8);

                let ip_value = read.read_u32().await?;
                cache.put_u32(ip_value);

                let port = read.read_u16().await?;
                cache.put_u16(port);

                let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_value)), port);
                Ok(Address::Socket(socket_addr, cache.freeze()))
            }
            AddressType::IpV6 => {
                let mut cache = BytesMut::with_capacity(1 + 16 + 2);
                cache.put_u8(address_type.to_byte());

                let ip_value = read.read_u128().await?;
                cache.put_u128(ip_value);

                let port = read.read_u16().await?;
                cache.put_u16(port);

                let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_value)), port);
                Ok(Address::Socket(socket_addr, cache.freeze()))
            }
            AddressType::None => Ok(Address::None),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(addr, port, cache) => write!(f, "{addr}:{port} bin:{:?}", cache),
            Self::Socket(socket_addr, cache) => write!(f, "{socket_addr} bin:{:?}", cache),
            Self::None => write!(f, "None"),
        }
    }
}

impl AddressType {
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

use std::collections::HashSet;

static LOCAL_IPS: Lazy<HashSet<IpAddr>> = Lazy::new(|| {
    let mut set = HashSet::new();

    if let result::Result::Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            set.insert(iface.ip());
        }
    }

    set.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    set.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

    set
});

pub async fn is_local_addr(addr: Option<SocketAddr>) -> bool {
    let Some(addr) = addr else {
        return false;
    };

    LOCAL_IPS.contains(&addr.ip())
}

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
            Address::Socket(socket_address, _) => match socket_address {
                SocketAddr::V4(_) => AddressType::IpV4,
                SocketAddr::V6(_) => AddressType::IpV6,
            },
            Address::Domain(_, _, _) => AddressType::Domain,
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
