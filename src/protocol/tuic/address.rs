use core::str;
use std::{
    fmt::{self},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    result,
};

use anyhow::{Ok, Result, bail};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net,
};
use tracing::debug;

use super::address_type::AddressType;

type Port = u16;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    SocketAddress(SocketAddr, Bytes), //Add bytes for conversion cache, originally from client command
    DomainAddress(String, Port, Bytes), //Add bytes for conversion cache, originally from client command
    None,
}

impl Address {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match self {
            Address::SocketAddress(_, cache) => buf.put(cache.clone()),
            Address::DomainAddress(_, _, cache) => buf.put(cache.clone()),
            Address::None => buf.put_u8(0xFF),
        }
    }

    pub async fn to_socket_address(&self) -> Option<SocketAddr> {
        let socket_addr = match self {
            Address::SocketAddress(socket_addr, _) => Some(socket_addr.clone()),
            Address::DomainAddress(domain, port, _) => match self.resolve(domain, port).await {
                Result::Ok(socket_addr) => Some(socket_addr),
                Result::Err(_) => None,
            },
            Address::None => None,
        };

        let socket_addr = if is_local_addr(socket_addr).await {
            let socket_addr = if let Some(addr) = socket_addr {
                let addr = match addr {
                    SocketAddr::V4(_) => {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
                    }
                    SocketAddr::V6(_) => {
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
                    }
                };
                debug!("Using local address for socket: {:?}", addr);
                Some(addr)
            } else {
                unreachable!("Socket address should not be None if is_local_addr is true");
            };
            socket_addr
        } else {
            socket_addr
        };

        debug!("Resolved address to {:?}", socket_addr);
        socket_addr
    }

    async fn resolve(&self, domain: &String, port: &Port) -> Result<SocketAddr> {
        let mut addr_itr = net::lookup_host(format!("{}:{}", domain, port)).await?;
        let Some(addr) = addr_itr.next() else {
            bail!("Failed to resolve address: {}", domain);
        };
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

                let mut cache = BytesMut::with_capacity(1 + 1 + len as usize + 2);
                cache.put_u8(address_type as u8);
                cache.put_u8(len);

                let mut domain_bytes = vec![0u8; len as usize];
                read.read_exact(&mut domain_bytes).await?;
                cache.put_slice(&domain_bytes);

                let address = str::from_utf8(&domain_bytes)?.to_string();

                let port = read.read_u16().await?;
                cache.put_u16(port);

                Ok(Address::DomainAddress(address, port, cache.freeze()))
            }
            AddressType::IpV4 => {
                let mut cache = BytesMut::with_capacity(1 + 4 + 2);
                cache.put_u8(address_type as u8);

                let ip_value = read.read_u32().await?;
                cache.put_u32(ip_value);

                let port = read.read_u16().await?;
                cache.put_u16(port);

                let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_value)), port);
                Ok(Address::SocketAddress(socket_addr, cache.freeze()))
            }
            AddressType::IpV6 => {
                let mut cache = BytesMut::with_capacity(1 + 16 + 2);
                cache.put_u8(address_type.to_byte());

                let ip_value = read.read_u128().await?;
                cache.put_u128(ip_value);

                let port = read.read_u16().await?;
                cache.put_u16(port);

                let socket_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_value)), port);
                Ok(Address::SocketAddress(socket_addr, cache.freeze()))
            }
            AddressType::None => Ok(Address::None),
        }
    }

    pub fn to_owned(&self) -> Self {
        match self {
            Address::SocketAddress(addr, cache) => Address::SocketAddress(*addr, cache.clone()),
            Address::DomainAddress(domain, port, cache) => {
                Address::DomainAddress(domain.clone(), *port, cache.clone())
            }
            Address::None => Address::None,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DomainAddress(addr, port, cache) => write!(f, "{addr}:{port} bin:{:?}", cache),
            Self::SocketAddress(socket_addr, cache) => write!(f, "{socket_addr} bin:{:?}", cache),
            Self::None => write!(f, "None"),
        }
    }
}

impl AddressType {
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

use get_if_addrs::get_if_addrs;
use once_cell::sync::Lazy;
use std::collections::HashSet;

static LOCAL_IPS: Lazy<HashSet<IpAddr>> = Lazy::new(|| {
    let mut set = HashSet::new();

    if let result::Result::Ok(ifaces) = get_if_addrs() {
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
