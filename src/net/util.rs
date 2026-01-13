use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::result;

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

pub fn is_local_addr(addr: &SocketAddr) -> bool {
    let ip = addr.ip();

    // Quick accept for loopback addresses
    if ip.is_loopback() {
        return true;
    }

    match ip {
        IpAddr::V4(_) => LOCAL_IPS.contains(&ip),
        IpAddr::V6(v6) => {
            // Direct IPv6 match
            if LOCAL_IPS.contains(&IpAddr::V6(v6)) {
                return true;
            }

            // If this is an IPv4-mapped IPv6 address, check the mapped IPv4
            if let Some(v4) = v6.to_ipv4() {
                return LOCAL_IPS.contains(&IpAddr::V4(v4));
            }

            false
        }
    }
}
