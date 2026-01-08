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
    LOCAL_IPS.contains(&addr.ip())
}
