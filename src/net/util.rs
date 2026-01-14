use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::result;
use std::sync::Arc;
use std::time::Duration;

fn build_local_ips() -> HashSet<IpAddr> {
    let mut set = HashSet::new();

    if let result::Result::Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            set.insert(iface.ip());
        }
    }

    set.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    set.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

    set
}

static LOCAL_IPS: Lazy<Arc<ArcSwap<HashSet<IpAddr>>>> = Lazy::new(|| {
    let swap = Arc::new(ArcSwap::from_pointee(build_local_ips()));
    let thread_swap = Arc::clone(&swap);

    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(5));
            (&*thread_swap).store(Arc::new(build_local_ips()));
        }
    });

    swap
});

pub fn is_local_addr(addr: &SocketAddr) -> bool {
    let ip = addr.ip();

    if ip.is_loopback() {
        return true;
    }

    match ip {
        IpAddr::V4(_) => {
            let ips = LOCAL_IPS.load();
            ips.contains(&ip)
        }
        IpAddr::V6(v6) => {
            let ips = LOCAL_IPS.load();

            // Direct IPv6 match
            if ips.contains(&IpAddr::V6(v6)) {
                return true;
            }

            // If this is an IPv4-mapped IPv6 address, check the mapped IPv4
            if let Some(v4) = v6.to_ipv4() {
                return ips.contains(&IpAddr::V4(v4));
            }

            false
        }
    }
}
