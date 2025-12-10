use anyhow::Result;
use moka::future::Cache;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net;
use tracing::debug;

#[derive(Clone, Debug)]
struct CachedAddress {
    addr: SocketAddr,
    ttl: Instant,
}

#[derive(Clone)]
pub struct DnsResolver {
    cache: Cache<String, CachedAddress>,
    ttl_secs: u64,
}

impl DnsResolver {
    pub fn new() -> Self {
        Self::with_config(1000, 300)
    }

    pub fn with_config(max_entries: u64, ttl_secs: u64) -> Self {
        let cache = Cache::builder().max_capacity(max_entries).build();

        Self { cache, ttl_secs }
    }

    pub async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr> {
        let cache_key = format!("{}:{}", domain, port);

        if let Some(cached) = self.cache.get(&cache_key).await {
            if Instant::now() < cached.ttl {
                if tracing::enabled!(tracing::Level::DEBUG) {
                    debug!("DNS cache hit for {}:{}", domain, port);
                }
                return Ok(cached.addr);
            } else {
                self.cache.invalidate(&cache_key).await;
            }
        }

        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!("DNS cache miss for {}:{}, resolving...", domain, port);
        }

        let query_host = format!("{}:{}", domain, port);
        let mut addr_itr = net::lookup_host(&query_host).await?;

        let addr = addr_itr
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve address: {}", domain))?;

        let cached = CachedAddress {
            addr,
            ttl: Instant::now() + Duration::from_secs(self.ttl_secs),
        };

        self.cache.insert(cache_key, cached).await;

        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                "Resolved {}:{} to {}, cached for {} seconds",
                domain, port, addr, self.ttl_secs
            );
        }

        Ok(addr)
    }

    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.cache.invalidate_all();
    }

    #[allow(dead_code)]
    pub fn size(&self) -> u64 {
        self.cache.entry_count()
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}
