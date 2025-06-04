use bytes::{Bytes, BytesMut};
use dashmap::{mapref::entry::Entry, DashMap};
use log::{debug, error, info};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{net::UdpSocket, sync::Mutex, time};

use crate::protocol::tuic::command::packet::Packet;

#[derive(Error, Debug)]
pub enum UdpError {
    #[error("Fragment exceeds maximum size of 128")]
    FragmentTooLarge,
    #[error("Invalid fragment ID")]
    InvalidFragmentId,
    #[error("Socket not found for client {0} and association {1}")]
    SocketNotFound(SocketAddr, u16),
    #[error("Cleanup operation failed: {0}")]
    CleanupError(String),
}

#[derive(Debug, Clone)]
pub struct UdpFragment {
    pub assoc_id: u16,
    pub pkt_id: u16,
    pub frag_id: u8,
    pub frag_total: u8,
    pub payload: Bytes,
}

impl UdpFragment {
    pub fn from_packet(packet: &Packet) -> Option<Self> {
        Some(UdpFragment {
            assoc_id: packet.assoc_id,
            pkt_id: packet.pkt_id,
            frag_id: packet.frag_id,
            frag_total: packet.frag_total,
            payload: Bytes::copy_from_slice(packet.payload.as_ref()),
        })
    }
}

impl std::fmt::Display for UdpFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UdpFragment {{ assoc_id: {}, pkt_id: {}, frag_id: {}, frag_total: {}, payload_size: {} }}",
            self.assoc_id,
            self.pkt_id,
            self.frag_id,
            self.frag_total,
            self.payload.len()
        )
    }
}

#[derive(Debug)]
pub struct ReassemblyBuffer {
    frag_total: u8,
    fragments: Vec<Option<Bytes>>,
    received_bitmap: u128,
    received_count: usize,
    last_update: Instant,
}

impl ReassemblyBuffer {
    pub fn new(frag_total: u8) -> Self {
        let size = frag_total as usize;
        assert!(size <= 128, "frag_total exceed 128");
        Self {
            frag_total,
            fragments: vec![None; size],
            received_bitmap: 0,
            received_count: 0,
            last_update: Instant::now(),
        }
    }

    pub fn insert(&mut self, frag_id: u8, payload: Bytes) -> Result<Option<Bytes>, UdpError> {
        let idx = frag_id as usize;
        if idx >= self.fragments.len() {
            return Err(UdpError::InvalidFragmentId);
        }
        if (self.received_bitmap & (1 << idx)) != 0 {
            return Ok(None);
        }

        self.fragments[idx] = Some(payload);
        self.received_bitmap |= 1 << idx;
        self.received_count += 1;
        self.last_update = Instant::now();

        if self.received_count == self.frag_total as usize {
            let total_len: usize = self
                .fragments
                .iter()
                .map(|frag| frag.as_ref().unwrap().len())
                .sum();

            let mut full_packet = BytesMut::with_capacity(total_len);
            for frag in &self.fragments {
                full_packet.extend_from_slice(frag.as_ref().unwrap());
            }

            Ok(Some(full_packet.freeze()))
        } else {
            Ok(None)
        }
    }

    pub fn _is_expired(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.last_update) > timeout
    }

    pub fn shrink_to_fit(&mut self) {
        for frag in &mut self.fragments {
            if let Some(bytes) = frag.take() {
                drop(bytes);
            }
        }
        self.fragments.clear();
        self.fragments.shrink_to_fit();
    }
}

#[derive(Clone, Debug)]
pub struct UdpSessionManager {
    sessions: Arc<DashMap<(SocketAddr, u16, u16), ReassemblyBuffer>>,

    socket_map: Arc<DashMap<(SocketAddr, u16), (Arc<Mutex<UdpSocket>>, Instant)>>,

    session_timeout: Duration,

    socket_timeout: Duration,

    #[allow(dead_code)]
    cleanup_interval: Duration,
}

impl UdpSessionManager {
    pub fn new(
        session_timeout: Duration,
        socket_timeout: Duration,
        cleanup_interval: Duration,
    ) -> Self {
        info!(
            "Creating new UdpSessionManager with session_timeout={:?}, socket_timeout={:?}, cleanup_interval={:?}",
            session_timeout, socket_timeout, cleanup_interval
        );

        let manager = Self {
            sessions: Arc::new(DashMap::new()),
            socket_map: Arc::new(DashMap::new()),
            session_timeout,
            socket_timeout,
            cleanup_interval,
        };

        {
            let manager = manager.clone();
            tokio::spawn(async move {
                let mut interval = time::interval(cleanup_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = manager.cleanup_expired_sessions() {
                        error!("Error cleaning up expired sessions: {}", e);
                    }
                }
            });
        }

        {
            let manager = manager.clone();
            tokio::spawn(async move {
                let mut interval = time::interval(cleanup_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = manager.cleanup_expired_sockets() {
                        debug!("Error cleaning up expired sockets: {}", e);
                    }
                }
            });
        }

        manager
    }

    pub fn register_socket(
        &self,
        client: SocketAddr,
        assoc_id: u16,
        socket: Arc<Mutex<UdpSocket>>,
    ) {
        debug!(
            "Registering socket for client {} with assoc_id {}",
            client, assoc_id
        );
        self.socket_map
            .insert((client, assoc_id), (socket, Instant::now()));
    }

    pub fn get_socket(
        &self,
        client: SocketAddr,
        assoc_id: u16,
    ) -> Result<Arc<Mutex<UdpSocket>>, UdpError> {
        if let Some(mut entry) = self.socket_map.get_mut(&(client, assoc_id)) {
            entry.value_mut().1 = Instant::now();
            Ok(entry.value().0.clone())
        } else {
            Err(UdpError::SocketNotFound(client, assoc_id))
        }
    }

    pub fn remove_socket(&self, client: SocketAddr, assoc_id: u16) {
        debug!(
            "Removing socket for client {} with assoc_id {}",
            client, assoc_id
        );
        self.socket_map.remove(&(client, assoc_id));
    }

    pub fn is_registered(&self, client: SocketAddr, assoc_id: u16) -> bool {
        self.socket_map.contains_key(&(client, assoc_id))
    }

    pub fn receive_fragment(&self, frag: UdpFragment, client: SocketAddr) -> Option<Bytes> {
        let key = (client, frag.assoc_id, frag.pkt_id);
        debug!(
            "Receiving fragment from client {} with assoc_id {} and pkt_id {}",
            client, frag.assoc_id, frag.pkt_id
        );

        match self.sessions.entry(key) {
            Entry::Occupied(mut entry) => {
                match entry.get_mut().insert(frag.frag_id, frag.payload) {
                    Ok(bytes_opt) => {
                        if bytes_opt.is_some() {
                            debug!("Completed packet reassembly for {:?}", key);
                            let mut buffer = entry.remove();
                            buffer.shrink_to_fit();
                        }
                        bytes_opt
                    }
                    Err(e) => {
                        error!("Error inserting fragment: {}", e);
                        None
                    }
                }
            }
            Entry::Vacant(entry) => {
                if frag.frag_total > 128 {
                    error!("Fragment total exceeds maximum size: {}", frag.frag_total);
                    return Err(UdpError::FragmentTooLarge).ok();
                }

                debug!("Creating new reassembly buffer for {:?}", key);
                let mut buffer = ReassemblyBuffer::new(frag.frag_total);
                match buffer.insert(frag.frag_id, frag.payload) {
                    Ok(Some(bytes)) => return Some(bytes),
                    Ok(None) => {
                        entry.insert(buffer);
                        None
                    }
                    Err(e) => {
                        error!("Error inserting fragment: {}", e);
                        None
                    }
                }
            }
        }
    }

    pub fn cleanup_expired_sessions(&self) -> Result<(), UdpError> {
        let now = Instant::now();
        let timeout = self.session_timeout;
        let mut expired_keys = Vec::new();

        for item in self.sessions.iter() {
            if now.duration_since(item.value().last_update) >= timeout {
                expired_keys.push(*item.key());
            }
        }

        let initial_count = expired_keys.len();
        let mut cleaned_count = 0;

        for key in expired_keys {
            if let Some((_, mut buffer)) = self.sessions.remove(&key) {
                buffer.shrink_to_fit();
                cleaned_count += 1;
            }
        }

        debug!(
            "Cleaned up {}/{} expired sessions",
            cleaned_count, initial_count
        );
        Ok(())
    }

    fn cleanup_expired_sockets(&self) -> Result<(), UdpError> {
        let now = Instant::now();
        let mut removed = 0;

        self.socket_map.retain(|key, (_, ts)| {
            let retain = now.duration_since(*ts) < self.socket_timeout;
            if !retain {
                removed += 1;
                debug!("Removing expired socket for {:?}", key);
            }
            retain
        });

        debug!(
            "Cleaned up {} expired sockets, {} remaining",
            removed,
            self.socket_map.len()
        );

        if removed > 0 && self.socket_map.len() == 0 {
            return Err(UdpError::CleanupError(
                "All sockets have been removed due to timeout".to_string(),
            ));
        }

        Ok(())
    }
}
