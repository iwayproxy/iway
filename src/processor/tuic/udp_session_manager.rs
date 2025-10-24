use bytes::{Bytes, BytesMut};
use dashmap::{mapref::entry::Entry, DashMap};
use log::{debug, error, info};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::time;

use crate::protocol::tuic::command::packet::Packet;

#[derive(Error, Debug)]
pub enum UdpError {
    #[error("Invalid fragment ID")]
    InvalidFragmentId,
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
    pub fn from_packet(packet: &Packet) -> Self {
        UdpFragment {
            assoc_id: packet.assoc_id,
            pkt_id: packet.pkt_id,
            frag_id: packet.frag_id,
            frag_total: packet.frag_total,
            payload: Bytes::copy_from_slice(packet.payload.as_ref()),
        }
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
        if (self.received_bitmap & (1u128 << idx)) != 0 {
            return Ok(None);
        }

        self.fragments[idx] = Some(payload);
    self.received_bitmap |= 1u128 << idx;
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

    pub fn is_expired(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.last_update) > timeout
    }

    pub fn shrink_to_fit(&mut self) {
        // Clear fragments and reset counters so memory can be reclaimed
        self.fragments.clear();
        self.fragments.shrink_to_fit();
        self.received_bitmap = 0;
        self.received_count = 0;
    }
}

#[derive(Clone, Debug)]
pub struct UdpSessionManager {
    sessions: Arc<DashMap<(SocketAddr, u16), ReassemblyBuffer>>,
    session_timeout: Duration,
    cleanup_interval: Duration,
}

impl UdpSessionManager {
    pub fn new(
        session_timeout: Duration,
        cleanup_interval: Duration,
    ) -> Arc<UdpSessionManager> {
        info!(
            "Creating new UdpSessionManager with session_timeout={:?}, cleanup_interval={:?}",
            session_timeout, cleanup_interval
        );

        let manager = Arc::new(Self {
            sessions: Arc::new(DashMap::new()),
            session_timeout,
            cleanup_interval,
        });

        let schedule_manager = manager.clone();
        {
            tokio::spawn(async move {
                let mut interval = time::interval(schedule_manager.cleanup_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = schedule_manager.cleanup_expired_sessions() {
                        error!("Error cleaning up expired sessions: {}", e);
                    }
                }
            });
        }

        manager
    }

    pub fn receive_fragment(&self, frag: UdpFragment, client: SocketAddr) -> Option<Bytes> {
        let key = (client, frag.assoc_id);
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
                if frag.frag_total as usize > 128 {
                    error!("Fragment total exceeds maximum size: {}", frag.frag_total);
                    return None;
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

    pub fn remove_session(&self, client: SocketAddr, assoc_id: u16) {
        if let Some((_, mut buffer)) = self.sessions.remove(&(client, assoc_id)) {
            buffer.shrink_to_fit();
            debug!("Removed session for {:?}", (client, assoc_id));
        }
    }

    pub fn cleanup_expired_sessions(&self) -> Result<(), UdpError> {
    let timeout = self.session_timeout;
        let mut expired_keys = Vec::new();

        for item in self.sessions.iter() {
            if item.value().is_expired(timeout) {
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

}
