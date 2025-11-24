use bytes::{Bytes, BytesMut};
use dashmap::{DashMap, mapref::entry::Entry};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::{debug, error, info};

use crate::protocol::tuic::command::packet::Packet;

#[derive(Error, Debug)]
pub enum UdpError {
    #[error("Session exceeds maximum total bytes")]
    SessionTooLarge,
    #[error("Invalid fragment ID")]
    InvalidFragmentId,
}

#[derive(Debug, Clone)]
pub struct UdpFragment {
    assoc_id: u16,
    pkt_id: u16,
    frag_id: u8,
    frag_total: u8,
    payload: Bytes,
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
    total_bytes: usize,
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
            total_bytes: 0,
            last_update: Instant::now(),
        }
    }

    pub fn last_update(&self) -> Instant {
        self.last_update
    }

    pub fn insert(
        &mut self,
        frag_id: u8,
        payload: Bytes,
        max_total_bytes: Option<usize>,
    ) -> Result<Option<Bytes>, UdpError> {
        let idx = frag_id as usize;
        if idx >= self.fragments.len() {
            return Err(UdpError::InvalidFragmentId);
        }
        if (self.received_bitmap & (1u128 << idx)) != 0 {
            return Ok(None);
        }

        // enforce per-session total bytes limit if provided
        let payload_len = payload.len();
        if let Some(max) = max_total_bytes {
            if self.total_bytes + payload_len > max {
                return Err(UdpError::SessionTooLarge);
            }
        }

        self.fragments[idx] = Some(payload);
        self.received_bitmap |= 1u128 << idx;
        self.received_count += 1;
        self.total_bytes += payload_len;
        self.last_update = Instant::now();

        if self.received_count == self.frag_total as usize {
            // compute total length, ensure no missing fragment (defensive)
            let mut total_len: usize = 0;
            for frag in &self.fragments {
                if let Some(b) = frag.as_ref() {
                    total_len += b.len();
                } else {
                    // inconsistent state: expected all fragments present
                    return Err(UdpError::InvalidFragmentId);
                }
            }

            let mut full_packet = BytesMut::with_capacity(total_len);
            for frag in &self.fragments {
                if let Some(b) = frag.as_ref() {
                    full_packet.extend_from_slice(b);
                } else {
                    return Err(UdpError::InvalidFragmentId);
                }
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
        self.total_bytes = 0;
    }
}

#[derive(Clone, Debug)]
pub struct UdpSessionManager {
    sessions: Arc<DashMap<(SocketAddr, u16), ReassemblyBuffer>>,
    session_timeout: Duration,
    cleanup_interval: Duration,
    max_sessions: std::sync::Arc<std::sync::Mutex<Option<usize>>>,
    max_reassembly_bytes_per_session: std::sync::Arc<std::sync::Mutex<Option<usize>>>,
}

impl UdpSessionManager {
    pub fn new(session_timeout: Duration, cleanup_interval: Duration) -> Arc<UdpSessionManager> {
        info!(
            "Creating new UdpSessionManager with session_timeout={:?}, cleanup_interval={:?}",
            session_timeout, cleanup_interval
        );

        let manager = Arc::new(Self {
            sessions: Arc::new(DashMap::new()),
            session_timeout,
            cleanup_interval,
            max_sessions: std::sync::Arc::new(std::sync::Mutex::new(None)),
            max_reassembly_bytes_per_session: std::sync::Arc::new(std::sync::Mutex::new(None)),
        });

        let schedule_manager = manager.clone();
        {
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(schedule_manager.cleanup_interval).await;
                    if let Err(e) = schedule_manager.cleanup_expired_sessions() {
                        error!("Error cleaning up expired sessions: {}", e);
                    }
                }
            });
        }

        manager
    }

    /// Set the maximum number of concurrent sessions. If None, no hard limit is enforced.
    pub fn set_max_sessions(&self, max: Option<usize>) {
        if let Ok(mut guard) = self.max_sessions.lock() {
            *guard = max;
        }
    }

    /// Set the maximum total reassembly bytes per session. If None, no per-session byte limit is enforced.
    pub fn set_max_reassembly_bytes_per_session(&self, max: Option<usize>) {
        if let Ok(mut guard) = self.max_reassembly_bytes_per_session.lock() {
            *guard = max;
        }
    }

    pub fn receive_fragment(&self, frag: UdpFragment, client: SocketAddr) -> Option<Bytes> {
        let key = (client, frag.assoc_id);
        debug!(
            "Receiving fragment from client {} with assoc_id {} and pkt_id {}",
            client, frag.assoc_id, frag.pkt_id
        );

        match self.sessions.entry(key) {
            Entry::Occupied(mut entry) => {
                let max_reassembly = self
                    .max_reassembly_bytes_per_session
                    .lock()
                    .map(|g| *g)
                    .unwrap_or(None);

                match entry
                    .get_mut()
                    .insert(frag.frag_id, frag.payload, max_reassembly)
                {
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
                        // if it's a session-too-large error, drop the session to free resources
                        if matches!(e, UdpError::SessionTooLarge) {
                            let mut buffer = entry.remove();
                            buffer.shrink_to_fit();
                            debug!("Removed session {:?} due to size limit", key);
                        }
                        None
                    }
                }
            }
            Entry::Vacant(entry) => {
                if frag.frag_total as usize > 128 {
                    error!("Fragment total exceeds maximum size: {}", frag.frag_total);
                    return None;
                }

                // Enforce max sessions by evicting oldest sessions if configured
                let max_sessions = self.max_sessions.lock().map(|g| *g).unwrap_or(None);
                if let Some(max) = max_sessions {
                    while self.sessions.len() >= max {
                        // find the oldest session
                        let mut oldest: Option<((SocketAddr, u16), Instant)> = None;
                        for item in self.sessions.iter() {
                            let k = *item.key();
                            let lu = item.value().last_update();
                            match &oldest {
                                Some((_, t)) if *t <= lu => {}
                                _ => oldest = Some((k, lu)),
                            }
                        }
                        if let Some((k, _)) = oldest {
                            if let Some((_, mut buffer)) = self.sessions.remove(&k) {
                                buffer.shrink_to_fit();
                                debug!("Evicted oldest UDP session {:?}", k);
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }

                debug!("Creating new reassembly buffer for {:?}", key);
                let mut buffer = ReassemblyBuffer::new(frag.frag_total);
                let max_reassembly = self
                    .max_reassembly_bytes_per_session
                    .lock()
                    .map(|g| *g)
                    .unwrap_or(None);

                match buffer.insert(frag.frag_id, frag.payload, max_reassembly) {
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
        let mut expired_keys = Vec::with_capacity(self.sessions.len());

        for item in self.sessions.iter() {
            if item.value().is_expired(self.session_timeout) {
                expired_keys.push(*item.key());
            }
        }

        let total_count = self.sessions.len();
        let initial_count = expired_keys.len();
        let mut cleaned_count = 0;

        for key in expired_keys {
            if let Some((_, mut buffer)) = self.sessions.remove(&key) {
                buffer.shrink_to_fit();
                cleaned_count += 1;
            }
        }

        debug!(
            "Cleaned up {}/{} expired sessions, {} sessions in total.",
            cleaned_count, initial_count, total_count
        );
        Ok(())
    }
}
