use sha2::{Digest, Sha224};

pub struct TrojanAuthenticationManager {
    valid_hashes: Vec<String>,
}

impl TrojanAuthenticationManager {
    pub fn new(passwords: Vec<String>) -> Self {
        let valid_hashes = passwords
            .into_iter()
            .map(|pwd| {
                let mut hasher = Sha224::new();
                hasher.update(pwd.as_bytes());
                let hash = format!("{:x}", hasher.finalize());
                tracing::debug!(
                    "[Trojan Auth] Computed hash for password '{}': {}",
                    pwd,
                    hash
                );
                hash
            })
            .collect();

        Self { valid_hashes }
    }

    pub fn verify_password_hash(&self, received_hash: &str) -> bool {
        let result = self
            .valid_hashes
            .iter()
            .any(|valid_hash| constant_time_eq(valid_hash.as_bytes(), received_hash.as_bytes()));

        if !result {
            tracing::warn!(
                "[Trojan Auth] No matching hash found. Valid hashes: {:?}, Received: {}",
                self.valid_hashes,
                received_hash
            );
        }

        result
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}
