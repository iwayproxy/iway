use std::{
    fmt::Debug,
    io::Error,
    net::SocketAddr,
};

use async_trait::async_trait;

/// Trait defining the authentication-related requirements for a connection.
/// This allows for easier testing by mocking the connection behavior.
#[async_trait]
pub trait AuthenticationConnection: Debug + Send + Sync {
    /// Get the remote peer's address
    fn remote_address(&self) -> SocketAddr;

    /// Export keying material for authentication
    async fn export_keying_material<'b, 'c, 'd>(
        &self,
        out: &'b mut [u8],
        label: &'c [u8],
        context: &'d [u8],
    ) -> Result<(), Error>;
}

// Implement the trait for quinn::Connection
#[async_trait]
impl AuthenticationConnection for quinn::Connection {
    fn remote_address(&self) -> SocketAddr {
        self.remote_address()
    }

    async fn export_keying_material<'b, 'c, 'd>(
        &self,
        out: &'b mut [u8],
        label: &'c [u8],
        context: &'d [u8],
    ) -> Result<(), Error> {
        self.export_keying_material(out, label, context)
            .map_err(|_| Error::new(std::io::ErrorKind::Other, "failed to export keying material"))
    }
}