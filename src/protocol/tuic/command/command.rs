use anyhow::{Context, Result};
use std::fmt;
use tokio::io::AsyncRead;

use crate::protocol::tuic::header::Header;

use super::{
    authenticate::Authenticate, command_type::CommandType, connect::Connect,
    dissociate::Dissociate, heartbeat::Heartbeat, packet::Packet,
};

#[derive(Debug)]
pub enum Command {
    Authenticate(Authenticate),
    Connect(Connect),
    Packet(Packet),
    Heartbeat(Heartbeat),
    Dissociate(Dissociate),
}

impl Command {
    pub async fn read_from<R>(mut read: R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let header = Header::read_from(&mut read)
            .await
            .context("Failed to read header")?;

        match header.command_type() {
            CommandType::Authenticate => Authenticate::read_from(header, &mut read)
                .await
                .map(Command::Authenticate)
                .context("Failed to parse Authenticate command"),
            CommandType::Connect => Connect::read_from(header, &mut read)
                .await
                .map(Command::Connect)
                .context("Failed to parse Connect command"),
            CommandType::Packet => Packet::read_from(header, &mut read)
                .await
                .map(Command::Packet)
                .context("Failed to parse Packet command"),
            CommandType::Dissociate => Dissociate::read_from(header, &mut read)
                .await
                .map(Command::Dissociate)
                .context("Failed to parse Dissociate command"),
            CommandType::Heartbeat => Heartbeat::read_from(header, &mut read)
                .await
                .map(Command::Heartbeat)
                .context("Failed to parse Heartbeat command"),
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Connect(c) => write!(f, "{}", c),
            Command::Authenticate(a) => write!(f, "{}", a),
            Command::Packet(p) => write!(f, "{}", p),
            Command::Heartbeat(_) => write!(f, "Heartbeat"),
            Command::Dissociate(_) => write!(f, "Dissociate"),
        }
    }
}
