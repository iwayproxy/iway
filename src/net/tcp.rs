use anyhow::{Ok, Result};
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub async fn connect(addr: SocketAddr) -> Result<TcpStream> {
    let stream = TcpStream::connect(addr).await?;

    Ok(stream)
}
