use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, warn};

#[allow(dead_code)]
pub struct FallbackHandler;

impl FallbackHandler {
    #[allow(dead_code)]
    pub async fn handle_fallback(
        mut client_stream: TcpStream,
        fallback_addr: SocketAddr,
    ) -> Result<()> {
        match TcpStream::connect(fallback_addr).await {
            Ok(mut fallback_stream) => {
                let (mut client_read, mut client_write) = client_stream.split();
                let (mut fallback_read, mut fallback_write) = fallback_stream.split();

                tokio::select! {
                    result = tokio::io::copy(&mut client_read, &mut fallback_write) => {
                        if let Err(e) = result {
                            debug!("[Trojan] Client to fallback copy error: {}", e);
                        }
                    }
                    result = tokio::io::copy(&mut fallback_read, &mut client_write) => {
                        if let Err(e) = result {
                            debug!("[Trojan] Fallback to client copy error: {}", e);
                        }
                    }
                }

                debug!("[Trojan] Fallback connection closed");
                Ok(())
            }
            Err(e) => {
                warn!(
                    "[Trojan] Failed to connect to fallback server {}: {}",
                    fallback_addr, e
                );

                let response = b"HTTP/1.1 200 OK\r\n\
                                 Content-Type: text/html\r\n\
                                 Content-Length: 0\r\n\
                                 \r\n";

                if let Err(e) = client_stream.write_all(response).await {
                    debug!("[Trojan] Failed to send fallback response: {}", e);
                }

                Ok(())
            }
        }
    }

    #[allow(dead_code)]
    pub async fn handle_http_probe(mut stream: TcpStream) -> Result<()> {
        debug!("[Trojan] Handling HTTP probe");

        let response = b"HTTP/1.1 404 Not Found\r\n\
                         Content-Type: text/html\r\n\
                         Content-Length: 9\r\n\
                         \r\n\
                         Not Found";

        stream.write_all(response).await?;
        Ok(())
    }
}
