use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::net::{TcpStream, UdpSocket};
use tokio::select;
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::authenticate::trojan::TrojanAuthenticationManager;
use crate::protocol::trojan::address::{Address, AddressType};
use crate::protocol::trojan::command::{CommandType, TrojanRequest};

#[allow(dead_code)]
pub struct RuntimeContext {
    pub client_addr: String,
    pub authenticated: bool,
}

impl RuntimeContext {
    pub fn new(client_addr: String) -> Self {
        Self {
            client_addr,
            authenticated: false,
        }
    }
}

pub struct TrojanConnectionProcessor {
    auth: Arc<TrojanAuthenticationManager>,
    fallback_addr: std::net::SocketAddr,
}

impl TrojanConnectionProcessor {
    pub fn new(auth: Arc<TrojanAuthenticationManager>) -> Self {
        Self {
            auth,
            fallback_addr: "127.0.0.1:80"
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap()),
        }
    }

    pub fn with_fallback_addr(mut self, fallback_addr: std::net::SocketAddr) -> Self {
        self.fallback_addr = fallback_addr;
        self
    }

    pub async fn process_connection_tls<S>(
        &self,
        mut tls_stream: TlsStream<S>,
        context: Arc<RuntimeContext>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let trojan_request = match TrojanRequest::read_from(&mut tls_stream, &self.auth).await {
            Ok(Some(req)) => req,
            Ok(None) => {
                return Ok(());
            }
            Err(e) => {
                return Err(e);
            }
        };

        match trojan_request.command {
            CommandType::Connect => {
                self.handle_connect_tls(tls_stream, trojan_request, context)
                    .await?;
            }
            CommandType::UdpAssociate => {
                self.handle_udp_associate_tls(tls_stream, trojan_request, context)
                    .await?;
            }
        }

        Ok(())
    }

    async fn handle_connect_tls<S>(
        &self,
        tls_stream: TlsStream<S>,
        request: TrojanRequest,
        _context: Arc<RuntimeContext>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let target_addr = request.address.to_address_string();

        let server_stream = TcpStream::connect(&target_addr)
            .await
            .with_context(|| format!("Failed to connect to {}", target_addr))?;

        relay_tcp(tls_stream, server_stream, 32 * 1024).await?;

        Ok(())
    }

    async fn handle_udp_associate_tls<S>(
        &self,
        tls_stream: TlsStream<S>,
        _request: TrojanRequest,
        _context: Arc<RuntimeContext>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        use tokio_util::sync::CancellationToken;

        let (mut tls_reader, mut tls_writer) = split(tls_stream);

        let udp_v4 = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let udp_v6 = match UdpSocket::bind("[::]:0").await {
            Ok(s) => Some(Arc::new(s)),
            Err(_) => None,
        };

        let (udp_resp_tx, mut udp_resp_rx) = mpsc::channel::<(SocketAddr, bytes::Bytes)>(1024);

        let cancel = CancellationToken::new();

        let recv_task = {
            let udp_v4 = udp_v4.clone();
            let udp_v6 = udp_v6.clone();
            let tx = udp_resp_tx.clone();
            let cancel = cancel.clone();

            tokio::spawn(async move {
                let shared_buf = Arc::new(Mutex::new(vec![0u8; 4096]));

                loop {
                    if let Some(ref v6) = udp_v6 {
                        let shared_buf1 = shared_buf.clone();
                        let shared_buf2 = shared_buf.clone();

                        tokio::select! {
                            res = async {
                                let mut b = shared_buf1.lock().await;
                                match udp_v4.recv_from(&mut b[..]).await {
                                    Ok((n, src)) => {
                                        let data = bytes::Bytes::copy_from_slice(&b[..n]);
                                        Ok((src, data))
                                    }
                                    Err(e) => Err(e),
                                }
                            } => {
                                match res {
                                    Ok((src, data)) => {
                                        if tx.send((src, data)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            res = async {
                                let mut b = shared_buf2.lock().await;
                                        match v6.recv_from(&mut b[..]).await {
                                    Ok((n, src)) => {
                                        let data = bytes::Bytes::copy_from_slice(&b[..n]);
                                        Ok((src, data))
                                    }
                                    Err(e) => Err(e),
                                }
                            } => {
                                match res {
                                    Ok((src, data)) => {
                                        if tx.send((src, data)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            _ = cancel.cancelled() => break,
                        }
                    } else {
                        let shared_buf1 = shared_buf.clone();
                        tokio::select! {
                            res = async {
                                let mut b = shared_buf1.lock().await;
                                match udp_v4.recv_from(&mut b[..]).await {
                                    Ok((n, src)) => {
                                        let data = bytes::Bytes::copy_from_slice(&b[..n]);
                                        Ok((src, data))
                                    }
                                    Err(e) => Err(e),
                                }
                            } => {
                                match res {
                                    Ok((src, data)) => {
                                        if tx.send((src, data)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            _ = cancel.cancelled() => break,
                        }
                    }
                }
            })
        };

        /* =========================
         * TLS reader → UDP send (choose v4/v6 socket according to target)
         * ========================= */
        let send_task = {
            let udp_v4 = udp_v4.clone();
            let udp_v6 = udp_v6.clone();
            let cancel = cancel.clone();

            tokio::spawn(async move {
                loop {
                    let frame = match read_trojan_udp_frame(&mut tls_reader).await {
                        Ok(f) => f,
                        Err(_) => {
                            cancel.cancel();
                            break;
                        }
                    };

                    let addrs = match frame.dst.to_socket_addrs().await {
                        Ok(a) => a,
                        Err(_) => continue,
                    };

                    if let Some(target) = addrs.first() {
                        let send_res = if target.is_ipv4() {
                            udp_v4.send_to(&frame.payload, target).await
                        } else if let Some(ref v6) = udp_v6 {
                            v6.send_to(&frame.payload, target).await
                        } else {
                            Err(std::io::Error::other("No IPv6 socket available"))
                        };

                        if let Err(e) = send_res {
                            tracing::error!("Failed to send UDP to {}: {}", target, e);
                        }
                    }
                }
            })
        };

        loop {
            tokio::select! {
                msg = udp_resp_rx.recv() => {
                    let Some((src, payload)) = msg else { break; };

                    let addr = match src {
                        std::net::SocketAddr::V4(sa_v4) => Address {
                            addr_type: AddressType::IPv4,
                            host: sa_v4.ip().to_string(),
                            port: sa_v4.port(),
                        },
                        std::net::SocketAddr::V6(sa_v6) => Address {
                            addr_type: AddressType::IPv6,
                            host: sa_v6.ip().to_string(),
                            port: sa_v6.port(),
                        },
                    };

                    if let Err(e) = write_trojan_udp_frame(&mut tls_writer, &addr, payload.as_ref()).await {
                        tracing::error!("Failed to write UDP frame to TLS: {}", e);
                        break;
                    }
                }

                _ = cancel.cancelled() => {
                    break;
                }
            }
        }

        cancel.cancel();
        drop(udp_resp_tx);
        recv_task.abort();
        send_task.abort();

        Ok(())
    }
}

#[derive(Debug)]
struct UdpFrame {
    dst: Address,
    payload: bytes::Bytes,
}

async fn read_trojan_udp_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<UdpFrame> {
    let address = Address::read_from(reader).await?;

    let len = reader.read_u16().await?;

    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;

    if crlf != *b"\r\n" {
        bail!("Invalid CRLF");
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;

    Ok(UdpFrame {
        dst: address,
        payload: payload.into(),
    })
}

async fn copy_with_cancel<R, W>(
    mut reader: R,
    mut writer: W,
    cancel: CancellationToken,
    buf_size: usize,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buf_size];
    let mut total = 0;

    loop {
        select! {
            _ = cancel.cancelled() => {
                return Ok(total);
            }

            n = reader.read(&mut buf) => {
                let n = n?;
                if n == 0 {
                    return Ok(total);
                }

                writer.write_all(&buf[..n]).await?;
                total += n as u64;
            }
        }
    }
}

pub async fn relay_tcp(
    left: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    right: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    buf_size: usize,
) -> anyhow::Result<()> {
    let (mut l_r, mut l_w) = split(left);
    let (mut r_r, mut r_w) = split(right);

    let cancel = CancellationToken::new();
    let cancel1 = cancel.clone();
    let cancel2 = cancel.clone();

    let a_to_b = tokio::spawn(async move {
        let _ =
            copy_with_cancel(&mut l_r, &mut r_w, cancel1, usize::min(buf_size, 16 * 1024)).await;
    });

    let b_to_a = tokio::spawn(async move {
        let _ =
            copy_with_cancel(&mut r_r, &mut l_w, cancel2, usize::min(buf_size, 16 * 1024)).await;
    });

    select! {
        _ = a_to_b => {}
        _ = b_to_a => {}
    }

    cancel.cancel();

    Ok(())
}

async fn write_trojan_udp_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    addr: &Address,
    payload: &[u8],
) -> Result<()> {
    match addr.addr_type {
        AddressType::IPv4 => {
            writer.write_u8(0x01).await?;
            writer
                .write_all(&addr.host.parse::<std::net::Ipv4Addr>()?.octets())
                .await?;
        }
        AddressType::IPv6 => {
            writer.write_u8(0x04).await?;
            writer
                .write_all(&addr.host.parse::<std::net::Ipv6Addr>()?.octets())
                .await?;
        }
        AddressType::DomainName => {
            writer.write_u8(0x03).await?;
            writer.write_u8(addr.host.len() as u8).await?;
            writer.write_all(addr.host.as_bytes()).await?;
        }
    }

    writer.write_u16(addr.port).await?;
    writer.write_u16(payload.len() as u16).await?;
    writer.write_all(b"\r\n").await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}
