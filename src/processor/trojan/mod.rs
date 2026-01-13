use crate::net::tcp as net_tcp;
use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::authenticate::trojan::TrojanAuthenticationManager;
use crate::protocol::trojan::address::Address;
use crate::protocol::trojan::command::{CommandType, TrojanRequest};

#[allow(dead_code)]
pub struct RuntimeContext {
    pub client_addr: SocketAddr,
    pub authenticated: bool,
}

impl RuntimeContext {
    pub fn new(client_addr: SocketAddr) -> Self {
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
            fallback_addr: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                80,
            ),
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
        let target_addr = request.address.to_socket_addrs().await?;

        let server_stream = net_tcp::connect(target_addr)
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
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};
        use tokio_util::sync::CancellationToken;

        let (mut tls_reader, mut tls_writer) = split(tls_stream);

        let (udp_resp_tx, mut udp_resp_rx) = mpsc::channel::<(SocketAddr, bytes::Bytes)>(1024);
        let cancel = CancellationToken::new();

        // We'll attempt to create a single dual-stack IPv6 socket (IPV6_V6ONLY = false).
        // If that fails, fall back to separate v4 and v6 sockets.
        let mut recv_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let udp_dual: Option<Arc<UdpSocket>> = (|| -> std::io::Result<Arc<UdpSocket>> {
            let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_only_v6(false)?;
            let bind_addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::UNSPECIFIED,
                0,
                0,
                0,
            ));
            sock.bind(&SockAddr::from(bind_addr))?;
            sock.set_nonblocking(true)?;
            let stdsock: std::net::UdpSocket = sock.into();
            Ok(Arc::new(UdpSocket::from_std(stdsock)?))
        })()
        .ok();

        // sockets to use for sending
        let udp_v4_sock: Option<Arc<UdpSocket>>;
        let udp_v6_sock: Option<Arc<UdpSocket>>;

        if let Some(dual) = udp_dual.clone() {
            // spawn single recv task for dual-stack socket
            let tx = udp_resp_tx.clone();
            let cancel_clone = cancel.clone();
            let arc_clone = dual.clone();
            let h = tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    tokio::select! {
                        res = arc_clone.recv_from(&mut buf) => {
                            match res {
                                Ok((n, src)) => {
                                    let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                                    if tx.send((src, data)).await.is_err() { break; }
                                }
                                Err(_) => break,
                            }
                        }
                        _ = cancel_clone.cancelled() => break,
                    }
                }
            });
            recv_handles.push(h);
            udp_v4_sock = Some(dual.clone());
            udp_v6_sock = Some(dual.clone());
        } else {
            // fallback: create separate v4 and v6 sockets
            udp_v4_sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => {
                    let tx = udp_resp_tx.clone();
                    let cancel_clone = cancel.clone();
                    let arc = Arc::new(s);
                    let arc_clone = arc.clone();
                    let h = tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        loop {
                            tokio::select! {
                                res = arc_clone.recv_from(&mut buf) => {
                                    match res {
                                        Ok((n, src)) => {
                                            let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                                            if tx.send((src, data)).await.is_err() { break; }
                                        }
                                        Err(_) => break,
                                    }
                                }
                                _ = cancel_clone.cancelled() => break,
                            }
                        }
                    });
                    recv_handles.push(h);
                    Some(arc)
                }
                Err(e) => {
                    tracing::error!("Failed to bind IPv4 socket: {}", e);
                    None
                }
            };

            udp_v6_sock = match UdpSocket::bind("[::]:0").await {
                Ok(s) => {
                    let tx = udp_resp_tx.clone();
                    let cancel_clone = cancel.clone();
                    let arc = Arc::new(s);
                    let arc_clone = arc.clone();
                    let h = tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        loop {
                            tokio::select! {
                                res = arc_clone.recv_from(&mut buf) => {
                                    match res {
                                        Ok((n, src)) => {
                                            let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                                            if tx.send((src, data)).await.is_err() { break; }
                                        }
                                        Err(_) => break,
                                    }
                                }
                                _ = cancel_clone.cancelled() => break,
                            }
                        }
                    });
                    recv_handles.push(h);
                    Some(arc)
                }
                Err(e) => {
                    tracing::error!("Failed to bind IPv6 socket: {}", e);
                    None
                }
            };
        }

        /* TLS reader → UDP send (use dual socket if available, otherwise select v4/v6) */
        let send_task = {
            let udp_dual = udp_dual.clone();
            let udp_v4_sock = udp_v4_sock.clone();
            let udp_v6_sock = udp_v6_sock.clone();
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

                    let target = match frame.dst.to_socket_addrs().await {
                        Ok(a) => a,
                        Err(_) => continue,
                    };

                    // If we created a dual-stack IPv6 socket, use it for IPv6 targets
                    // and for IPv4 targets send to an IPv4-mapped IPv6 address.
                    if let Some(dual) = udp_dual.as_ref() {
                        if target.is_ipv4() {
                            if let std::net::SocketAddr::V4(sa_v4) = target {
                                let o = sa_v4.ip().octets();
                                let v6_octets: [u8; 16] = [
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, o[0], o[1], o[2],
                                    o[3],
                                ];
                                let mapped = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                                    std::net::Ipv6Addr::from(v6_octets),
                                    sa_v4.port(),
                                    0,
                                    0,
                                ));
                                if let Err(e) = dual.send_to(&frame.payload, mapped).await {
                                    tracing::error!("Failed to send UDP to {}: {}", mapped, e);
                                }
                            }
                        } else {
                            if let Err(e) = dual.send_to(&frame.payload, target).await {
                                tracing::error!("Failed to send UDP to {}: {}", target, e);
                            }
                        }
                        continue;
                    }

                    // otherwise select based on address family and use v4/v6 sockets
                    if target.is_ipv4() {
                        if let Some(sock) = udp_v4_sock.as_ref() {
                            if let Err(e) = sock.send_to(&frame.payload, target).await {
                                tracing::error!("Failed to send UDP to {}: {}", target, e);
                            }
                        }
                    } else {
                        if let Some(sock) = udp_v6_sock.as_ref() {
                            if let Err(e) = sock.send_to(&frame.payload, target).await {
                                tracing::error!("Failed to send UDP to {}: {}", target, e);
                            }
                        }
                    }
                }
            })
        };

        loop {
            tokio::select! {
                msg = udp_resp_rx.recv() => {
                    let Some((src, payload)) = msg else { break; };

                    let addr = Address::Socket(src);

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
        for h in recv_handles {
            h.abort();
        }
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
    match addr {
        Address::Socket(sa) => match sa {
            std::net::SocketAddr::V4(v4) => {
                writer.write_u8(0x01).await?;
                writer.write_all(&v4.ip().octets()).await?;
                writer.write_u16(v4.port()).await?;
            }
            std::net::SocketAddr::V6(v6) => {
                writer.write_u8(0x04).await?;
                writer.write_all(&v6.ip().octets()).await?;
                writer.write_u16(v6.port()).await?;
            }
        },
        Address::Domain(domain, port) => {
            writer.write_u8(0x03).await?;
            writer.write_u8(domain.len() as u8).await?;
            writer.write_all(domain.as_bytes()).await?;
            writer.write_u16(*port).await?;
        }
    }
    writer.write_u16(payload.len() as u16).await?;
    writer.write_all(b"\r\n").await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}
