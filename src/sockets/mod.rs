use std::sync::Arc;

use socket2::Socket;

#[derive(Debug)]
pub enum SocketKind {
    TCP(Arc<Socket>),
    UDP(Arc<Socket>),
}

