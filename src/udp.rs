//! Per-shard UDP socket with SO_REUSEPORT and batched recv/send.

use polling::{Event, Poller};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};

pub const BATCH: usize = 64;

pub struct UdpIo {
    pub socket: UdpSocket,
    pub local: SocketAddr,
}

impl UdpIo {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        #[cfg(unix)]
        sock.set_reuse_port(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&addr.into())?;
        let socket: UdpSocket = sock.into();
        let local = socket.local_addr()?;
        Ok(Self { socket, local })
    }

    pub fn recv_batch(&self, bufs: &mut [Vec<u8>]) -> io::Result<arrayvec::ArrayVec<(usize, SocketAddr), BATCH>> {
        let mut out = arrayvec::ArrayVec::new();
        for buf in bufs.iter_mut().take(BATCH) {
            if buf.len() < 2048 {
                buf.resize(2048, 0);
            }
            match self.socket.recv_from(buf) {
                Ok((n, src)) => {
                    let _ = out.try_push((n, src));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    pub fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, dest)
    }
}

pub fn register_socket(poller: &Poller, io: &UdpIo, key: usize) -> io::Result<()> {
    unsafe { poller.add(&io.socket, Event::readable(key)) }
}

pub fn reregister_readable(poller: &Poller, io: &UdpIo, key: usize) -> io::Result<()> {
    poller.modify(&io.socket, Event::readable(key))
}
