//! The datagram socket KCP rides on: UDP for `transport = "kcp"`, the raw IPv4 TCP
//! carrier for `transport = "paqet"`. Everything above this file (protection, KCP, FEC,
//! datagrams, keepalive, demultiplexing) is shared unchanged.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::debug;

use crate::transport::mark_dscp;

use crate::transport::dns::packet as dns_packet;
#[cfg(target_os = "linux")]
use crate::transport::icmp::raw as icmp_raw;
#[cfg(target_os = "linux")]
use crate::transport::paqet::{raw, spoof};

use super::SpoofParams;

/// One socket for one KCP or Paqet stream: a Datagram-type interface over either a UDP
/// socket or a Linux raw IPv4 socket. Cloning is cheap (the underlying socket is shared).
#[derive(Clone)]
pub(crate) struct PacketSocket {
    kind: Kind,
    local: SocketAddr,
    peer: Option<SocketAddr>,
}

#[derive(Clone)]
enum Kind {
    Udp(Arc<UdpSocket>),
    /// A UDP socket whose datagrams are wrapped in DNS messages (`respond`: a response on
    /// the listening side, a query on the dialing side).
    Dns {
        socket: Arc<UdpSocket>,
        respond: bool,
    },
    #[cfg(target_os = "linux")]
    Paqet(Arc<raw::RawSocket>),
    #[cfg(target_os = "linux")]
    Spoof(Arc<spoof::SpoofSocket>),
    #[cfg(target_os = "linux")]
    Icmp(Arc<icmp_raw::IcmpSocket>),
}

impl PacketSocket {
    /// Binds a UDP socket for the listening side.
    pub(crate) fn udp_bind(addr: SocketAddr, buffer: usize, dscp: Option<u8>) -> io::Result<Self> {
        let socket = bind_udp(addr, buffer, dscp)?;
        let local = socket.local_addr()?;
        Ok(Self {
            kind: Kind::Udp(Arc::new(socket)),
            local,
            peer: None,
        })
    }

    /// Binds and connects a UDP socket for the dialing side.
    pub(crate) async fn udp_connect(
        peer: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<Self> {
        let local = match peer {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = bind_udp(local, buffer, dscp)?;
        let local = socket.local_addr()?;
        socket.connect(peer).await?;
        Ok(Self {
            kind: Kind::Udp(Arc::new(socket)),
            local,
            peer: Some(peer),
        })
    }

    /// Binds the DNS carrier listener: a UDP socket that answers with DNS responses.
    pub(crate) fn dns_listen(
        addr: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<Self> {
        let socket = bind_udp(addr, buffer, dscp)?;
        let local = socket.local_addr()?;
        Ok(Self {
            kind: Kind::Dns {
                socket: Arc::new(socket),
                respond: true,
            },
            local,
            peer: None,
        })
    }

    /// Creates the dialing side of the DNS carrier: a UDP socket that sends DNS queries.
    pub(crate) async fn dns_dial(
        peer: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<Self> {
        let local = match peer {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = bind_udp(local, buffer, dscp)?;
        let local = socket.local_addr()?;
        socket.connect(peer).await?;
        Ok(Self {
            kind: Kind::Dns {
                socket: Arc::new(socket),
                respond: false,
            },
            local,
            peer: Some(peer),
        })
    }

    /// Binds the raw socket listener (Linux IPv4 only).
    pub(crate) fn paqet_listen(
        addr: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let socket = Arc::new(raw::RawSocket::listen(addr, buffer, dscp)?);
            let local = socket.local_addr();
            Ok(Self {
                kind: Kind::Paqet(socket),
                local,
                peer: None,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (addr, buffer, dscp);
            Err(unsupported())
        }
    }

    /// Creates the dialing side of the raw carrier (Linux IPv4 only).
    pub(crate) fn paqet_dial(
        peer: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let socket = Arc::new(raw::RawSocket::dial(peer, buffer, dscp)?);
            let local = socket.local_addr();
            Ok(Self {
                kind: Kind::Paqet(socket),
                local,
                peer: Some(peer),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (peer, buffer, dscp);
            Err(unsupported())
        }
    }

    /// Binds the raw ICMP carrier listener (Linux IPv4 only).
    pub(crate) fn icmp_listen(
        addr: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let socket = Arc::new(icmp_raw::IcmpSocket::listen(addr, buffer, dscp)?);
            let local = socket.local_addr();
            Ok(Self {
                kind: Kind::Icmp(socket),
                local,
                peer: None,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (addr, buffer, dscp);
            Err(unsupported())
        }
    }

    /// Creates the dialing side of the raw ICMP carrier (Linux IPv4 only).
    pub(crate) fn icmp_dial(peer: SocketAddr, buffer: usize, dscp: Option<u8>) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let socket = Arc::new(icmp_raw::IcmpSocket::dial(peer, buffer, dscp)?);
            let local = socket.local_addr();
            Ok(Self {
                kind: Kind::Icmp(socket),
                local,
                peer: Some(peer),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (peer, buffer, dscp);
            Err(unsupported())
        }
    }

    /// Binds the spoofing raw carrier listener (Linux IPv4 only).
    pub(crate) fn spoof_listen(
        addr: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
        params: SpoofParams,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let addrs = spoof_addrs(&params, addr.port())?;
            let socket = Arc::new(spoof::SpoofSocket::listen(addr, buffer, dscp, addrs)?);
            let local = socket.local_addr();
            Ok(Self {
                kind: Kind::Spoof(socket),
                local,
                peer: None,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (addr, buffer, dscp, params);
            Err(unsupported())
        }
    }

    /// Creates the dialing side of the spoofing raw carrier (Linux IPv4 only).
    pub(crate) fn spoof_dial(
        peer: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
        params: SpoofParams,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let addrs = spoof_addrs(&params, peer.port())?;
            let socket = Arc::new(spoof::SpoofSocket::dial(peer, buffer, dscp, addrs)?);
            let local = socket.local_addr();
            Ok(Self {
                kind: Kind::Spoof(socket),
                local,
                peer: Some(peer),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (peer, buffer, dscp, params);
            Err(unsupported())
        }
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub(crate) fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Whether the carrier is a raw IPv4 TCP one (paqet or spoof): the wire counters
    /// account its packets as TCP.
    pub(crate) fn is_paqet(&self) -> bool {
        match &self.kind {
            Kind::Udp(_) => false,
            Kind::Dns { .. } => false,
            #[cfg(target_os = "linux")]
            Kind::Paqet(_) => true,
            #[cfg(target_os = "linux")]
            Kind::Spoof(_) => true,
            // ICMP's IP + echo header is 28 bytes, as a UDP packet's is, so it is metered
            // on the plain counters.
            #[cfg(target_os = "linux")]
            Kind::Icmp(_) => false,
        }
    }

    /// The next packet from the configured peer.
    pub(crate) async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.kind {
            Kind::Udp(socket) => socket.recv(buf).await,
            // Skip any datagram on :53 that is not one of ours (a stray real query, say).
            Kind::Dns { socket, .. } => loop {
                let n = socket.recv(buf).await?;
                if let Some(len) = dns_payload_to_front(buf, n) {
                    return Ok(len);
                }
            },
            #[cfg(target_os = "linux")]
            Kind::Paqet(socket) => socket.recv(buf).await.map(|(len, _)| len),
            #[cfg(target_os = "linux")]
            Kind::Spoof(socket) => socket.recv(buf).await.map(|(len, _)| len),
            #[cfg(target_os = "linux")]
            Kind::Icmp(socket) => socket.recv(buf).await.map(|(len, _)| len),
        }
    }

    /// The next packet and where it came from.
    pub(crate) async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.kind {
            Kind::Udp(socket) => socket.recv_from(buf).await,
            Kind::Dns { socket, .. } => loop {
                let (n, peer) = socket.recv_from(buf).await?;
                if let Some(len) = dns_payload_to_front(buf, n) {
                    return Ok((len, peer));
                }
            },
            #[cfg(target_os = "linux")]
            Kind::Paqet(socket) => socket.recv(buf).await,
            #[cfg(target_os = "linux")]
            Kind::Spoof(socket) => socket.recv(buf).await,
            #[cfg(target_os = "linux")]
            Kind::Icmp(socket) => socket.recv(buf).await,
        }
    }

    /// Sends to the configured peer without waiting. `scratch` is reusable packet space
    /// for the raw carrier; UDP ignores it.
    pub(crate) fn try_send(&self, payload: &[u8], _scratch: &mut Vec<u8>) -> io::Result<usize> {
        match &self.kind {
            Kind::Udp(socket) => socket.try_send(payload),
            Kind::Dns { socket, respond } => {
                dns_wrap(payload, *respond, _scratch)?;
                socket.try_send(_scratch)
            }
            #[cfg(target_os = "linux")]
            Kind::Paqet(socket) => socket.try_send(payload, _scratch),
            #[cfg(target_os = "linux")]
            Kind::Spoof(socket) => socket.try_send_to(payload, None, _scratch),
            #[cfg(target_os = "linux")]
            Kind::Icmp(socket) => socket.try_send(payload, _scratch),
        }
    }

    /// Sends to `peer` without waiting.
    pub(crate) fn try_send_to(
        &self,
        payload: &[u8],
        peer: SocketAddr,
        _scratch: &mut Vec<u8>,
    ) -> io::Result<usize> {
        match &self.kind {
            Kind::Udp(socket) => socket.try_send_to(payload, peer),
            Kind::Dns { socket, respond } => {
                dns_wrap(payload, *respond, _scratch)?;
                socket.try_send_to(_scratch, peer)
            }
            #[cfg(target_os = "linux")]
            Kind::Paqet(socket) => socket.try_send_to(payload, peer, _scratch),
            #[cfg(target_os = "linux")]
            Kind::Spoof(socket) => {
                let flow = match peer {
                    SocketAddr::V4(v4) => Some(v4),
                    SocketAddr::V6(_) => None,
                };
                socket.try_send_to(payload, flow, _scratch)
            }
            #[cfg(target_os = "linux")]
            Kind::Icmp(socket) => socket.try_send_to(payload, peer, _scratch),
        }
    }
}

/// Turns the core's [`SpoofParams`] into the socket's [`spoof::SpoofAddrs`]. The forged
/// source port defaults to the tunnel's real port; `peer_real` is filled by the dialer
/// from the dialed address, so a placeholder is fine there.
#[cfg(target_os = "linux")]
fn spoof_addrs(params: &SpoofParams, real_port: u16) -> io::Result<spoof::SpoofAddrs> {
    if params.sources.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spoof needs at least one source address",
        ));
    }
    Ok(spoof::SpoofAddrs {
        sources: params.sources.clone(),
        peer_spoof: params.peer,
        peer_real: params.peer_real.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
        src_port: params.port.unwrap_or(real_port),
    })
}

/// Wraps `payload` in a DNS message (a response when `respond`, else a query) in `out`,
/// with a random transaction id as a real client uses.
fn dns_wrap(payload: &[u8], respond: bool, out: &mut Vec<u8>) -> io::Result<()> {
    let id = u16::from_le_bytes(crate::crypto::random_bytes::<2>().unwrap_or([0, 1]));
    dns_packet::encode(out, respond, id, payload)
}

/// Decodes the DNS message in `buf[..n]` and moves its payload to the front of `buf`,
/// returning the payload's length, or `None` if it is not one of ours.
fn dns_payload_to_front(buf: &mut [u8], n: usize) -> Option<usize> {
    let payload = dns_packet::decode(buf.get(..n)?)?;
    let start = payload.as_ptr() as usize - buf.as_ptr() as usize;
    let len = payload.len();
    buf.copy_within(start..start + len, 0);
    Some(len)
}

pub(super) fn bind_udp(addr: SocketAddr, buffer: usize, dscp: Option<u8>) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)?;
    let sock = socket2::SockRef::from(&socket);
    if let Err(e) = sock
        .set_recv_buffer_size(buffer)
        .and_then(|_| sock.set_send_buffer_size(buffer))
    {
        debug!(error = %e, "could not set KCP socket buffers");
    }
    mark_dscp(&sock, dscp);
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "paqet is only supported on Linux",
    )
}
