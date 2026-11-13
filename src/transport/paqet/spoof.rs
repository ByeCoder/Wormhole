//! `transport = "spoof"`: the same synthetic IPv4 TCP carrier as Paqet, but the IP
//! source address is **forged**, for a Layer-3 whitelist firewall that only passes
//! traffic claiming to come from a whitelisted address.
//!
//! ```text
//!  handshake / records / kmux      unchanged, over a KcpStream
//!  KCP / protection / FEC          unchanged (spoof changes only the packet key)
//!  synthetic IPv4 + TCP            full IPv4 header built here, source address forged
//!  raw IP socket (IPPROTO_RAW,     the kernel writes nothing of the header
//!    IP_HDRINCL) for sending
//!  raw IP socket (IPPROTO_TCP)     for receiving; a BPF filter keeps only the peer's
//!                                  forged-source packets for the local port
//! ```
//!
//! Unlike Paqet, the two directions use two sockets: sending needs `IP_HDRINCL` so the
//! forged source goes on the wire, while receiving keeps an ordinary `IPPROTO_TCP` raw
//! socket (the kernel delivers inbound TCP there) with a classic BPF filter.
//!
//! This is point-to-point. The peer always forges the same source address
//! (`peer_spoof`), so a packet's source cannot identify who sent it; replies always go to
//! the peer's configured **real** address (`peer_real`). Linux and IPv4 only; needs
//! `CAP_NET_RAW` (root in practice) **and a network that permits egress source spoofing**.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Mutex;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::task::yield_now;

use super::{firewall, packet};

const INVALID_BEFORE_YIELD: u32 = 32;
const IPPROTO_TCP: u8 = 6;
/// `IPPROTO_RAW`: a send-only raw socket whose `IP_HDRINCL` is on by default, so the
/// whole IPv4 header (forged source included) is ours.
const IPPROTO_RAW: i32 = 255;
const ACCEPT_WHOLE: u32 = u16::MAX as u32;
const MAX_FLOWS: usize = 4096;

/// The TCP numbers of one flow (the peer's forged source and port).
#[derive(Debug, Clone, Copy)]
struct Flow {
    sequence: u32,
    acknowledgment: u32,
}

/// The forged addresses a spoof socket sends with and expects.
#[derive(Clone)]
pub(crate) struct SpoofAddrs {
    /// This side's forged source addresses, used round-robin.
    pub sources: Vec<Ipv4Addr>,
    /// The source the peer forges, a receive filter only (crypto is the real gate).
    /// `None`: accept any source.
    pub peer_spoof: Option<Ipv4Addr>,
    /// The peer's real address, where every reply is sent.
    pub peer_real: Ipv4Addr,
    /// The forged TCP source port.
    pub src_port: u16,
}

/// A spoofing raw IPv4 socket: `IP_HDRINCL` send + `IPPROTO_TCP` receive.
pub(crate) struct SpoofSocket {
    send: AsyncFd<Socket>,
    recv: AsyncFd<Socket>,
    /// This side's real address and the real TCP port the peer dials/answers.
    local: SocketAddrV4,
    addrs: SpoofAddrs,
    src_cursor: AtomicUsize,
    ip_id: AtomicU16,
    flows: Mutex<HashMap<SocketAddrV4, Flow>>,
    _reserved: Socket,
    _firewall: firewall::Rules,
}

impl SpoofSocket {
    /// The listening side: the peer dials the real local address; replies go to
    /// `addrs.peer_real`.
    pub(crate) fn listen(
        local: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
        addrs: SpoofAddrs,
    ) -> io::Result<Self> {
        let SocketAddr::V4(local) = local else {
            return Err(unsupported());
        };
        Self::bind(*local.ip(), local.port(), None, buffer, dscp, addrs)
    }

    /// The dialing side: `peer` is the peer's real address.
    pub(crate) fn dial(
        peer: SocketAddr,
        buffer: usize,
        dscp: Option<u8>,
        mut addrs: SpoofAddrs,
    ) -> io::Result<Self> {
        let SocketAddr::V4(peer) = peer else {
            return Err(unsupported());
        };
        if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("spoof cannot dial {peer}"),
            ));
        }
        addrs.peer_real = *peer.ip();
        let local_ip = route_local_ip(peer)?;
        Self::bind(local_ip, peer.port(), Some(peer), buffer, dscp, addrs)
    }

    fn bind(
        ip: Ipv4Addr,
        port: u16,
        peer: Option<SocketAddrV4>,
        buffer: usize,
        dscp: Option<u8>,
        addrs: SpoofAddrs,
    ) -> io::Result<Self> {
        // Reserve the TCP port so no other process answers on it. For the dialer the
        // port is the peer's port (both ends agree on it, like Paqet's reserved port).
        let reserved = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        reserved
            .bind(&SockAddr::from(SocketAddr::from((ip, port))))
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("spoof could not reserve TCP port {port} on {ip}: {e}"),
                )
            })?;
        let Some(SocketAddr::V4(local)) = reserved.local_addr()?.as_socket() else {
            return Err(io::Error::other("spoof reserved a non-IPv4 address"));
        };

        // Receive: ordinary IPPROTO_TCP raw socket + BPF for our port and the peer's
        // forged source.
        let recv =
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).map_err(need_cap_net_raw)?;
        recv.set_nonblocking(true)?;
        set_buffers(&recv, buffer);
        recv.bind(&SockAddr::from(SocketAddr::from((ip, 0))))?;
        attach_filter(&recv, local.port(), addrs.peer_spoof)?;

        // Send: IPPROTO_RAW gives IP_HDRINCL, so we write the whole header.
        let send = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
            .map_err(need_cap_net_raw)?;
        send.set_nonblocking(true)?;
        set_buffers(&send, buffer);
        if let Some(dscp) = dscp {
            let _ = send.set_tos_v4(u32::from(dscp) << 2);
        }

        let firewall = match peer {
            Some(peer) => firewall::Rules::dialer(ip, peer),
            None => firewall::Rules::listener(local),
        };

        Ok(Self {
            send: AsyncFd::new(send)?,
            recv: AsyncFd::new(recv)?,
            local,
            addrs,
            src_cursor: AtomicUsize::new(0),
            ip_id: AtomicU16::new(random_u32() as u16),
            flows: Mutex::new(HashMap::new()),
            _reserved: reserved,
            _firewall: firewall,
        })
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.local)
    }

    fn flows(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddrV4, Flow>> {
        self.flows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn heard(&self, peer: SocketAddrV4, end: u32) {
        let mut flows = self.flows();
        if let Some(flow) = flows.get_mut(&peer) {
            if later(end, flow.acknowledgment) {
                flow.acknowledgment = end;
            }
        } else if flows.len() < MAX_FLOWS {
            flows.insert(
                peer,
                Flow {
                    sequence: random_u32(),
                    acknowledgment: end,
                },
            );
        }
    }

    fn numbers(&self, peer: SocketAddrV4, length: usize) -> (u32, u32) {
        let mut flows = self.flows();
        if flows.len() >= MAX_FLOWS && !flows.contains_key(&peer) {
            flows.clear();
        }
        let flow = flows.entry(peer).or_insert_with(|| Flow {
            sequence: random_u32(),
            acknowledgment: random_u32(),
        });
        let sequence = flow.sequence;
        flow.sequence = sequence.wrapping_add(length as u32);
        (sequence, flow.acknowledgment)
    }

    /// The next forged source address (round-robin over the configured list).
    fn next_source(&self) -> Ipv4Addr {
        let n = self.addrs.sources.len().max(1);
        let i = self.src_cursor.fetch_add(1, Ordering::Relaxed) % n;
        self.addrs.sources[i]
    }

    /// Reads one valid TCP payload. The peer's forged source is already enforced by the
    /// BPF filter, so every accepted packet is from `peer_spoof`.
    pub(crate) async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut invalid = 0u32;
        loop {
            let mut ready = self.recv.readable().await?;
            let received = ready.try_io(|fd| recv_once(fd.get_ref(), buf));
            let length = match received {
                Ok(result) => result?,
                Err(_) => continue,
            };
            let Some(parsed) =
                packet::parse_ipv4_tcp(&buf[..length], *self.local.ip(), self.local.port()).filter(
                    |p| {
                        self.addrs
                            .peer_spoof
                            .map_or(true, |expected| p.peer.ip() == &expected)
                    },
                )
            else {
                invalid += 1;
                if invalid % INVALID_BEFORE_YIELD == 0 {
                    yield_now().await;
                }
                continue;
            };
            let start = parsed.payload.as_ptr() as usize - buf.as_ptr() as usize;
            let len = parsed.payload.len();
            let peer = parsed.peer;
            let end = parsed.sequence.wrapping_add(len as u32);
            self.heard(peer, end);
            buf.copy_within(start..start + len, 0);
            return Ok((len, SocketAddr::V4(peer)));
        }
    }

    /// Sends `payload` to the peer. The destination is always the peer's real address;
    /// the passed `peer` (if any) only selects the flow's TCP numbers.
    pub(crate) fn try_send_to(
        &self,
        payload: &[u8],
        flow_peer: Option<SocketAddrV4>,
        scratch: &mut Vec<u8>,
    ) -> io::Result<usize> {
        let flow_peer = flow_peer.unwrap_or_else(|| {
            let ip = self.addrs.peer_spoof.unwrap_or(self.addrs.peer_real);
            SocketAddrV4::new(ip, self.local.port())
        });
        let (sequence, acknowledgment) = self.numbers(flow_peer, payload.len());
        let source = self.next_source();
        let dest = SocketAddrV4::new(self.addrs.peer_real, self.local.port());
        let id = self.ip_id.fetch_add(1, Ordering::Relaxed);
        packet::build_spoofed_ipv4_tcp(
            source,
            self.addrs.src_port,
            *dest.ip(),
            dest.port(),
            id,
            sequence,
            acknowledgment,
            payload,
            scratch,
        )?;
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dest.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        let fd = self.send.get_ref().as_raw_fd();
        let sent = loop {
            let sent = unsafe {
                libc::sendto(
                    fd,
                    scratch.as_ptr().cast(),
                    scratch.len(),
                    0,
                    (&address as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if sent >= 0 {
                break sent as usize;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        };
        if sent != scratch.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "spoof raw socket accepted only part of a packet",
            ));
        }
        Ok(payload.len())
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "spoof supports IPv4 only in this phase",
    )
}

fn need_cap_net_raw(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::PermissionDenied {
        io::Error::new(
            e.kind(),
            format!("spoof needs root or CAP_NET_RAW to open a raw socket: {e}"),
        )
    } else {
        e
    }
}

fn later(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn random_u32() -> u32 {
    crate::crypto::random_bytes::<4>().map_or(0x5eed_1e55, u32::from_le_bytes)
}

fn set_buffers(socket: &Socket, buffer: usize) {
    let size = libc::c_int::try_from(buffer).unwrap_or(libc::c_int::MAX);
    for (force, plain) in [
        (libc::SO_RCVBUFFORCE, libc::SO_RCVBUF),
        (libc::SO_SNDBUFFORCE, libc::SO_SNDBUF),
    ] {
        if setsockopt_int(socket, force, size).is_ok() {
            continue;
        }
        let _ = setsockopt_int(socket, plain, size);
    }
}

fn setsockopt_int(socket: &Socket, option: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn route_local_ip(peer: SocketAddrV4) -> io::Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    probe.connect(SocketAddr::V4(peer))?;
    let IpAddr::V4(ip) = probe.local_addr()?.ip() else {
        return Err(io::Error::other("a route probe chose a non-IPv4 address"));
    };
    if ip.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no route to {peer}"),
        ));
    }
    Ok(ip)
}

fn recv_once(socket: &Socket, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let received =
            unsafe { libc::recv(socket.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if received >= 0 {
            return Ok(received as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

/// A classic BPF filter: IPv4 TCP to destination port `port`, and (when `peer` is set)
/// from that source address. Without `peer`, any source is accepted (the crypto rejects
/// non-peer packets); this is needed when the peer rotates its forged sources.
fn attach_filter(socket: &Socket, port: u16, peer: Option<Ipv4Addr>) -> io::Result<()> {
    let port = u32::from(port);
    let filter = if let Some(peer) = peer {
        vec![
            instruction(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0, 0, 0),
            instruction(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K, 0, 0, 0xf0),
            instruction(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 7, 0x40),
            instruction(libc::BPF_LDX | libc::BPF_B | libc::BPF_MSH, 0, 0, 0),
            instruction(libc::BPF_LD | libc::BPF_H | libc::BPF_IND, 0, 0, 2),
            instruction(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 4, port),
            instruction(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0, 0, 9),
            instruction(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                0,
                2,
                u32::from(IPPROTO_TCP),
            ),
            instruction(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 12),
            instruction(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                1,
                0,
                u32::from_be_bytes(peer.octets()),
            ),
            instruction(libc::BPF_RET | libc::BPF_K, 0, 0, 0),
            instruction(libc::BPF_RET | libc::BPF_K, 0, 0, ACCEPT_WHOLE),
        ]
    } else {
        vec![
            instruction(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0, 0, 0),
            instruction(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K, 0, 0, 0xf0),
            instruction(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 5, 0x40),
            instruction(libc::BPF_LDX | libc::BPF_B | libc::BPF_MSH, 0, 0, 0),
            instruction(libc::BPF_LD | libc::BPF_H | libc::BPF_IND, 0, 0, 2),
            instruction(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 2, port),
            instruction(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0, 0, 9),
            instruction(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                1,
                0,
                u32::from(IPPROTO_TCP),
            ),
            instruction(libc::BPF_RET | libc::BPF_K, 0, 0, 0),
            instruction(libc::BPF_RET | libc::BPF_K, 0, 0, ACCEPT_WHOLE),
        ]
    };
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&program as *const libc::sock_fprog).cast(),
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn instruction(code: u32, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}
