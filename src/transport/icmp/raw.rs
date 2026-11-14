//! Linux IPv4 raw socket carrier for `icmp`: a nonblocking `IPPROTO_ICMP` socket whose
//! ICMP echo header and checksum this module writes itself, and whose IPv4 header the
//! kernel writes and reads.
//!
//! A classic BPF program attached to the socket drops every ICMP packet that is not an
//! echo request for this socket's id before it reaches userspace. The receive side is
//! driven by Tokio's `AsyncFd`; sends are direct nonblocking `sendto` calls, so a full
//! socket buffer drops a packet instead of blocking a KCP timer or a writer. The dialing
//! side's socket is connected to its peer, so the kernel hands it only that peer's
//! packets.
//!
//! The two ends are told apart by the echo identifier, used like a port: each socket has
//! a 16-bit local id, a packet's `id` field is the destination's local id and its `seq`
//! field is the source's, so a received packet names both where it belongs and where a
//! reply to it goes. This works even on loopback, where both ends share an address.
//!
//! A listener may be on every IPv4 address (`0.0.0.0`). Each flow then remembers the
//! address its packets came to and is answered from it (`IP_PKTINFO` on the send), so a
//! server with several addresses answers on the one that was dialed.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Mutex;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::task::yield_now;
use tracing::debug;

use super::{firewall, packet};

/// Invalid packets handled before yielding to the async runtime, so a flood of junk
/// cannot keep one driver task running forever.
const INVALID_BEFORE_YIELD: u32 = 32;
const IPPROTO_ICMP: u8 = 1;
/// What the BPF filter returns for a packet it accepts: the bytes of it to keep. Any
/// smaller cap would quietly cut a packet longer than it, which then fails
/// authentication.
const ACCEPT_WHOLE: u32 = u16::MAX as u32;
/// Flows a socket remembers a reply address for. Packets are counted before they are
/// authenticated, so a flood of forged sources must not grow the table without end; past
/// this, flows are forgotten and learned again.
const MAX_FLOWS: usize = 4096;

/// A raw IPv4 ICMP socket bound to one local address (or every one, on the listening
/// side) with a 16-bit local id.
pub(crate) struct IcmpSocket {
    fd: AsyncFd<Socket>,
    local: SocketAddrV4,
    /// This socket's own id: incoming packets must carry it, outgoing ones put it in the
    /// sequence number so the peer can reply to it.
    local_id: u16,
    /// Set on the dialing side: sends go here unless a peer is passed explicitly.
    peer: Option<SocketAddrV4>,
    /// The address each peer's packets came to, for a listener on every address: the
    /// source of the replies. Keyed by the peer as `recv` reports it (address and id).
    flows: Mutex<HashMap<SocketAddrV4, Ipv4Addr>>,
    /// The host firewall rules this socket needs (see [`firewall`]); removed with it.
    _firewall: firewall::Rules,
}

impl IcmpSocket {
    /// Listens on one local IPv4 address, or on every one (`0.0.0.0`). The address' port
    /// is the local id; 0 picks a random one, which [`Self::local_addr`] then reports.
    pub(crate) fn listen(local: SocketAddr, buffer: usize, dscp: Option<u8>) -> io::Result<Self> {
        let SocketAddr::V4(local) = local else {
            return Err(ipv4_only());
        };
        let id = nonzero_id(local.port(), 0);
        Self::bind(*local.ip(), id, None, buffer, dscp)
    }

    /// Dials `peer` (whose port is the listener's id) from the address the route selects,
    /// with a random local id of its own.
    pub(crate) fn dial(peer: SocketAddr, buffer: usize, dscp: Option<u8>) -> io::Result<Self> {
        let SocketAddr::V4(peer) = peer else {
            return Err(ipv4_only());
        };
        if peer.port() == 0
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
            || peer.ip().is_broadcast()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("icmp cannot dial {peer}"),
            ));
        }
        let local_ip = route_local_ip(peer)?;
        // A random local id, never the peer's, so the two ends differ on loopback too.
        let id = nonzero_id(0, peer.port());
        Self::bind(local_ip, id, Some(peer), buffer, dscp)
    }

    fn bind(
        ip: Ipv4Addr,
        local_id: u16,
        peer: Option<SocketAddrV4>,
        buffer: usize,
        dscp: Option<u8>,
    ) -> io::Result<Self> {
        let raw = raw_socket().map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                io::Error::new(
                    e.kind(),
                    format!("icmp needs root or CAP_NET_RAW to open a raw ICMP socket: {e}"),
                )
            } else {
                e
            }
        })?;
        raw.set_nonblocking(true)?;
        set_buffers(&raw, buffer);
        if let Some(dscp) = dscp {
            if let Err(e) = raw.set_tos_v4(u32::from(dscp) << 2) {
                debug!(error = %e, dscp, "could not set the icmp DSCP mark");
            }
        }
        raw.bind(&SockAddr::from(SocketAddr::from((ip, 0))))?;
        if let Some(peer) = peer {
            // The kernel then delivers only the peer's packets to this socket.
            raw.connect(&SockAddr::from(SocketAddr::from((*peer.ip(), 0))))?;
        }
        attach_id_filter(&raw, local_id, peer.map(|p| *p.ip()))?;
        let fd = AsyncFd::new(raw)?;
        let firewall = match peer {
            Some(peer) => firewall::Rules::dialer(ip, *peer.ip()),
            None => firewall::Rules::listener(ip),
        };
        Ok(Self {
            fd,
            local: SocketAddrV4::new(ip, local_id),
            local_id,
            peer,
            flows: Mutex::new(HashMap::new()),
            _firewall: firewall,
        })
    }

    fn flows(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddrV4, Ipv4Addr>> {
        self.flows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether this is a listener on every address, which answers each flow from the
    /// address its packets came to.
    fn on_every_address(&self) -> bool {
        self.local.ip().is_unspecified()
    }

    /// Records that `peer` was last heard from at `local`: the source of the next reply.
    fn heard(&self, peer: SocketAddrV4, local: Ipv4Addr) {
        if !self.on_every_address() {
            return;
        }
        let mut flows = self.flows();
        if flows.len() >= MAX_FLOWS && !flows.contains_key(&peer) {
            flows.clear();
        }
        flows.insert(peer, local);
    }

    /// The address a reply to `peer` goes from: the one its packets came to, or the route
    /// to it if it has not been heard yet.
    fn reply_from(&self, peer: SocketAddrV4) -> Ipv4Addr {
        if !self.on_every_address() {
            return *self.local.ip();
        }
        if let Some(local) = self.flows().get(&peer) {
            return *local;
        }
        route_local_ip(peer).unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.local)
    }

    /// Reads one valid echo payload. Invalid packets are skipped; a sustained flood
    /// yields to the runtime every [`INVALID_BEFORE_YIELD`] of them.
    pub(crate) async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut invalid = 0u32;
        loop {
            let mut ready = self.fd.readable().await?;
            let received = ready.try_io(|fd| recv_once(fd.get_ref(), buf));
            let length = match received {
                Ok(result) => result?,
                Err(_) => continue,
            };
            let Some(packet::Incoming {
                payload,
                peer,
                local,
            }) = packet::parse_ipv4_icmp(&buf[..length], *self.local.ip(), self.local_id)
                .filter(|p| self.peer.map_or(true, |remote| remote.ip() == p.peer.ip()))
            else {
                invalid += 1;
                if invalid % INVALID_BEFORE_YIELD == 0 {
                    yield_now().await;
                }
                continue;
            };
            let start = payload.as_ptr() as usize - buf.as_ptr() as usize;
            let len = payload.len();
            self.heard(peer, local);
            buf.copy_within(start..start + len, 0);
            return Ok((len, SocketAddr::V4(peer)));
        }
    }

    /// Sends to the configured peer without waiting.
    pub(crate) fn try_send(&self, payload: &[u8], scratch: &mut Vec<u8>) -> io::Result<usize> {
        let peer = self.peer.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "an icmp listener has no default peer",
            )
        })?;
        self.try_send_to_addr(payload, peer, scratch)
    }

    /// Sends to `peer` without waiting.
    pub(crate) fn try_send_to(
        &self,
        payload: &[u8],
        peer: SocketAddr,
        scratch: &mut Vec<u8>,
    ) -> io::Result<usize> {
        let SocketAddr::V4(peer) = peer else {
            return Err(ipv4_only());
        };
        self.try_send_to_addr(payload, peer, scratch)
    }

    fn try_send_to_addr(
        &self,
        payload: &[u8],
        peer: SocketAddrV4,
        scratch: &mut Vec<u8>,
    ) -> io::Result<usize> {
        // `id` is the destination's id (the peer, as `recv` reported it); `seq` is ours.
        packet::build_echo(peer.port(), self.local_id, payload, scratch)?;
        let from = self.reply_from(peer);
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(peer.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        let fd = self.fd.get_ref().as_raw_fd();
        let sent = loop {
            let sent = if self.on_every_address() && !from.is_unspecified() {
                send_from(fd, scratch, &address, from)
            } else {
                unsafe {
                    libc::sendto(
                        fd,
                        scratch.as_ptr().cast(),
                        scratch.len(),
                        0,
                        (&address as *const libc::sockaddr_in).cast(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
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
                "icmp raw socket accepted only part of a message",
            ));
        }
        Ok(payload.len())
    }
}

fn ipv4_only() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "icmp supports IPv4 only in this phase",
    )
}

fn raw_socket() -> io::Result<Socket> {
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
}

/// A nonzero id: `wanted` if it is not zero and not `forbidden`, otherwise a random one
/// that is neither.
fn nonzero_id(wanted: u16, forbidden: u16) -> u16 {
    if wanted != 0 && wanted != forbidden {
        return wanted;
    }
    loop {
        let id = u16::from_le_bytes(crate::crypto::random_bytes::<2>().unwrap_or([0x5e, 0xed]));
        if id != 0 && id != forbidden {
            return id;
        }
    }
}

/// `sendmsg` of `data` to `to` with `from` as the IPv4 source (`IP_PKTINFO`'s
/// `ipi_spec_dst`, which a raw socket's send honours): a listener on every address
/// answers from the address the flow came to, not the one the route would pick.
fn send_from(fd: RawFd, data: &[u8], to: &libc::sockaddr_in, from: Ipv4Addr) -> isize {
    let info_len = std::mem::size_of::<libc::in_pktinfo>() as libc::c_uint;
    // Room for one control message, aligned for `cmsghdr`.
    let mut control = [0u64; 8];
    let space = unsafe { libc::CMSG_SPACE(info_len) } as usize;
    debug_assert!(space <= std::mem::size_of_val(&control));
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (to as *const libc::sockaddr_in).cast_mut().cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    let info = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
            s_addr: u32::from_ne_bytes(from.octets()),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    };
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_level = libc::IPPROTO_IP;
        (*header).cmsg_type = libc::IP_PKTINFO;
        (*header).cmsg_len = libc::CMSG_LEN(info_len) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::in_pktinfo>(), info);
        libc::sendmsg(fd, &msg, 0)
    }
}

/// Sets the socket buffers to `buffer` bytes (see `paqet::raw` for the `FORCE` options).
fn set_buffers(socket: &Socket, buffer: usize) {
    let size = libc::c_int::try_from(buffer).unwrap_or(libc::c_int::MAX);
    for (force, plain, name) in [
        (libc::SO_RCVBUFFORCE, libc::SO_RCVBUF, "receive"),
        (libc::SO_SNDBUFFORCE, libc::SO_SNDBUF, "send"),
    ] {
        if setsockopt_int(socket, force, size).is_ok() {
            continue;
        }
        if let Err(e) = setsockopt_int(socket, plain, size) {
            debug!(error = %e, buffer = name, "could not set an icmp raw socket buffer");
        }
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

/// The address the kernel routes to `peer` from, learned without sending a packet.
fn route_local_ip(peer: SocketAddrV4) -> io::Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    probe.connect(SocketAddr::V4(peer))?;
    let local = probe.local_addr()?;
    let IpAddr::V4(ip) = local.ip() else {
        return Err(io::Error::other(
            "a UDP route probe chose a non-IPv4 address",
        ));
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

/// Attaches a classic BPF filter for IPv4 ICMP echo requests (type 8) whose identifier is
/// `id`. With `peer`, the source address must be that peer too (the dialing side knows
/// it).
///
/// ```text
/// ip[0] & 0xf0 == 0x40
/// ip[9] == 1                 (ICMP)
/// ip[12..16] == peer         (dialing side)
/// x = 4 * (ip[0] & 0xf)
/// icmp[x] == 8               (echo request)
/// icmp[x + 4 .. x + 6] == id
/// ```
///
/// Loads are bounds-checked by the kernel filter engine: a short packet returns 0.
fn attach_id_filter(socket: &Socket, id: u16, peer: Option<Ipv4Addr>) -> io::Result<()> {
    let id = u32::from(id);
    let mut filter = vec![
        // IPv4?
        instruction(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0, 0, 0),
        instruction(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K, 0, 0, 0xf0),
        instruction(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 0, 0x40), // jf set below
        // ICMP?
        instruction(libc::BPF_LD | libc::BPF_B | libc::BPF_ABS, 0, 0, 9),
        instruction(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            0,
            0,
            u32::from(IPPROTO_ICMP),
        ),
    ];
    if let Some(peer) = peer {
        // Source address == peer?
        filter.push(instruction(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            0,
            0,
            12,
        ));
        filter.push(instruction(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            0,
            0,
            u32::from_be_bytes(peer.octets()),
        ));
    }
    // x = IPv4 header length; then the echo type and id at icmp offsets 0 and 4.
    filter.extend([
        instruction(libc::BPF_LDX | libc::BPF_B | libc::BPF_MSH, 0, 0, 0),
        instruction(libc::BPF_LD | libc::BPF_B | libc::BPF_IND, 0, 0, 0),
        instruction(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            0,
            0,
            u32::from(packet::ECHO_REQUEST),
        ),
        instruction(libc::BPF_LD | libc::BPF_H | libc::BPF_IND, 0, 0, 4),
        instruction(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 0, id), // jf set below
        instruction(libc::BPF_RET | libc::BPF_K, 0, 0, ACCEPT_WHOLE),
        instruction(libc::BPF_RET | libc::BPF_K, 0, 0, 0),
    ]);
    // Every conditional jumps to the single reject at the end: the accept is the
    // second-to-last instruction, the reject the last.
    let reject = filter.len() - 1;
    for (index, inst) in filter.iter_mut().enumerate() {
        let is_jeq = u32::from(inst.code) == (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K)
            && inst.jt == 0
            && inst.jf == 0;
        if is_jeq {
            inst.jf = (reject - index - 1) as u8;
        }
    }
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
