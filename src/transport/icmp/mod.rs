//! `transport = "icmp"`: KCP packets carried in the payload of ICMP echo messages over a
//! Linux IPv4 raw socket.
//!
//! Like `paqet`, this reuses Wormhole's own packet protection, KCP, FEC, datagram and
//! keepalive code with a domain-separated key, and only the carrier below them is new:
//!
//! ```text
//!  handshake / records / kmux      unchanged, over a KcpStream
//!  KCP / protection / FEC          unchanged (icmp changes only the packet key)
//!  ICMP echo (type 8)              one sealed packet per echo message, no ping/pong
//!  raw IP socket (IPPROTO_ICMP)    kernel writes and reads the IPv4 header
//! ```
//!
//! Both ends send echo requests (never replies), so the only echo replies on the wire
//! are the kernel's own answers to those requests, which a scoped firewall rule drops
//! (`firewall`). The echo identifier is used as a light "port" so several tunnels, and
//! the host's own `ping`, do not get mixed up, and so the two ends can be told apart even
//! on loopback.
//!
//! This phase supports IPv4 only and requires `CAP_NET_RAW` (root in practice).

pub mod packet;

#[cfg_attr(not(all(target_os = "linux", feature = "kcp")), allow(dead_code))]
pub(crate) mod firewall;

#[cfg(all(target_os = "linux", feature = "kcp"))]
pub(crate) mod raw;
