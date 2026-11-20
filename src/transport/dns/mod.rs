//! `transport = "dns"`: KCP packets wrapped in DNS query/response messages over UDP.
//!
//! Like the other KCP transports, this reuses Wormhole's packet protection, KCP, FEC,
//! datagram and keepalive code with a domain-separated key, and only the carrier is new:
//! a plain UDP socket (bound to port 53 on the listening side) whose every datagram is a
//! DNS message. The dialing side sends DNS queries, the listening side DNS responses, so a
//! filter that passes only DNS on UDP 53 lets the tunnel through.
//!
//! Wormhole is a direct server-to-server tunnel, so these messages do not pass through a
//! recursive resolver: the sealed KCP packet rides whole in a record's RDATA rather than
//! being squeezed into the query name (see [`packet`]). Works over IPv4 and IPv6.
//!
//! With `[tunnel.dns] resolvers` the packets go through real recursive resolvers instead,
//! to a listener that is the authoritative server of `[tunnel.dns] domain` (see
//! [`resolver`]): slower, but it gets out where only DNS does.

pub mod list;
pub mod packet;
#[cfg(feature = "kcp")]
pub mod resolver;
pub mod wire;
