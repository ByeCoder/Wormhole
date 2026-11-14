//! The ICMP echo framing of an `icmp` packet.
//!
//! One sealed KCP packet goes into the payload of one ICMP echo message (type 8). There
//! is no ping/pong pairing: both sides send echo requests, and KCP is the reliable layer
//! above. The only fields an echo header has besides the checksum are a 16-bit
//! identifier and a 16-bit sequence number; `icmp` uses them as a pair of light "ports"
//! so several tunnels (and the host's own `ping`) do not get mixed up, and so the two
//! ends can be told apart even on loopback, where both have the same address:
//!
//! ```text
//!  id   the destination's local id  (a packet is "for me" when this is my local id)
//!  seq  the source's local id       (where replies to this packet go)
//! ```
//!
//! The IPv4 header is written and read by the kernel (as for `paqet`), so this builds and
//! parses only the ICMP message. The checksum is the standard one's-complement sum over
//! the whole ICMP message, with no pseudo-header (unlike TCP).

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

/// IPv4 header without options.
pub const IPV4_HEADER: usize = 20;
/// ICMP echo header: type, code, checksum, identifier, sequence number.
pub const ICMP_HEADER: usize = 8;

const IPPROTO_ICMP: u8 = 1;
/// ICMP echo request. Both directions use it: the kernel answers an echo request with an
/// echo reply (type 0) of its own, so sending only requests leaves the replies on the
/// wire as exactly the kernel's unwanted ones, which a single scoped firewall rule drops
/// without touching the tunnel (`firewall`).
pub const ECHO_REQUEST: u8 = 8;

/// An echo message received for the local id.
pub struct Incoming<'a> {
    pub payload: &'a [u8],
    /// Who sent it: the source address, and the source's own local id (from `seq`), which
    /// is the id replies to it must carry.
    pub peer: SocketAddrV4,
    /// The address it was sent to: the source of the replies to it (for a listener on
    /// every address, the one the peer dialed).
    pub local: Ipv4Addr,
}

/// Builds an ICMP echo request (header and `payload`): `dest_id` goes in the identifier
/// (so the destination accepts it), `src_id` in the sequence number (so the destination
/// knows where to reply).
pub fn build_echo(dest_id: u16, src_id: u16, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let length = ICMP_HEADER + payload.len();
    u16::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "icmp payload does not fit in an echo message",
        )
    })?;
    out.clear();
    out.reserve(length);
    out.push(ECHO_REQUEST);
    out.push(0); // code
    out.extend_from_slice(&[0, 0]); // checksum, filled in below
    out.extend_from_slice(&dest_id.to_be_bytes());
    out.extend_from_slice(&src_id.to_be_bytes());
    out.extend_from_slice(payload);
    let checksum = checksum(out);
    out[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

/// The payload of a received IPv4 ICMP packet, if it is an echo request for `local_id`.
pub fn parse_ipv4_icmp(packet: &[u8], local_ip: Ipv4Addr, local_id: u16) -> Option<Incoming<'_>> {
    if packet.len() < IPV4_HEADER + ICMP_HEADER || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_HEADER || packet.len() < header_len + ICMP_HEADER {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + ICMP_HEADER || total_len > packet.len() {
        return None;
    }
    // Only unfragmented packets: a raw socket gets reassembled datagrams, so an offset or
    // the MF bit here means a fragment arrived on its own.
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }
    if packet[9] != IPPROTO_ICMP {
        return None;
    }
    let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let to_us = if local_ip.is_unspecified() {
        !(destination_ip.is_unspecified()
            || destination_ip.is_multicast()
            || destination_ip.is_broadcast())
    } else {
        destination_ip == local_ip
    };
    if !to_us || source_ip.is_unspecified() || source_ip.is_multicast() || source_ip.is_broadcast()
    {
        return None;
    }
    let icmp = &packet[header_len..total_len];
    if icmp[0] != ECHO_REQUEST || icmp[1] != 0 {
        return None;
    }
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    if id != local_id {
        return None;
    }
    if !checksum_valid(icmp) {
        return None;
    }
    let src_id = u16::from_be_bytes([icmp[6], icmp[7]]);
    let payload = &icmp[ICMP_HEADER..];
    if payload.is_empty() {
        return None;
    }
    Some(Incoming {
        payload,
        peer: SocketAddrV4::new(source_ip, src_id),
        local: destination_ip,
    })
}

/// The ICMP checksum of a message whose checksum field is zeroed.
fn checksum(message: &[u8]) -> u16 {
    !checksum16(sum_words(message))
}

/// Whether a received ICMP message's checksum is correct.
fn checksum_valid(message: &[u8]) -> bool {
    checksum16(sum_words(message)) == u16::MAX
}

fn sum_words(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut words = bytes.chunks_exact(2);
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let [last] = words.remainder() {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn checksum16(mut sum: u32) -> u16 {
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn destination() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn echo(dest_id: u16, src_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        build_echo(dest_id, src_id, payload, &mut out).unwrap();
        out
    }

    /// An IPv4 packet around `icmp`, with no options.
    fn ipv4(icmp: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; IPV4_HEADER];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(IPV4_HEADER as u16 + icmp.len() as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
        packet[8] = 64;
        packet[9] = IPPROTO_ICMP;
        packet[12..16].copy_from_slice(&source().octets());
        packet[16..20].copy_from_slice(&destination().octets());
        packet.extend_from_slice(icmp);
        packet
    }

    #[test]
    fn builds_a_valid_echo() {
        let icmp = echo(3080, 50000, b"hello");
        assert_eq!(icmp.len(), ICMP_HEADER + 5);
        assert_eq!(icmp[0], ECHO_REQUEST);
        assert_eq!(icmp[1], 0);
        assert_eq!(u16::from_be_bytes([icmp[4], icmp[5]]), 3080);
        assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), 50000);
        assert_eq!(&icmp[ICMP_HEADER..], b"hello");
        assert!(checksum_valid(&icmp));
    }

    #[test]
    fn parses_what_it_builds() {
        let packet = ipv4(&echo(3080, 50000, b"payload here"));
        let got = parse_ipv4_icmp(&packet, destination(), 3080).expect("parsed");
        assert_eq!(got.payload, b"payload here");
        assert_eq!(got.peer, SocketAddrV4::new(source(), 50000));
        assert_eq!(got.local, destination());
    }

    #[test]
    fn a_listener_on_every_address_accepts_it() {
        let packet = ipv4(&echo(3080, 1, b"x"));
        let got = parse_ipv4_icmp(&packet, Ipv4Addr::UNSPECIFIED, 3080).expect("parsed");
        assert_eq!(got.local, destination());
    }

    #[test]
    fn rejects_another_id() {
        let packet = ipv4(&echo(3080, 50000, b"x"));
        assert!(parse_ipv4_icmp(&packet, destination(), 3081).is_none());
    }

    #[test]
    fn rejects_a_reply_or_other_type() {
        let mut icmp = echo(3080, 50000, b"x");
        icmp[0] = 0; // echo reply (what the kernel sends back)
        icmp[2..4].copy_from_slice(&[0, 0]);
        let fixed = checksum(&icmp);
        icmp[2..4].copy_from_slice(&fixed.to_be_bytes());
        assert!(parse_ipv4_icmp(&ipv4(&icmp), destination(), 3080).is_none());
    }

    #[test]
    fn rejects_a_bad_checksum() {
        let mut packet = ipv4(&echo(3080, 50000, b"x"));
        let last = packet.len() - 1;
        packet[last] ^= 0xff;
        assert!(parse_ipv4_icmp(&packet, destination(), 3080).is_none());
    }

    #[test]
    fn rejects_the_wrong_protocol() {
        let mut packet = ipv4(&echo(3080, 50000, b"x"));
        packet[9] = 6; // tcp
        assert!(parse_ipv4_icmp(&packet, destination(), 3080).is_none());
    }

    #[test]
    fn rejects_an_empty_payload() {
        let packet = ipv4(&echo(3080, 50000, b""));
        assert!(parse_ipv4_icmp(&packet, destination(), 3080).is_none());
    }

    #[test]
    fn a_short_packet_is_not_parsed() {
        assert!(parse_ipv4_icmp(&[0x45, 0, 0], destination(), 3080).is_none());
    }
}
