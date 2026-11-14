//! The DNS message framing of a `dns` packet.
//!
//! Wormhole is a direct server-to-server tunnel, so a `dns` packet does not pass through a
//! recursive resolver: it only has to look like DNS to a filter that watches UDP port 53.
//! So one sealed KCP packet is carried whole in the resource data of one record, not
//! encoded into the query name (which a real resolver would cap at 255 bytes) — the dialer
//! sends it as a standard query, the listener as the matching response:
//!
//! ```text
//!  header       id, flags (query or response), one question, one record
//!  question     a plausible name under a base domain, with a random leading label
//!  record       TYPE=NULL, and the sealed KCP packet as its RDATA
//! ```
//!
//! The query carries the record in the additional section and the response in the answer
//! section, which is where each normally sits. The name is cosmetic — the decoder skips it
//! — so a fresh random label on every message makes each query a distinct subdomain, as
//! ordinary DNS traffic is.

use std::io;

/// DNS header: id, flags, and the four section counts.
const HEADER: usize = 12;
/// `TYPE` and `CLASS` of the resource record, and `QTYPE`/`QCLASS` of the question.
const TYPE_NULL: u16 = 10;
const CLASS_IN: u16 = 1;
/// A compression pointer to the question's name at offset [`HEADER`] (`0b11` then the
/// offset): the record's owner name, two bytes instead of repeating the labels.
const NAME_POINTER: u16 = 0xC000 | HEADER as u16;
/// The base domain of the question name, after a random leading label. Reserved for
/// documentation (RFC 6761), so it is never a real host; cosmetic (the decoder skips it).
const BASE_DOMAIN: &[&[u8]] = &[b"example", b"net"];
/// Bytes of random hex in the leading label of the question name.
const LABEL_BYTES: usize = 8;

/// The most a record's RDATA may hold (`RDLENGTH` is 16-bit). Sealed KCP packets are far
/// smaller, but a decoded length is checked against it.
const MAX_RDATA: usize = u16::MAX as usize;

/// Writes a DNS message carrying `payload` into `out`: a response when `respond`, else a
/// query. `id` is the DNS transaction id (random per message, like a real client's).
pub fn encode(out: &mut Vec<u8>, respond: bool, id: u16, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_RDATA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dns payload does not fit one record",
        ));
    }
    out.clear();
    // Header. Query flags: RD set (recursion desired). Response flags: QR, RD and RA set.
    let flags: u16 = if respond { 0x8180 } else { 0x0100 };
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&u16::from(respond).to_be_bytes()); // ancount: 1 in a response
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&u16::from(!respond).to_be_bytes()); // arcount: 1 in a query

    // Question: <random>.example.net, a NULL record in the IN class.
    write_question_name(out);
    out.extend_from_slice(&TYPE_NULL.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());

    // The record carrying the payload, its name a pointer back to the question.
    out.extend_from_slice(&NAME_POINTER.to_be_bytes());
    out.extend_from_slice(&TYPE_NULL.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // TTL
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes()); // RDLENGTH
    out.extend_from_slice(payload);
    Ok(())
}

/// The payload carried in a DNS message's first record, or `None` if `datagram` is not a
/// message this module could have produced. The owner name is skipped, not checked.
pub fn decode(datagram: &[u8]) -> Option<&[u8]> {
    if datagram.len() < HEADER {
        return None;
    }
    let qdcount = u16::from_be_bytes([datagram[4], datagram[5]]);
    let records = u16::from_be_bytes([datagram[6], datagram[7]])
        + u16::from_be_bytes([datagram[10], datagram[11]]);
    if qdcount != 1 || records < 1 {
        return None;
    }
    let mut at = HEADER;
    // Question: a name, then QTYPE and QCLASS.
    at = skip_name(datagram, at)?;
    at = at.checked_add(4)?;
    if at > datagram.len() {
        return None;
    }
    // First record: a name, TYPE, CLASS, TTL, then the length-prefixed RDATA.
    at = skip_name(datagram, at)?;
    let rdlength_at = at.checked_add(8)?;
    let rdata_at = rdlength_at.checked_add(2)?;
    if rdata_at > datagram.len() {
        return None;
    }
    let rdlength = usize::from(u16::from_be_bytes([
        datagram[rdlength_at],
        datagram[rdlength_at + 1],
    ]));
    let end = rdata_at.checked_add(rdlength)?;
    if rdlength == 0 || end > datagram.len() {
        return None;
    }
    Some(&datagram[rdata_at..end])
}

/// Writes the question name `<random hex>.example.net`, terminated by the root label.
fn write_question_name(out: &mut Vec<u8>) {
    let random = crate::crypto::random_bytes::<LABEL_BYTES>().unwrap_or([0x5e; LABEL_BYTES]);
    let mut label = [0u8; LABEL_BYTES * 2];
    hex(&random, &mut label);
    out.push(label.len() as u8);
    out.extend_from_slice(&label);
    for part in BASE_DOMAIN {
        out.push(part.len() as u8);
        out.extend_from_slice(part);
    }
    out.push(0);
}

/// Advances past a DNS name starting at `at`: a run of length-prefixed labels ending in a
/// zero length, or a two-byte compression pointer. Returns the offset just after it.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let &length = message.get(at)?;
        match length & 0xC0 {
            0x00 => {
                if length == 0 {
                    return Some(at + 1);
                }
                at = at.checked_add(1 + usize::from(length))?;
            }
            0xC0 => return at.checked_add(2),
            // 0x40 and 0x80 are reserved and never produced here.
            _ => return None,
        }
    }
}

/// Lower-case hex of `bytes` into `out` (which must be twice as long).
fn hex(bytes: &[u8], out: &mut [u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (byte, pair) in bytes.iter().zip(out.chunks_exact_mut(2)) {
        pair[0] = DIGITS[usize::from(byte >> 4)];
        pair[1] = DIGITS[usize::from(byte & 0x0f)];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_round_trips() {
        let mut out = Vec::new();
        encode(&mut out, false, 0x1234, b"a sealed packet").unwrap();
        // A query: QR clear, one question, no answer, one additional.
        assert_eq!(out[2] & 0x80, 0);
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 0); // ancount
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 1); // arcount
        assert_eq!(decode(&out).unwrap(), b"a sealed packet");
    }

    #[test]
    fn a_response_round_trips() {
        let mut out = Vec::new();
        encode(&mut out, true, 0x1234, b"the answer bytes").unwrap();
        assert_eq!(out[2] & 0x80, 0x80); // QR set
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 1); // ancount
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 0); // arcount
        assert_eq!(decode(&out).unwrap(), b"the answer bytes");
    }

    #[test]
    fn the_id_is_carried() {
        let mut out = Vec::new();
        encode(&mut out, false, 0xBEEF, b"x").unwrap();
        assert_eq!(u16::from_be_bytes([out[0], out[1]]), 0xBEEF);
    }

    #[test]
    fn every_query_name_differs() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        encode(&mut a, false, 1, b"x").unwrap();
        encode(&mut b, false, 1, b"x").unwrap();
        assert_ne!(a, b); // the random leading label
        assert_eq!(decode(&a).unwrap(), b"x");
    }

    #[test]
    fn a_full_size_payload_fits() {
        let payload = vec![0x42u8; 1471];
        let mut out = Vec::new();
        encode(&mut out, true, 7, &payload).unwrap();
        assert_eq!(decode(&out).unwrap(), &payload[..]);
    }

    #[test]
    fn junk_is_rejected() {
        assert!(decode(b"").is_none());
        assert!(decode(&[0u8; 8]).is_none());
        // A header that claims a payload longer than the datagram.
        let mut out = Vec::new();
        encode(&mut out, false, 1, b"hello").unwrap();
        assert!(decode(&out[..out.len() - 2]).is_none());
    }

    #[test]
    fn a_non_dns_datagram_is_rejected() {
        // qdcount 0: not one of ours.
        let mut out = Vec::new();
        encode(&mut out, false, 1, b"hello").unwrap();
        out[4] = 0;
        out[5] = 0;
        assert!(decode(&out).is_none());
    }
}
