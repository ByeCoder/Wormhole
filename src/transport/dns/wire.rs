//! The DNS messages of the resolver path (`[tunnel.dns]`): what a recursive resolver will
//! carry between the dialing side and the authoritative listener.
//!
//! A resolver only forwards what DNS allows, so the two directions differ:
//!
//! ```text
//!  upstream    a TXT query for <data>.<domain>: the data in the query name, base32
//!              (case-insensitive, as resolvers may change the case), 63-character labels
//!  downstream  the TXT answer to that query: the data in its character-strings, as is
//!              (or base64, for resolvers that mangle bytes outside text)
//! ```
//!
//! The data of a query is a header and one fragment of a packet:
//!
//! ```text
//!  session  4   the dialing side's random session (one per KCP connection); 0: a probe
//!  nonce    2   a counter, so no two names are the same and no resolver answers from cache
//!  packet   2   the packet's number in the session (a probe: the answer size it asks for)
//!  index    1   this fragment's index
//!  count    1   the packet's fragment count (0: no data, a poll: a way for the listener
//!               to answer)
//!  down     1   the most an answer through this resolver may carry, in 8-byte units
//!               (0: whatever the query's EDNS0 buffer allows)
//!  flags    1   bit 0: answer in base64
//!  data     …   the fragment (a probe: 8 bytes to echo, then padding)
//! ```
//!
//! The data of an answer is a flags byte (bit 0: the listener has more waiting) and
//! fragments of packets: length (2), packet number (2), index (1), last (1: 1 for the
//! packet's last fragment), bytes. Each answer can take a fragment of its own size, as the
//! resolvers that carry them allow different sizes. A probe's answer is `P`, the 8 bytes it
//! was sent, and filler up to the size asked for.

use std::io;

use base64::Engine as _;

/// The DNS header: id, flags and the four section counts.
pub const HEADER: usize = 12;
pub const TYPE_TXT: u16 = 16;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
/// The EDNS0 buffer both sides offer: the size the DNS flag day of 2020 settled on.
pub const EDNS_SIZE: u16 = 1232;
/// A name's text is at most 253 characters (255 bytes on the wire).
const MAX_NAME_TEXT: usize = 253;
const MAX_LABEL: usize = 63;
/// The query data header.
pub const QUERY_HEADER: usize = 12;
/// What each fragment of an answer adds: length, packet, index, last.
pub const ANSWER_FRAGMENT_HEADER: usize = 6;
/// Fragments per packet, either way.
pub const MAX_FRAGMENTS: usize = 255;
/// The bytes a probe echoes.
pub const PROBE_TOKEN: usize = 8;
/// Answer flags.
pub const MORE: u8 = 1;
/// Query flags.
pub const BASE64: u8 = 1;

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// What one query carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream<'a> {
    pub session: u32,
    pub nonce: u16,
    pub packet: u16,
    pub index: u8,
    /// The fragment count (0: a poll).
    pub count: u8,
    /// The most an answer may carry, in 8-byte units (0: no limit but the buffer's).
    pub down: u8,
    pub flags: u8,
    pub data: &'a [u8],
}

impl Upstream<'_> {
    /// A probe: no session, the size of the answer it asks for, and its token.
    pub fn is_probe(&self) -> bool {
        self.session == 0
    }
}

/// A tunnel domain, as labels, checked once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    labels: Vec<Vec<u8>>,
    /// Its text length (dots between labels, none at the end).
    text: usize,
    name: String,
}

impl Domain {
    pub fn parse(name: &str) -> io::Result<Self> {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let bad = |why: &str| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("dns domain {name:?}: {why}"),
            )
        };
        if name.is_empty() {
            return Err(bad("empty"));
        }
        let labels: Vec<Vec<u8>> = name.split('.').map(|l| l.as_bytes().to_vec()).collect();
        for label in &labels {
            if label.is_empty() || label.len() > MAX_LABEL {
                return Err(bad("a label is empty or longer than 63 characters"));
            }
            if !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            {
                return Err(bad("only letters, digits, dashes and dots"));
            }
        }
        let text = name.len();
        if text > 200 {
            return Err(bad(
                "too long to leave room for data (at most 200 characters)",
            ));
        }
        Ok(Self { labels, text, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// How many bytes of query data (header included) fit one name under this domain.
    pub fn query_capacity(&self) -> usize {
        // Data characters c, in ceil(c/63) labels, each followed by a dot, then the domain.
        let room = MAX_NAME_TEXT - self.text;
        let mut chars = room;
        while chars + chars.div_ceil(MAX_LABEL) > room {
            chars -= 1;
        }
        chars * 5 / 8
    }

    /// The name's labels before the domain, or `None` if `labels` is not under it.
    fn strip<'a>(&self, labels: &'a [Vec<u8>]) -> Option<&'a [Vec<u8>]> {
        let n = labels.len().checked_sub(self.labels.len())?;
        let tail = &labels[n..];
        tail.iter()
            .zip(&self.labels)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
            .then_some(&labels[..n])
    }
}

/// Writes a TXT query for `up` under `domain`, with an EDNS0 record offering
/// [`EDNS_SIZE`]: the dialing side's message to a resolver. Fails if `up` does not fit
/// the name.
pub fn encode_query(
    out: &mut Vec<u8>,
    id: u16,
    domain: &Domain,
    up: &Upstream<'_>,
) -> io::Result<()> {
    let mut raw = Vec::with_capacity(QUERY_HEADER + up.data.len());
    raw.extend_from_slice(&up.session.to_be_bytes());
    raw.extend_from_slice(&up.nonce.to_be_bytes());
    raw.extend_from_slice(&up.packet.to_be_bytes());
    raw.push(up.index);
    raw.push(up.count);
    raw.push(up.down);
    raw.push(up.flags);
    raw.extend_from_slice(up.data);
    if raw.len() > domain.query_capacity() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dns query data too long",
        ));
    }
    let text = base32(&raw);
    out.clear();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD: a resolver resolves it
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&0u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&1u16.to_be_bytes()); // arcount: the OPT record
    for label in text.chunks(MAX_LABEL) {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    for label in &domain.labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    write_opt(out);
    Ok(())
}

/// An empty OPT record offering [`EDNS_SIZE`].
fn write_opt(out: &mut Vec<u8>) {
    out.push(0); // root name
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&EDNS_SIZE.to_be_bytes()); // CLASS: the UDP payload size
    out.extend_from_slice(&0u32.to_be_bytes()); // extended rcode, version, flags
    out.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
}

/// A query as the listener sees it: what it needs to answer, and the tunnel data if the
/// name carries any.
#[derive(Debug)]
pub struct Query<'a> {
    pub id: u16,
    /// The question section as it came (the answer repeats it).
    pub question: &'a [u8],
    pub qtype: u16,
    /// Recursion desired, echoed in the answer.
    pub rd: bool,
    /// The EDNS0 buffer the asker offers; `None`: no OPT record (512 bytes).
    pub edns: Option<u16>,
    /// Whether the name is under one of the tunnel domains, and the data its leading
    /// labels decode to (`None` for a domain itself, a name it does not decode, or another
    /// type).
    pub under: bool,
    pub data: Option<Vec<u8>>,
}

/// Reads a query for the listener. `None` for anything that is not a one-question query.
pub fn decode_query<'a>(message: &'a [u8], domains: &[Domain]) -> Option<Query<'a>> {
    if message.len() < HEADER || message[2] & 0x80 != 0 {
        return None;
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    let rd = message[2] & 0x01 != 0;
    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    let ancount = u16::from_be_bytes([message[6], message[7]]);
    let nscount = u16::from_be_bytes([message[8], message[9]]);
    let arcount = u16::from_be_bytes([message[10], message[11]]);
    if qdcount != 1 {
        return None;
    }
    let (labels, after_name) = read_name(message, HEADER)?;
    let end = after_name.checked_add(4)?;
    if end > message.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([message[after_name], message[after_name + 1]]);
    let question = &message[HEADER..end];
    // The OPT record, if any, among the additional records (after any others).
    let mut at = end;
    let mut edns = None;
    for i in 0..(u32::from(ancount) + u32::from(nscount) + u32::from(arcount)) {
        let (_, after) = read_name(message, at)?;
        let fixed = after.checked_add(10)?;
        if fixed > message.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([message[after], message[after + 1]]);
        let class = u16::from_be_bytes([message[after + 2], message[after + 3]]);
        let rdlen = usize::from(u16::from_be_bytes([message[after + 8], message[after + 9]]));
        if rtype == TYPE_OPT && i >= u32::from(ancount) + u32::from(nscount) {
            edns = Some(class.max(512));
        }
        at = fixed.checked_add(rdlen)?;
    }
    let data_labels = domains.iter().find_map(|d| d.strip(&labels));
    let under = data_labels.is_some();
    let data = match data_labels {
        Some(data) if !data.is_empty() && qtype == TYPE_TXT => {
            let mut text = Vec::with_capacity(data.iter().map(Vec::len).sum());
            for label in data {
                text.extend_from_slice(label);
            }
            unbase32(&text).filter(|d| d.len() >= QUERY_HEADER)
        }
        _ => None,
    };
    Some(Query {
        id,
        question,
        qtype,
        rd,
        edns,
        under,
        data,
    })
}

/// Splits query data into its fields.
pub fn parse_upstream(data: &[u8]) -> Option<Upstream<'_>> {
    if data.len() < QUERY_HEADER {
        return None;
    }
    let (index, count) = (data[8], data[9]);
    if count != 0 && index >= count {
        return None;
    }
    Some(Upstream {
        session: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        nonce: u16::from_be_bytes([data[4], data[5]]),
        packet: u16::from_be_bytes([data[6], data[7]]),
        index,
        count,
        down: data[10],
        flags: data[11],
        data: &data[QUERY_HEADER..],
    })
}

/// How a listener answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer<'a> {
    /// A TXT record holding `payload` (as is, or base64 when the query asked for it).
    Data(&'a [u8]),
    /// No records: a name of the domain with nothing to say (NOERROR, NODATA).
    Empty,
    /// Not this listener's domain (REFUSED).
    Refused,
}

/// The TXT bytes an answer to `query` may hold: what fits the asker's buffer after the
/// header, the question, the record and the OPT record.
fn txt_capacity(query: &Query<'_>) -> usize {
    let buffer = usize::from(query.edns.unwrap_or(512).min(EDNS_SIZE));
    let opt = if query.edns.is_some() { 11 } else { 0 };
    let fixed = HEADER + query.question.len() + 12 + opt;
    let room = buffer.saturating_sub(fixed);
    // One length byte per 255 bytes of character-string.
    room.saturating_sub(room.div_ceil(256))
}

/// The payload an answer to `query` may carry, before any base64: the buffer's room, and
/// no more than the dialing side asked for (`down`, a resolver's measured size).
pub fn answer_capacity(query: &Query<'_>, down: u8, base64: bool) -> usize {
    let mut cap = txt_capacity(query);
    if base64 {
        cap = cap / 4 * 3;
    }
    if down > 0 {
        cap = cap.min(usize::from(down) * 8);
    }
    cap
}

/// Writes the listener's answer to `query`, its payload in base64 if `base64`.
pub fn encode_answer(out: &mut Vec<u8>, query: &Query<'_>, answer: Answer<'_>, base64: bool) {
    let encoded;
    let answer = match answer {
        Answer::Data(payload) if base64 => {
            encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(payload);
            Answer::Data(encoded.as_bytes())
        }
        other => other,
    };
    out.clear();
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR, AA (the listener is the domain's server), RD echoed; the rcode last.
    let rcode: u16 = if answer == Answer::Refused { 5 } else { 0 };
    let flags = 0x8400 | if query.rd { 0x0100 } else { 0 } | rcode;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    let records = u16::from(matches!(answer, Answer::Data(_)));
    out.extend_from_slice(&records.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&u16::from(query.edns.is_some()).to_be_bytes());
    out.extend_from_slice(query.question);
    if let Answer::Data(payload) = answer {
        out.extend_from_slice(&(0xC000u16 | HEADER as u16).to_be_bytes());
        out.extend_from_slice(&TYPE_TXT.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL 0: never cached
        let strings = payload.len().div_ceil(255).max(1);
        out.extend_from_slice(&((payload.len() + strings) as u16).to_be_bytes());
        if payload.is_empty() {
            out.push(0);
        }
        for chunk in payload.chunks(255) {
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
    }
    if query.edns.is_some() {
        write_opt(out);
    }
}

/// An answer as the dialing side reads it.
#[derive(Debug)]
pub struct Response {
    pub id: u16,
    /// The DNS rcode (0: no error).
    pub rcode: u8,
    /// Whether the resolver cut the answer short (TC).
    pub truncated: bool,
    /// The TXT payload of the first TXT answer, its strings joined (still base64 if it
    /// was asked so).
    pub payload: Option<Vec<u8>>,
}

/// Reads a resolver's answer.
pub fn decode_response(message: &[u8]) -> Option<Response> {
    if message.len() < HEADER || message[2] & 0x80 == 0 {
        return None;
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    let truncated = message[2] & 0x02 != 0;
    let rcode = message[3] & 0x0f;
    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    let ancount = u16::from_be_bytes([message[6], message[7]]);
    let mut at = HEADER;
    for _ in 0..qdcount {
        at = read_name(message, at)?.1.checked_add(4)?;
    }
    let mut payload = None;
    for _ in 0..ancount {
        let after = read_name(message, at)?.1;
        let fixed = after.checked_add(10)?;
        if fixed > message.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([message[after], message[after + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([message[after + 8], message[after + 9]]));
        let end = fixed.checked_add(rdlen)?;
        if end > message.len() {
            return None;
        }
        if rtype == TYPE_TXT && payload.is_none() {
            let mut joined = Vec::with_capacity(rdlen);
            let mut s = fixed;
            while s < end {
                let len = usize::from(message[s]);
                let next = s + 1 + len;
                if next > end {
                    return None;
                }
                joined.extend_from_slice(&message[s + 1..next]);
                s = next;
            }
            payload = Some(joined);
        }
        at = end;
    }
    Some(Response {
        id,
        rcode,
        truncated,
        payload,
    })
}

/// The payload of an answer, decoded from base64 if it was asked so.
pub fn answer_payload(payload: Vec<u8>, base64: bool) -> Option<Vec<u8>> {
    if base64 {
        base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(payload.trim_ascii())
            .ok()
    } else {
        Some(payload)
    }
}

/// One fragment of a packet in an answer.
#[derive(Debug, PartialEq, Eq)]
pub struct DownFragment<'a> {
    pub packet: u16,
    pub index: u8,
    /// Whether it is the packet's last fragment.
    pub last: bool,
    pub data: &'a [u8],
}

/// Appends a fragment to an answer payload.
pub fn push_fragment(payload: &mut Vec<u8>, f: &DownFragment<'_>) {
    payload.extend_from_slice(&(f.data.len() as u16).to_be_bytes());
    payload.extend_from_slice(&f.packet.to_be_bytes());
    payload.push(f.index);
    payload.push(u8::from(f.last));
    payload.extend_from_slice(f.data);
}

/// The flags and fragments of an answer payload.
pub fn read_fragments(payload: &[u8]) -> Option<(u8, Vec<DownFragment<'_>>)> {
    let (&flags, mut rest) = payload.split_first()?;
    let mut out = Vec::new();
    while rest.len() >= ANSWER_FRAGMENT_HEADER {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let data = rest.get(ANSWER_FRAGMENT_HEADER..ANSWER_FRAGMENT_HEADER + len)?;
        if rest[5] > 1 {
            return None;
        }
        out.push(DownFragment {
            packet: u16::from_be_bytes([rest[2], rest[3]]),
            index: rest[4],
            last: rest[5] == 1,
            data,
        });
        rest = &rest[ANSWER_FRAGMENT_HEADER + len..];
    }
    Some((flags, out))
}

/// The answer payload of a probe: `P`, its token, and filler up to `size` bytes.
pub fn probe_answer(token: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size.max(1 + PROBE_TOKEN));
    out.push(b'P');
    out.extend_from_slice(&token[..PROBE_TOKEN.min(token.len())]);
    let mut x = 0x5Au8;
    while out.len() < size {
        out.push(x);
        x = x.wrapping_mul(31).wrapping_add(7);
    }
    out
}

/// Reads the name at `at`, following compression pointers: its labels, and the offset
/// just after it where it starts.
fn read_name(message: &[u8], mut at: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let mut labels = Vec::new();
    let mut after = None;
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        let &length = message.get(at)?;
        match length & 0xC0 {
            0x00 => {
                if length == 0 {
                    return Some((labels, after.unwrap_or(at + 1)));
                }
                let start = at + 1;
                let end = start.checked_add(usize::from(length))?;
                total += usize::from(length) + 1;
                if total > 255 {
                    return None;
                }
                labels.push(message.get(start..end)?.to_vec());
                at = end;
            }
            0xC0 => {
                let pointer =
                    usize::from(u16::from_be_bytes([length, *message.get(at + 1)?]) & 0x3FFF);
                after.get_or_insert(at + 2);
                jumps += 1;
                if jumps > 16 || pointer >= at {
                    return None;
                }
                at = pointer;
            }
            _ => return None,
        }
    }
}

/// Base32 (RFC 4648, lower case, no padding).
fn base32(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize]);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize]);
    }
    out
}

/// The bytes of base32 text, in either case; `None` for any other character.
fn unbase32(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &c in text {
        let value = match c.to_ascii_lowercase() {
            c @ b'a'..=b'z' => c - b'a',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains() -> Vec<Domain> {
        vec![
            Domain::parse("t.example.com").unwrap(),
            Domain::parse("x.other.org").unwrap(),
        ]
    }

    fn up(data: &[u8]) -> Upstream<'_> {
        Upstream {
            session: 0xDEAD_BEEF,
            nonce: 7,
            packet: 300,
            index: 2,
            count: 5,
            down: 40,
            flags: BASE64,
            data,
        }
    }

    #[test]
    fn base32_round_trips_in_either_case() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = base32(&data);
            assert_eq!(unbase32(&text).unwrap(), data);
            // A resolver may randomise the case of the name (0x20 encoding).
            let upper: Vec<u8> = text.iter().map(u8::to_ascii_uppercase).collect();
            assert_eq!(unbase32(&upper).unwrap(), data);
        }
        assert!(unbase32(b"ab-c").is_none());
    }

    #[test]
    fn a_query_carries_its_fragment_under_any_of_the_domains() {
        for d in &domains() {
            let cap = d.query_capacity() - QUERY_HEADER;
            assert!(cap > 120, "{cap}");
            let data = vec![0xA5u8; cap];
            let mut out = Vec::new();
            encode_query(&mut out, 0x4242, d, &up(&data)).unwrap();
            let q = decode_query(&out, &domains()).unwrap();
            assert_eq!(
                (q.id, q.qtype, q.rd, q.edns),
                (0x4242, TYPE_TXT, true, Some(EDNS_SIZE))
            );
            assert!(q.under);
            assert_eq!(parse_upstream(&q.data.unwrap()).unwrap(), up(&data));
            // One byte more does not fit.
            let more = vec![0u8; cap + 1];
            assert!(encode_query(&mut out, 1, d, &up(&more)).is_err());
        }
    }

    #[test]
    fn names_outside_the_domains_carry_no_data() {
        let mut out = Vec::new();
        encode_query(&mut out, 1, &Domain::parse("nope.net").unwrap(), &up(&[])).unwrap();
        let q = decode_query(&out, &domains()).unwrap();
        assert!(!q.under && q.data.is_none());
    }

    #[test]
    fn answers_carry_fragments_as_is_or_in_base64_and_fit() {
        let ds = domains();
        let mut query = Vec::new();
        encode_query(&mut query, 77, &ds[0], &up(&[])).unwrap();
        let q = decode_query(&query, &ds).unwrap();
        for base64 in [false, true] {
            let cap = answer_capacity(&q, 0, base64);
            let mut payload = vec![MORE];
            let data = vec![0x5Au8; cap - 1 - ANSWER_FRAGMENT_HEADER];
            push_fragment(
                &mut payload,
                &DownFragment {
                    packet: 9,
                    index: 1,
                    last: true,
                    data: &data,
                },
            );
            assert_eq!(payload.len(), cap);
            let mut out = Vec::new();
            encode_answer(&mut out, &q, Answer::Data(&payload), base64);
            assert!(out.len() <= usize::from(EDNS_SIZE), "{}", out.len());
            let r = decode_response(&out).unwrap();
            assert_eq!((r.id, r.rcode, r.truncated), (77, 0, false));
            let got = answer_payload(r.payload.unwrap(), base64).unwrap();
            let (flags, frags) = read_fragments(&got).unwrap();
            assert_eq!(flags, MORE);
            assert_eq!(
                frags,
                [DownFragment {
                    packet: 9,
                    index: 1,
                    last: true,
                    data: &data
                }]
            );
        }
        // A resolver's measured size caps it.
        assert_eq!(answer_capacity(&q, 40, false), 320);
        let mut out = Vec::new();
        encode_answer(&mut out, &q, Answer::Empty, false);
        assert!(decode_response(&out).unwrap().payload.is_none());
        encode_answer(&mut out, &q, Answer::Refused, false);
        assert_eq!(decode_response(&out).unwrap().rcode, 5);
    }

    #[test]
    fn a_probe_answer_echoes_its_token() {
        let a = probe_answer(b"12345678", 300);
        assert_eq!(a.len(), 300);
        assert_eq!(&a[..9], b"P12345678");
    }

    #[test]
    fn junk_is_not_a_query() {
        let ds = domains();
        assert!(decode_query(b"", &ds).is_none());
        assert!(decode_query(&[0u8; 11], &ds).is_none());
        let mut out = Vec::new();
        encode_query(&mut out, 1, &ds[0], &up(&[])).unwrap();
        assert!(decode_query(&out[..out.len() - 15], &ds).is_none());
        assert!(decode_response(&out).is_none(), "a query is not a response");
        assert!(
            read_fragments(&[0, 0, 1, 0, 1, 0, 7, 9]).is_none(),
            "bad last byte"
        );
    }

    #[test]
    fn a_bad_domain_is_refused() {
        assert!(Domain::parse("").is_err());
        assert!(Domain::parse("a..b").is_err());
        assert!(Domain::parse("bad_name.com").is_err());
        assert!(Domain::parse(&"a".repeat(201)).is_err());
        assert_eq!(
            Domain::parse("T.Example.COM.").unwrap().name(),
            "t.example.com"
        );
    }
}
