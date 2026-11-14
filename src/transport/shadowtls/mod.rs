//! `transport = "shadowtls"`: the tunnel inside a TLS connection that is made to look like
//! traffic to a real site, in the spirit of ShadowTLS and REALITY.
//!
//! What rustls allows, and what it does not: a true ShadowTLS v3 or REALITY borrows or
//! relays a *real* server's certificate and authenticates the client inside the TLS
//! handshake itself (a custom ClientHello, an HMAC over the transcript, taking the socket
//! back from the TLS library afterwards). rustls exposes none of that, so this is the
//! achievable form:
//!
//! - the **dialer** opens a normal TLS 1.3 connection to the listener, with its SNI set to
//!   a fresh `<random><hmac>.<real-site>` subdomain of a real host (the token keys the
//!   HMAC). On the wire it looks like a TLS connection to that host;
//! - the **listener** reads the ClientHello, checks the SNI's HMAC, and if it is one of
//!   ours answers the TLS handshake with an ephemeral self-signed certificate and runs the
//!   tunnel inside. A connection whose SNI does not carry a valid HMAC — an active probe —
//!   is **relayed** to the real `handshake` site, so the prober gets that site's real TLS,
//!   not a hint that anything else is here.
//!
//! The certificate the listener shows authenticated clients is self-signed (rustls cannot
//! lend it the real site's certificate), so the dialer does not verify it — exactly as
//! ShadowTLS does, because the security is the tunnel's own encryption above this layer,
//! not this TLS. This TLS is camouflage, not the tunnel's confidentiality.
//!
//! This phase supports the handshake-relay and SNI-HMAC authentication described above.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::config::TlsConfig;
use crate::crypto::Psk;
use crate::transport::tls;

/// Domain separation for the token-derived key that authenticates the SNI.
const SNI_KEY_CONTEXT: &str = "wormhole 2026-11 shadowtls sni v1";
/// Bytes of randomness and of HMAC tag in the SNI's leading label (hex-encoded, so the
/// label is `(8 + 8) * 2 = 32` characters).
const NONCE: usize = 8;
const TAG: usize = 8;
/// The most a ClientHello may be before the listener gives up (a real one is far smaller).
const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// The token-derived key the SNI's HMAC is computed with.
fn auth_key(token: &str) -> [u8; 32] {
    Psk::new(token).subkey(SNI_KEY_CONTEXT)
}

/// The tag for `nonce`: a keyed BLAKE3 hash, truncated.
fn tag(key: &[u8; 32], nonce: &[u8]) -> [u8; TAG] {
    let hash = blake3::keyed_hash(key, nonce);
    let mut out = [0u8; TAG];
    out.copy_from_slice(&hash.as_bytes()[..TAG]);
    out
}

/// The SNI a dialer sends: `<nonce><tag>.<base>`, the leading label fresh each time, so
/// every connection is a distinct subdomain of the real host.
pub fn client_sni(token: &str, base: &str) -> String {
    let nonce = crate::crypto::random_bytes::<NONCE>().unwrap_or([0x5e; NONCE]);
    let tag = tag(&auth_key(token), &nonce);
    let mut label = String::with_capacity((NONCE + TAG) * 2);
    for byte in nonce.iter().chain(tag.iter()) {
        label.push_str(&format!("{byte:02x}"));
    }
    format!("{label}.{base}")
}

/// Whether `sni`'s leading label is a valid token HMAC (a connection of ours, not a probe).
pub fn sni_is_ours(token: &str, sni: &str) -> bool {
    let label = sni.split('.').next().unwrap_or("");
    if label.len() != (NONCE + TAG) * 2 {
        return false;
    }
    let Some(bytes) = decode_hex(label) else {
        return false;
    };
    let (nonce, got) = bytes.split_at(NONCE);
    tag(&auth_key(token), nonce) == got[..]
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// The server name in a TLS ClientHello record, if it has an SNI extension. `record` is one
/// whole TLS record (its 5-byte header included). Returns `None` for anything it cannot
/// parse, so a malformed or SNI-less hello is simply treated as not ours.
pub fn sni_of(record: &[u8]) -> Option<String> {
    // TLS record: type(1)=22, version(2), length(2), then the handshake message.
    let body = record.get(5..)?;
    if record.first() != Some(&22) {
        return None;
    }
    // Handshake: type(1)=1 (ClientHello), length(3), then the body.
    if body.first() != Some(&1) {
        return None;
    }
    let mut p = Reader::new(body.get(4..)?);
    p.skip(2)?; // client_version
    p.skip(32)?; // random
    let sid = usize::from(p.u8()?);
    p.skip(sid)?; // session_id
    let cs = usize::from(p.u16()?);
    p.skip(cs)?; // cipher_suites
    let comp = usize::from(p.u8()?);
    p.skip(comp)?; // compression_methods
    let ext_total = usize::from(p.u16()?);
    let mut ext = Reader::new(p.take(ext_total)?);
    while !ext.done() {
        let kind = ext.u16()?;
        let len = usize::from(ext.u16()?);
        let data = ext.take(len)?;
        if kind == 0 {
            // server_name: list length(2), then entries of type(1) + name(len-prefixed 2).
            let mut list = Reader::new(data);
            let _list_len = list.u16()?;
            let name_type = list.u8()?;
            let name_len = usize::from(list.u16()?);
            let name = list.take(name_len)?;
            if name_type == 0 {
                return std::str::from_utf8(name).ok().map(str::to_owned);
            }
        }
    }
    None
}

/// A little big-endian byte reader that never panics.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }
}

/// Reads one whole TLS record (its 5-byte header and body) from `stream`.
async fn read_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    if header[0] != 22 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadowtls expected a TLS handshake record",
        ));
    }
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if len == 0 || len > MAX_CLIENT_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadowtls ClientHello out of range",
        ));
    }
    let mut record = vec![0u8; 5 + len];
    record[..5].copy_from_slice(&header);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}

/// A stream that yields `prefix` before reading from `inner`: used to give the TLS acceptor
/// a ClientHello the listener has already read off the socket.
/// Internal adapter, public only because it appears in [`ShadowStream`]'s type.
pub struct Prefixed {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: TcpStream,
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let left = (self.prefix.get_ref().len() as u64).saturating_sub(self.prefix.position());
        if left > 0 {
            let pos = self.prefix.position() as usize;
            let n = (left as usize).min(buf.remaining());
            let bytes = self.prefix.get_ref()[pos..pos + n].to_vec();
            buf.put_slice(&bytes);
            self.prefix.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The TLS tunnel stream: the dialing and listening sides TLS-wrap different inner types, so
/// one enum holds both and splits back into independent halves with a lock (as `wss` does).
pub enum ShadowStream {
    Client(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Server(Box<tokio_rustls::server::TlsStream<Prefixed>>),
}

impl AsyncRead for ShadowStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Client(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Self::Server(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ShadowStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Client(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Self::Server(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Client(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Self::Server(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Client(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Self::Server(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Dials the listener over `stream`: a TLS connection whose SNI carries the token HMAC under
/// `base` (the real host's name), with the server certificate not verified (the tunnel's own
/// encryption secures the data).
pub async fn connect(stream: TcpStream, token: &str, base: &str) -> io::Result<ShadowStream> {
    let sni = client_sni(token, base);
    let tls = TlsConfig {
        sni: Some(sni),
        insecure: true,
        ..TlsConfig::default()
    };
    let client = tls::Client::new(Some(&tls), base)?;
    let tls = client.connect(stream).await?;
    Ok(ShadowStream::Client(Box::new(tls)))
}

/// Accepts a connection over `stream`. If its SNI carries a valid token HMAC it is one of
/// ours: the TLS handshake is answered with an ephemeral self-signed certificate and the
/// stream returned. Otherwise it is an active probe: it is relayed to `handshake` (a real
/// TLS site) in a background task and `None` is returned.
pub async fn accept(
    mut stream: TcpStream,
    token: &str,
    handshake: &str,
) -> io::Result<Option<ShadowStream>> {
    let record = read_record(&mut stream).await?;
    let ours = sni_of(&record).is_some_and(|sni| sni_is_ours(token, &sni));
    if !ours {
        // An active probe (or junk): relay it to the real site so the prober sees that site.
        let target = handshake.to_owned();
        tokio::spawn(async move {
            if let Err(e) = relay(stream, record, &target).await {
                debug!(error = %e, "shadowtls probe relay ended");
            }
        });
        return Ok(None);
    }
    let acceptor = ephemeral_acceptor()?;
    let prefixed = Prefixed {
        prefix: std::io::Cursor::new(record),
        inner: stream,
    };
    let tls = acceptor.accept(prefixed).await?;
    Ok(Some(ShadowStream::Server(Box::new(tls))))
}

/// Relays a probe to the real `handshake` site: the ClientHello already read, then the two
/// sockets spliced, so the prober completes a real TLS handshake with that site.
async fn relay(mut client: TcpStream, client_hello: Vec<u8>, handshake: &str) -> io::Result<()> {
    let target = with_https_port(handshake);
    let mut upstream = TcpStream::connect(&target).await?;
    upstream.write_all(&client_hello).await?;
    upstream.flush().await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(|_| ())
}

/// `host:port` as given, or `host:443` when no port is present (so `handshake` may be a bare
/// host). A bracketed IPv6 literal without a port is handled too.
fn with_https_port(handshake: &str) -> String {
    let has_port = if let Some(rest) = handshake.strip_prefix('[') {
        // [ipv6]:port has a port only after the closing bracket.
        rest.rsplit_once(']')
            .is_some_and(|(_, tail)| tail.starts_with(':'))
    } else {
        handshake
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    };
    if has_port {
        handshake.to_owned()
    } else {
        format!("{handshake}:443")
    }
}

/// A TLS acceptor with a fresh in-memory self-signed certificate (camouflage only; the
/// dialer does not verify it).
fn ephemeral_acceptor() -> io::Result<tokio_rustls::TlsAcceptor> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|e| io::Error::other(format!("shadowtls could not make a certificate: {e}")))?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::from(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    );
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("shadowtls TLS config: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| io::Error::other(format!("shadowtls TLS config: {e}")))?;
    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a ClientHello record carrying `sni` (TLS 1.2 shape, enough for the parser).
    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // list len
        server_name.push(0); // host_name
        server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
        server_name.extend_from_slice(name);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // server_name ext
        ext.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        ext.extend_from_slice(&server_name);

        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression len
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut handshake = vec![1]; // ClientHello
        handshake.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn sni_round_trips_through_a_client_hello() {
        let record = client_hello("abc.example.com");
        assert_eq!(sni_of(&record).as_deref(), Some("abc.example.com"));
    }

    #[test]
    fn our_sni_is_recognised_and_a_plain_one_is_not() {
        let sni = client_sni("a-token", "www.example.com");
        assert!(sni.ends_with(".www.example.com"));
        assert!(sni_is_ours("a-token", &sni));
        // A real visitor's SNI (no HMAC label) is not ours, nor is a wrong token.
        assert!(!sni_is_ours("a-token", "www.example.com"));
        assert!(!sni_is_ours("other-token", &sni));
    }

    #[test]
    fn a_hello_with_our_sni_is_detected() {
        let sni = client_sni("tok", "site.net");
        let record = client_hello(&sni);
        assert!(sni_of(&record).is_some_and(|s| sni_is_ours("tok", &s)));
    }

    #[test]
    fn junk_and_sni_less_hellos_are_not_ours() {
        assert!(sni_of(b"not tls").is_none());
        assert!(sni_of(&[22, 3, 1, 0, 0]).is_none());
        // A ClientHello with no extensions at all.
        let mut record = client_hello("x");
        record.truncate(5 + 4 + 2 + 32 + 1); // cut inside the body
        assert!(sni_of(&record).is_none());
    }

    #[tokio::test]
    async fn authenticated_client_round_trips_over_real_tls() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let s = accept(sock, "tok", "localhost:1").await.unwrap();
            let mut s = s.expect("authenticated, not relayed");
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.flush().await.unwrap();
        });
        let sock = TcpStream::connect(addr).await.unwrap();
        let mut c = connect(sock, "tok", "localhost").await.unwrap();
        c.write_all(b"hello").await.unwrap();
        c.flush().await.unwrap();
        let mut got = [0u8; 5];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        server.await.unwrap();
    }

    #[test]
    fn the_label_length_is_checked() {
        assert!(!sni_is_ours("t", "short.example.com"));
        assert!(!sni_is_ours(
            "t",
            "zznothexzz00112233445566778899aabb.example.com"
        ));
    }
}
