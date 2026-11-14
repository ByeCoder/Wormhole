//! `transport = "xhttp"`: the tunnel streamed over an ordinary HTTP/1.1 request and
//! response, like XHTTP in Xray. The dialing side sends a `POST` whose chunked body is the
//! upstream, the listening side answers `200` whose chunked body is the downstream, and
//! both bodies stay open for the life of the connection (the "stream-one" shape):
//!
//! ```text
//!  POST /... HTTP/1.1            headers once, then the body streams up
//!  Transfer-Encoding: chunked
//!  <hex len>\r\n<bytes>\r\n ...  the tunnel's bytes, one HTTP chunk per write
//!
//!  HTTP/1.1 200 OK              headers once, then the body streams down
//!  Transfer-Encoding: chunked
//!  <hex len>\r\n<bytes>\r\n ...
//! ```
//!
//! It is for paths that pass only plain HTTP, or that sit behind an HTTP CDN or reverse
//! proxy. This phase is cleartext HTTP/1.1 over TCP; TLS is layered by the caller the same
//! way `wss` layers it over `ws`. The handshake runs once on the whole stream; afterwards
//! each half carries one direction, [`XhttpWriter`] chunk-encoding and [`XhttpReader`]
//! de-chunking, so the layers above see a plain byte stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

/// The most tunnel bytes put in one HTTP chunk, so one write becomes a bounded chunk.
const MAX_CHUNK: usize = 16 * 1024;
/// The most header bytes read before the body, so a peer cannot make us buffer forever.
const MAX_HEADERS: usize = 16 * 1024;
/// A plausible request path and headers, so the exchange looks like a streaming upload.
const PATH: &str = "/";

/// Writes the client request headers and reads the `200` response headers, returning any
/// body bytes read past them (the start of the chunked downstream).
pub async fn client_handshake(stream: &mut TcpStream, host: &str) -> io::Result<Vec<u8>> {
    let request = format!(
        "POST {PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0\r\n\
         Accept: */*\r\n\
         Content-Type: application/octet-stream\r\n\
         Transfer-Encoding: chunked\r\n\
         Cache-Control: no-store\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let (head, rest) = read_head(stream).await?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    if response.parse(&head).is_err() || response.code != Some(200) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xhttp server did not answer 200",
        ));
    }
    Ok(rest)
}

/// Reads the client request headers and writes the `200` response headers, returning any
/// body bytes read past the request headers (the start of the chunked upstream).
pub async fn server_handshake(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let (head, rest) = read_head(stream).await?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    if request.parse(&head).is_err() || request.method != Some("POST") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xhttp client did not send a POST",
        ));
    }
    let response = "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Transfer-Encoding: chunked\r\n\
         Cache-Control: no-store\r\n\
         \r\n";
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(rest)
}

/// Reads until the end of the HTTP headers (`\r\n\r\n`), returning the header bytes (up to
/// and including the blank line) and the bytes read past them.
async fn read_head(stream: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "xhttp peer closed before the headers ended",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let rest = buf.split_off(pos);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xhttp headers too long",
            ));
        }
    }
}

/// The offset just past the `\r\n\r\n` that ends the headers, if present.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// The state of the chunked-body parser, carried across reads.
enum Chunk {
    /// Collecting the hex size line (the bytes so far, without the `\r\n`).
    Size,
    /// Inside a chunk's data, with this many bytes still to come.
    Data(usize),
    /// Expecting the `\r\n` that ends a chunk's data.
    Crlf,
    /// The zero-size chunk was seen: the stream has ended.
    Done,
}

/// The read half: an HTTP chunked body de-chunked to a byte stream.
pub struct XhttpReader {
    inner: OwnedReadHalf,
    /// Bytes received but not yet parsed past the chunk framing.
    raw: BytesMut,
    /// De-chunked payload ready to hand to a reader.
    ready: BytesMut,
    state: Chunk,
}

/// The write half: tunnel bytes chunk-encoded onto an HTTP body.
pub struct XhttpWriter {
    inner: OwnedWriteHalf,
    /// A framed chunk not yet fully written, and how many of its bytes were the caller's
    /// payload (reported once it is all written).
    pending: Vec<u8>,
    sent: usize,
    payload: usize,
}

impl XhttpReader {
    pub fn new(inner: OwnedReadHalf, read_ahead: Vec<u8>) -> Self {
        Self {
            inner,
            raw: BytesMut::from(&read_ahead[..]),
            ready: BytesMut::new(),
            state: Chunk::Size,
        }
    }

    /// Moves as much of `raw` as possible into `ready`, stripping the chunk framing.
    fn dechunk(&mut self) -> io::Result<()> {
        dechunk(&mut self.raw, &mut self.ready, &mut self.state)
    }
}

/// Moves as much of `raw` as possible into `ready`, stripping the HTTP chunk framing.
/// `state` carries the parse across reads. Errors on a malformed size line or chunk.
fn dechunk(raw: &mut BytesMut, ready: &mut BytesMut, state: &mut Chunk) -> io::Result<()> {
    loop {
        match *state {
            Chunk::Done => return Ok(()),
            Chunk::Size => {
                let Some(line_end) = find_crlf(raw) else {
                    if raw.len() > 64 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "xhttp chunk size line too long",
                        ));
                    }
                    return Ok(());
                };
                let line = raw.split_to(line_end + 2);
                // The size is hex, up to an optional `;` extension.
                let hex = &line[..line_end];
                let hex = hex.split(|&b| b == b';').next().unwrap_or(hex);
                let text = std::str::from_utf8(hex)
                    .ok()
                    .map(str::trim)
                    .ok_or_else(bad_chunk)?;
                let size = usize::from_str_radix(text, 16).map_err(|_| bad_chunk())?;
                *state = if size == 0 {
                    Chunk::Done
                } else {
                    Chunk::Data(size)
                };
            }
            Chunk::Data(remaining) => {
                if raw.is_empty() {
                    return Ok(());
                }
                let take = remaining.min(raw.len());
                ready.extend_from_slice(&raw.split_to(take));
                *state = if remaining == take {
                    Chunk::Crlf
                } else {
                    Chunk::Data(remaining - take)
                };
            }
            Chunk::Crlf => {
                if raw.len() < 2 {
                    return Ok(());
                }
                let crlf = raw.split_to(2);
                if &crlf[..] != b"\r\n" {
                    return Err(bad_chunk());
                }
                *state = Chunk::Size;
            }
        }
    }
}

fn bad_chunk() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed xhttp chunk")
}

/// The offset of the first `\r\n` in `buf`, if any.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

impl AsyncRead for XhttpReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.ready.is_empty() {
                let n = this.ready.len().min(buf.remaining());
                buf.put_slice(&this.ready.split_to(n));
                return Poll::Ready(Ok(()));
            }
            this.dechunk()?;
            if !this.ready.is_empty() {
                continue;
            }
            if matches!(this.state, Chunk::Done) {
                return Poll::Ready(Ok(())); // clean end of the body
            }
            // Read more raw bytes into a scratch, then into `raw`.
            let mut scratch = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        // The socket closed mid-body.
                        return Poll::Ready(Ok(()));
                    }
                    this.raw.extend_from_slice(filled);
                }
            }
        }
    }
}

impl XhttpWriter {
    pub fn new(inner: OwnedWriteHalf) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            sent: 0,
            payload: 0,
        }
    }

    /// Writes the pending framed chunk. `Ready(Ok(()))` once it is fully sent.
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.sent..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "xhttp stream closed",
                    )))
                }
                Poll::Ready(Ok(n)) => self.sent += n,
            }
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

/// Frames `payload` as one HTTP chunk into `out`.
fn chunk(payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
}

impl AsyncWrite for XhttpWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let payload = &buf[..buf.len().min(MAX_CHUNK)];
            let mut framed = Vec::with_capacity(payload.len() + 16);
            chunk(payload, &mut framed);
            this.pending = framed;
            this.payload = payload.len();
        }
        match this.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(this.payload)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Finish any pending chunk, then the terminating zero-size chunk.
        if this.pending.is_empty() && this.payload != usize::MAX {
            this.pending = b"0\r\n\r\n".to_vec();
            this.sent = 0;
            this.payload = usize::MAX; // mark the terminator as queued
        }
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// An xhttp tunnel stream: the two halves together, so it fits the stream type and splits
/// back into independent halves without a lock.
pub struct XhttpStream {
    reader: XhttpReader,
    writer: XhttpWriter,
}

impl XhttpStream {
    pub fn new(reader: XhttpReader, writer: XhttpWriter) -> Self {
        Self { reader, writer }
    }

    pub fn into_split(self) -> (XhttpReader, XhttpWriter) {
        (self.reader, self.writer)
    }

    /// A cheap, non-blocking check that the stream has not been closed by the peer; any
    /// bytes that arrive are buffered back, so the check consumes nothing.
    pub fn is_alive(&mut self) -> bool {
        if !self.reader.ready.is_empty() || !self.reader.raw.is_empty() {
            return true;
        }
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut probe = [0u8; 1];
        let mut rb = ReadBuf::new(&mut probe);
        match Pin::new(&mut self.reader).poll_read(&mut cx, &mut rb) {
            Poll::Pending => true,
            Poll::Ready(Ok(())) => {
                let got = rb.filled().to_vec();
                if got.is_empty() {
                    return false; // end of stream
                }
                // Put the byte back at the front of the ready buffer.
                let rest = std::mem::take(&mut self.reader.ready);
                self.reader.ready.extend_from_slice(&got);
                self.reader.ready.extend_from_slice(&rest);
                true
            }
            Poll::Ready(Err(_)) => false,
        }
    }
}

fn noop_waker() -> std::task::Waker {
    use std::sync::Arc;
    use std::task::Wake;
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    std::task::Waker::from(Arc::new(Noop))
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dechunk_all(raw: &[u8]) -> io::Result<Vec<u8>> {
        let mut raw = BytesMut::from(raw);
        let mut ready = BytesMut::new();
        let mut state = Chunk::Size;
        dechunk(&mut raw, &mut ready, &mut state)?;
        Ok(ready.to_vec())
    }

    fn encode(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        chunk(payload, &mut out);
        out
    }

    #[test]
    fn one_chunk_round_trips() {
        let mut body = encode(b"hello");
        body.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(dechunk_all(&body).unwrap(), b"hello");
    }

    #[test]
    fn several_chunks_concatenate() {
        let mut body = Vec::new();
        body.extend(encode(b"one"));
        body.extend(encode(b"two"));
        body.extend(encode(b"three"));
        assert_eq!(dechunk_all(&body).unwrap(), b"onetwothree");
    }

    #[test]
    fn a_chunk_extension_is_ignored() {
        let body = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        assert_eq!(dechunk_all(body).unwrap(), b"hello");
    }

    #[test]
    fn a_partial_body_decodes_what_it_has() {
        // Size line present, only part of the data: decode that part, wait for the rest.
        let body = b"5\r\nhel";
        assert_eq!(dechunk_all(body).unwrap(), b"hel");
    }

    #[test]
    fn a_bad_size_is_rejected() {
        assert!(dechunk_all(b"zz\r\nxx\r\n").is_err());
    }

    #[test]
    fn find_headers_end_finds_the_blank_line() {
        assert_eq!(find_headers_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(find_headers_end(b"no end yet\r\n"), None);
    }
}
