//! `transport = "grpc"`: a tunnel stream carried as a bidirectional gRPC call over
//! HTTP/2, so it passes through CDNs and reverse proxies that speak gRPC/HTTP-2.
//!
//! The dialing side opens one HTTP/2 stream with a `POST` to a gRPC-looking path and
//! `content-type: application/grpc`; the listening side answers `200` and the two then
//! stream to each other. The tunnel's bytes travel in the data of gRPC length-prefixed
//! messages (a one-byte "not compressed" flag and a four-byte length), the framing a real
//! gRPC call uses, so a middlebox sees ordinary gRPC. Both ends are ours, so the message
//! boundaries carry no meaning beyond framing: [`GrpcWriter`] frames each write and
//! [`GrpcReader`] removes the framing, presenting a plain byte stream to the layers above.
//!
//! HTTP/2 is provided by the `h2` crate. Its connection must be polled to make progress,
//! so each side drives it in a background task that ends when the stream closes. This
//! phase runs over cleartext HTTP/2 (prior knowledge); TLS is layered by the caller the
//! same way `wss` layers it over `ws`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The gRPC message prefix: one compression flag (0, not compressed) and a four-byte
/// big-endian length.
const GRPC_PREFIX: usize = 5;
/// The most tunnel bytes put in one gRPC message, so one write becomes a bounded HTTP/2
/// DATA frame rather than an arbitrarily large one.
const MAX_MESSAGE: usize = 16 * 1024;
/// A gRPC-looking path and content type, so the call is indistinguishable from a real one.
const PATH: &str = "/wh.Tunnel/Stream";
const GRPC: &str = "application/grpc";

/// Frames `payload` as one gRPC message (prefix and bytes).
fn frame(payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(GRPC_PREFIX + payload.len());
    out.extend_from_slice(&[0]); // not compressed
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.freeze()
}

/// The read half: an HTTP/2 `RecvStream` whose gRPC framing is stripped to a byte stream.
pub struct GrpcReader {
    recv: RecvStream,
    /// Bytes received but not yet parsed past the framing.
    raw: BytesMut,
    /// De-framed payload ready to hand to a reader.
    ready: BytesMut,
    /// Remaining payload bytes of the message being read; 0 means a prefix comes next.
    remaining: usize,
    /// The prefix is still being gathered (fewer than [`GRPC_PREFIX`] bytes seen).
    in_prefix: bool,
    done: bool,
}

/// The write half: tunnel bytes framed as gRPC messages on an HTTP/2 `SendStream`.
pub struct GrpcWriter {
    send: SendStream<Bytes>,
    /// A framed message not yet fully handed to HTTP/2, and how many of its bytes were the
    /// caller's payload (reported once it is all sent).
    pending: Bytes,
    pending_payload: usize,
}

impl GrpcReader {
    fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            raw: BytesMut::new(),
            ready: BytesMut::new(),
            remaining: 0,
            in_prefix: true,
            done: false,
        }
    }

    /// Moves as much of `raw` as possible into `ready`, stripping the gRPC framing.
    fn deframe(&mut self) {
        deframe(
            &mut self.raw,
            &mut self.ready,
            &mut self.remaining,
            &mut self.in_prefix,
        );
    }
}

/// Moves as much of `raw` as possible into `ready`, stripping the gRPC framing. `remaining`
/// and `in_prefix` carry the parse state across calls (a message may span several reads).
fn deframe(raw: &mut BytesMut, ready: &mut BytesMut, remaining: &mut usize, in_prefix: &mut bool) {
    loop {
        if *in_prefix {
            if raw.len() < GRPC_PREFIX {
                return;
            }
            let prefix = raw.split_to(GRPC_PREFIX);
            *remaining = u32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]) as usize;
            *in_prefix = false;
        }
        if *remaining == 0 {
            *in_prefix = true;
            continue;
        }
        if raw.is_empty() {
            return;
        }
        let take = (*remaining).min(raw.len());
        ready.extend_from_slice(&raw.split_to(take));
        *remaining -= take;
        if *remaining == 0 {
            *in_prefix = true;
        }
    }
}

impl AsyncRead for GrpcReader {
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
            this.deframe();
            if !this.ready.is_empty() {
                continue;
            }
            if this.done {
                return Poll::Ready(Ok(())); // clean end of stream
            }
            match Pin::new(&mut this.recv).poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(h2_io(e))),
                Poll::Ready(Some(Ok(chunk))) => {
                    // Return the window the chunk used, so the peer may send more.
                    let _ = this.recv.flow_control().release_capacity(chunk.len());
                    this.raw.extend_from_slice(&chunk);
                }
            }
        }
    }
}

impl GrpcWriter {
    fn new(send: SendStream<Bytes>) -> Self {
        Self {
            send,
            pending: Bytes::new(),
            pending_payload: 0,
        }
    }

    /// Sends `pending` under HTTP/2 flow control. `Ready(Ok(()))` once it is empty.
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            self.send.reserve_capacity(self.pending.len());
            match self.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "grpc stream closed",
                    )))
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(h2_io(e))),
                Poll::Ready(Some(Ok(0))) => return Poll::Pending,
                Poll::Ready(Some(Ok(cap))) => {
                    let n = cap.min(self.pending.len());
                    let piece = self.pending.split_to(n);
                    if let Err(e) = self.send.send_data(piece, false) {
                        return Poll::Ready(Err(h2_io(e)));
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for GrpcWriter {
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
            let payload = &buf[..buf.len().min(MAX_MESSAGE)];
            this.pending = frame(payload);
            this.pending_payload = payload.len();
        }
        match this.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(this.pending_payload)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // HTTP/2 DATA frames leave as capacity allows; there is nothing more to flush once
        // the pending message is gone.
        self.get_mut().flush_pending(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        // End the HTTP/2 stream with an empty final data frame.
        this.send
            .send_data(Bytes::new(), true)
            .map_or_else(|e| Poll::Ready(Err(h2_io(e))), |()| Poll::Ready(Ok(())))
    }
}

fn h2_io(e: h2::Error) -> io::Error {
    if let Some(code) = e.reason() {
        io::Error::other(format!("grpc/h2: {code}"))
    } else {
        io::Error::other(format!("grpc/h2: {e}"))
    }
}

/// Opens the dialing side over `io` (already connected, cleartext or TLS): the HTTP/2
/// handshake, then one gRPC call whose two directions become the stream halves.
pub async fn connect<S>(io: S, authority: &str) -> io::Result<(GrpcReader, GrpcWriter)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = h2::client::handshake(io).await.map_err(h2_io)?;
    // The connection makes progress only while polled; drive it until the stream ends.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{authority}{PATH}"))
        .header("content-type", GRPC)
        .header("te", "trailers")
        .body(())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut send_request = send_request.ready().await.map_err(h2_io)?;
    let (response, send) = send_request.send_request(request, false).map_err(h2_io)?;
    let response = response.await.map_err(h2_io)?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::other(format!(
            "grpc server answered {}",
            response.status()
        )));
    }
    Ok((GrpcReader::new(response.into_body()), GrpcWriter::new(send)))
}

/// Accepts the listening side over `io` (already accepted, cleartext or TLS): the HTTP/2
/// handshake, the first gRPC call, and a `200` answer, giving the stream halves.
pub async fn accept<S>(io: S) -> io::Result<(GrpcReader, GrpcWriter)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(io).await.map_err(h2_io)?;
    let (request, mut respond) = match connection.accept().await {
        Some(result) => result.map_err(h2_io)?,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "grpc client opened no stream",
            ))
        }
    };
    // Keep driving the connection (one stream in flight) in the background.
    tokio::spawn(async move { while connection.accept().await.is_some() {} });
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", GRPC)
        .body(())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let send = respond.send_response(response, false).map_err(h2_io)?;
    Ok((GrpcReader::new(request.into_body()), GrpcWriter::new(send)))
}

/// A gRPC tunnel stream: the two halves together, so it fits [`crate::transport`]'s stream
/// type and splits back into independent halves without a lock.
pub struct GrpcStream {
    reader: GrpcReader,
    writer: GrpcWriter,
}

impl GrpcStream {
    pub fn new(reader: GrpcReader, writer: GrpcWriter) -> Self {
        Self { reader, writer }
    }

    pub fn into_split(self) -> (GrpcReader, GrpcWriter) {
        (self.reader, self.writer)
    }

    /// A cheap, non-blocking check that the stream has not been closed by the peer; any
    /// bytes that arrive are buffered, so the check consumes nothing.
    pub fn is_alive(&mut self) -> bool {
        if !self.reader.ready.is_empty() || !self.reader.raw.is_empty() {
            return true;
        }
        let waker = futures_noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut probe = [0u8; 1];
        let mut buf = ReadBuf::new(&mut probe);
        match Pin::new(&mut self.reader).poll_read(&mut cx, &mut buf) {
            Poll::Pending => true,
            // Ready with data buffered it in `ready`; ready with none at EOF is dead.
            Poll::Ready(Ok(())) => {
                if buf.filled().is_empty() && self.reader.done {
                    false
                } else {
                    self.reader.ready.extend_from_slice(buf.filled());
                    true
                }
            }
            Poll::Ready(Err(_)) => false,
        }
    }
}

fn futures_noop_waker() -> std::task::Waker {
    use std::sync::Arc;
    use std::task::Wake;
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    std::task::Waker::from(Arc::new(Noop))
}

impl AsyncRead for GrpcStream {
    // delegates to the read half
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for GrpcStream {
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

    /// De-frames a whole buffer in one go (prefix state starts fresh).
    fn deframe_all(raw: &[u8]) -> Vec<u8> {
        let mut raw = BytesMut::from(raw);
        let mut ready = BytesMut::new();
        let (mut remaining, mut in_prefix) = (0usize, true);
        deframe(&mut raw, &mut ready, &mut remaining, &mut in_prefix);
        ready.to_vec()
    }

    #[test]
    fn frame_has_the_grpc_prefix() {
        let f = frame(b"hello");
        assert_eq!(f[0], 0); // not compressed
        assert_eq!(u32::from_be_bytes([f[1], f[2], f[3], f[4]]), 5);
        assert_eq!(&f[GRPC_PREFIX..], b"hello");
    }

    #[test]
    fn one_message_round_trips() {
        assert_eq!(deframe_all(&frame(b"payload")), b"payload");
    }

    #[test]
    fn several_messages_concatenate() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&frame(b"one"));
        buf.extend_from_slice(&frame(b"two"));
        buf.extend_from_slice(&frame(b"three"));
        assert_eq!(deframe_all(&buf), b"onetwothree");
    }

    #[test]
    fn a_message_split_across_reads_is_rejoined() {
        let framed = frame(b"split me across reads");
        let mut raw = BytesMut::new();
        let mut ready = BytesMut::new();
        let (mut remaining, mut in_prefix) = (0usize, true);
        // Feed one byte at a time.
        for byte in &framed {
            raw.extend_from_slice(&[*byte]);
            deframe(&mut raw, &mut ready, &mut remaining, &mut in_prefix);
        }
        assert_eq!(&ready[..], b"split me across reads");
        assert!(raw.is_empty());
    }

    #[test]
    fn an_empty_message_yields_nothing() {
        assert!(deframe_all(&frame(b"")).is_empty());
    }

    #[test]
    fn a_partial_prefix_waits() {
        assert!(deframe_all(&[0, 0, 0]).is_empty()); // fewer than 5 header bytes
    }
}
