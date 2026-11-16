//! The session layer: many streams (user TCP connections) and datagrams (UDP flows) over
//! one tunnel connection.
//!
//! Entry, exit and the UDP code work with [`Session`] and [`SessionStream`] only. Today
//! the one implementation is kmux (`src/mux/`), running over an authenticated link;
//! QUIC, which brings its own streams and datagrams, becomes a second variant. Enums rather than trait objects keep dispatch static.

mod manager;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(not(feature = "quic"))]
#[path = "quic_disabled.rs"]
pub mod quic;

use std::io;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;

use bytes::Bytes;

use crate::mux::{MuxSession, MuxStream};
use quic::{QuicSession, QuicStream};

pub use crate::mux::ResetReason;
pub use manager::{is_full, maintain, SessionPool};

/// What went over the sessions of one transport of an `auto` or `multi` tunnel, since the
/// tunnel started: shared by all its sessions (see [`crate::stats::Peer::session_up`]).
#[derive(Debug, Default)]
pub struct TransportUsage {
    /// Streams (user connections, UDP flows, probes) opened over it, by either side.
    pub streams: AtomicU64,
    /// Payload bytes this side sent and received, datagrams included.
    pub sent: AtomicU64,
    pub received: AtomicU64,
}

/// One tunnel connection carrying streams and datagrams.
pub enum Session {
    Kmux(MuxSession),
    Quic(QuicSession),
}

impl Session {
    /// Short name for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Kmux(_) => "mux",
            Self::Quic(_) => "quic",
        }
    }

    /// The transport an `auto` or `multi` tunnel's session runs over; `None` for the
    /// others.
    pub fn transport(&self) -> Option<&'static str> {
        match self {
            Self::Kmux(s) => s.transport(),
            Self::Quic(s) => s.transport(),
        }
    }

    /// Counts this session's streams and bytes into `usage` (once; later calls change
    /// nothing). Streams opened before keep going uncounted.
    pub fn set_usage(&self, usage: Arc<TransportUsage>) {
        match self {
            Self::Kmux(s) => s.set_usage(usage),
            Self::Quic(s) => s.set_usage(usage),
        }
    }

    fn usage(&self) -> Option<Arc<TransportUsage>> {
        let usage = match self {
            Self::Kmux(s) => s.usage(),
            Self::Quic(s) => s.usage(),
        }?;
        usage.streams.fetch_add(1, Relaxed);
        Some(usage.clone())
    }

    /// Opens a stream whose first bytes are `syn` (the open request). Data can be sent
    /// right away; the peer answers a failed open with a reset.
    pub fn open(&self, syn: Bytes) -> io::Result<SessionStream> {
        let inner = match self {
            Self::Kmux(s) => s.open(syn).map(Inner::Kmux),
            Self::Quic(s) => s.open(syn).map(Inner::Quic),
        }?;
        Ok(SessionStream {
            inner,
            usage: self.usage(),
        })
    }

    /// Waits for a stream the peer opened, with its open request. `None` once the
    /// session is closed or going away.
    pub async fn accept(&self) -> Option<(SessionStream, Bytes)> {
        let (inner, syn) = match self {
            Self::Kmux(s) => s
                .accept()
                .await
                .map(|(stream, syn)| (Inner::Kmux(stream), syn)),
            Self::Quic(s) => s
                .accept()
                .await
                .map(|(stream, syn)| (Inner::Quic(stream), syn)),
        }?;
        let usage = self.usage();
        Some((SessionStream { inner, usage }, syn))
    }

    /// No new streams in either direction; existing ones continue.
    pub fn goaway(&self) {
        match self {
            Self::Kmux(s) => s.goaway(),
            Self::Quic(s) => s.goaway(),
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            Self::Kmux(s) => s.is_closed(),
            Self::Quic(s) => s.is_closed(),
        }
    }

    /// Going away or closed: takes no new streams.
    pub fn is_draining(&self) -> bool {
        match self {
            Self::Kmux(s) => s.is_draining(),
            Self::Quic(s) => s.is_draining(),
        }
    }

    pub fn stream_count(&self) -> usize {
        match self {
            Self::Kmux(s) => s.stream_count(),
            Self::Quic(s) => s.stream_count(),
        }
    }

    /// Round-trip time to the peer: from pings (kmux) or QUIC's own estimate.
    pub fn rtt(&self) -> Option<std::time::Duration> {
        match self {
            Self::Kmux(s) => s.rtt(),
            Self::Quic(s) => s.rtt(),
        }
    }

    /// The round trip to weigh this session by when spreading new streams (see
    /// [`MuxSession::load_rtt`]); QUIC's own estimate for QUIC.
    pub fn load_rtt(&self) -> Option<std::time::Duration> {
        match self {
            Self::Kmux(s) => s.load_rtt(),
            Self::Quic(s) => s.rtt(),
        }
    }

    /// Why the session closed, once it has.
    pub fn close_reason(&self) -> Option<String> {
        match self {
            Self::Kmux(s) => s.close_reason(),
            Self::Quic(s) => s.close_reason(),
        }
    }

    /// Resolves once the session is closed.
    pub async fn closed(&self) {
        match self {
            Self::Kmux(s) => s.closed().await,
            Self::Quic(s) => s.closed().await,
        }
    }

    pub fn close(&self) {
        match self {
            Self::Kmux(s) => s.close(),
            Self::Quic(s) => s.close(),
        }
    }

    /// Stops new streams, waits for the existing ones to finish, then closes.
    pub async fn drain(&self) {
        match self {
            Self::Kmux(s) => s.drain().await,
            Self::Quic(s) => s.drain().await,
        }
    }
}

/// One stream of a [`Session`]: a user TCP connection, or a UDP flow (whose packets
/// travel as datagrams).
#[derive(Debug)]
pub struct SessionStream {
    inner: Inner,
    /// Where its bytes are counted (a stream of an `auto` or `multi` tunnel).
    usage: Option<Arc<TransportUsage>>,
}

#[derive(Debug)]
enum Inner {
    Kmux(MuxStream),
    Quic(QuicStream),
}

impl From<MuxStream> for SessionStream {
    fn from(s: MuxStream) -> Self {
        Self {
            inner: Inner::Kmux(s),
            usage: None,
        }
    }
}

impl From<QuicStream> for SessionStream {
    fn from(s: QuicStream) -> Self {
        Self {
            inner: Inner::Quic(s),
            usage: None,
        }
    }
}

impl SessionStream {
    /// Sends `data`, waiting for flow-control credit as needed.
    pub async fn send(&self, data: Bytes) -> io::Result<()> {
        let n = data.len() as u64;
        match &self.inner {
            Inner::Kmux(s) => s.send(data).await,
            Inner::Quic(s) => s.send(data).await,
        }?;
        self.count_sent(n);
        Ok(())
    }

    fn count_sent(&self, n: u64) {
        if let Some(u) = &self.usage {
            u.sent.fetch_add(n, Relaxed);
        }
    }

    fn count_received(&self, n: usize) {
        if let Some(u) = &self.usage {
            u.received.fetch_add(n as u64, Relaxed);
        }
    }

    /// Receives the next chunk of data; `None` at the end of the stream.
    pub async fn recv(&self) -> io::Result<Option<Bytes>> {
        let data = match &self.inner {
            Inner::Kmux(s) => s.recv().await,
            Inner::Quic(s) => s.recv().await,
        }?;
        if let Some(d) = &data {
            self.count_received(d.len());
        }
        Ok(data)
    }

    /// Half close: no more data from this side.
    pub fn finish(&self) -> io::Result<()> {
        match &self.inner {
            Inner::Kmux(s) => s.finish(),
            Inner::Quic(s) => s.finish(),
        }
    }

    /// Aborts the stream and tells the peer why.
    pub fn reset(self, reason: ResetReason) {
        match self.inner {
            Inner::Kmux(s) => s.reset(reason),
            Inner::Quic(s) => s.reset(reason),
        }
    }

    /// Why the stream was reset, once it has been (by either side).
    pub fn reset_reason(&self) -> Option<ResetReason> {
        match &self.inner {
            Inner::Kmux(s) => s.reset_reason(),
            Inner::Quic(s) => s.reset_reason(),
        }
    }

    /// Queues one datagram; never waits. False if it was dropped or cannot be sent.
    pub fn send_datagram(&self, packet: Bytes) -> bool {
        let n = packet.len() as u64;
        let sent = match &self.inner {
            Inner::Kmux(s) => s.send_datagram(packet),
            Inner::Quic(s) => s.send_datagram(packet),
        };
        if sent {
            self.count_sent(n);
        }
        sent
    }

    /// Whether a datagram of `len` bytes would be sent where it may be lost (KCP's
    /// datagram path, a QUIC datagram), rather than reliably in the connection.
    pub fn sends_unreliably(&self, len: usize) -> bool {
        match &self.inner {
            Inner::Kmux(s) => s.sends_unreliably(len),
            Inner::Quic(s) => s.sends_unreliably(len),
        }
    }

    /// Receives the next datagram, whole; `None` once the peer finished the stream.
    pub async fn recv_datagram(&self) -> io::Result<Option<Bytes>> {
        let packet = match &self.inner {
            Inner::Kmux(s) => s.recv_datagram().await,
            Inner::Quic(s) => s.recv_datagram().await,
        }?;
        if let Some(p) = &packet {
            self.count_received(p.len());
        }
        Ok(packet)
    }
}
