//! The resolver path of `transport = "dns"`: the tunnel's packets carried through real
//! recursive resolvers (`[tunnel.dns] resolvers`) to a listener that is the authoritative
//! server of a domain delegated to it (`[tunnel.dns] domain`). Where only DNS still gets
//! out (a shutdown that leaves the country's resolvers working), this does.
//!
//! The dialing side ([`Client`]) splits each packet into fragments small enough for a query
//! name and sends one TXT query per fragment, each to the resolver that has answered best
//! (and, with `duplicate`, to that many different ones). The listener ([`Authority`]) can
//! only speak when asked, so the dialing side keeps a few queries waiting there — polls —
//! and the listener answers each with the packets it has for that session, or, after a
//! short hold, with nothing. Resolvers that stop answering are left out for a while and
//! tried again later. KCP above resends whatever is lost, as on any other carrier.
//!
//! See [`super::wire`] for the messages.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use super::wire::{self, Answer, Domain, Upstream};

/// How long the listener holds a poll before answering it empty: long enough that one
/// waiting poll covers a while, short of the second or so after which a resolver asks again.
const HOLD: Duration = Duration::from_millis(350);
/// Polls the listener keeps waiting per session; an older one is answered at once.
const MAX_PARKED: usize = 24;
/// What the listener keeps for a session that is not being asked often enough.
const MAX_QUEUED: usize = 512 * 1024;
/// A session not heard from for this long is forgotten.
const SESSION_IDLE: Duration = Duration::from_secs(180);
/// A packet missing a fragment for this long is dropped (KCP sends it again).
const PARTIAL_TTL: Duration = Duration::from_secs(10);
const MAX_SESSIONS: usize = 4096;

/// A query without an answer after this long counts as lost for its resolver: the
/// listener answers every query within [`HOLD`], so beyond that and a slow resolver's
/// round trip it is not coming (and a poll lost on the way must not hold its place).
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// Polls the dialing side keeps waiting: while data moves, and when the tunnel is idle.
const POLLS_ACTIVE: usize = 8;
const POLLS_IDLE: usize = 1;
/// How long after the last data the tunnel counts as moving.
const ACTIVE_FOR: Duration = Duration::from_secs(3);
/// Lost queries in a row after which a resolver is left out, and for how long at first
/// (doubling each time it fails again, up to [`MAX_BENCH`]).
const FAILS_TO_BENCH: u32 = 4;
const BENCH: Duration = Duration::from_secs(15);
const MAX_BENCH: Duration = Duration::from_secs(240);
/// Of the queries sent, the share that goes to a random resolver rather than the best, so
/// the others' figures stay current.
const EXPLORE: f64 = 0.12;

const TICK: Duration = Duration::from_millis(20);

/// Aborts the background tasks of a carrier when its last handle goes.
struct Tasks(Vec<JoinHandle<()>>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

fn random_u16() -> u16 {
    u16::from_le_bytes(crate::crypto::random_bytes::<2>().unwrap_or([0x5a, 0xa5]))
}

fn random_u32() -> u32 {
    u32::from_le_bytes(crate::crypto::random_bytes::<4>().unwrap_or([1, 2, 3, 4]))
}

fn random_unit() -> f64 {
    f64::from(random_u16()) / f64::from(u16::MAX)
}

// ---------------------------------------------------------------- the dialing side

/// One resolver and how it has done.
#[derive(Debug, Clone)]
struct Resolver {
    addr: SocketAddr,
    /// Smoothed round trip, in milliseconds (`None` until it answers once).
    srtt: Option<f64>,
    sent: u64,
    answered: u64,
    lost_in_row: u32,
    benched: u32,
    off_until: Option<Instant>,
}

impl Resolver {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            srtt: None,
            sent: 0,
            answered: 0,
            lost_in_row: 0,
            benched: 0,
            off_until: None,
        }
    }

    fn usable(&self, now: Instant) -> bool {
        self.off_until.map_or(true, |t| now >= t)
    }

    /// Lower is better: the round trip, weighed up by the share of queries lost.
    fn score(&self) -> f64 {
        let rtt = self.srtt.unwrap_or(250.0);
        let loss = if self.sent >= 8 {
            1.0 - (self.answered as f64 / self.sent as f64).min(1.0)
        } else {
            0.0
        };
        rtt * (1.0 + 4.0 * loss)
    }
}

struct Inflight {
    resolver: usize,
    sent: Instant,
    poll: bool,
}

struct ClientState {
    resolvers: Vec<Resolver>,
    inflight: HashMap<u16, Inflight>,
    next_packet: u16,
    nonce: u16,
    last_data: Instant,
    /// Polls asked for beyond the target, because the listener said it has more.
    extra: usize,
    scratch: Vec<u8>,
}

/// The dialing side: queries out through the resolvers, packets back from the answers.
pub struct Client {
    v4: Option<Arc<UdpSocket>>,
    v6: Option<Arc<UdpSocket>>,
    domain: Domain,
    session: u32,
    duplicate: usize,
    state: Mutex<ClientState>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    wake: Arc<Notify>,
    _tasks: Mutex<Option<Tasks>>,
}

impl Client {
    pub async fn start(
        domain: Domain,
        resolvers: &[SocketAddr],
        duplicate: usize,
        buffer: usize,
    ) -> io::Result<Arc<Self>> {
        if resolvers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no dns resolvers",
            ));
        }
        let bind = |addr: SocketAddr| -> io::Result<Arc<UdpSocket>> {
            Ok(Arc::new(crate::transport::kcp::bind_udp_socket(
                addr, buffer,
            )?))
        };
        let v4 = if resolvers.iter().any(SocketAddr::is_ipv4) {
            Some(bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?)
        } else {
            None
        };
        let v6 = if resolvers.iter().any(SocketAddr::is_ipv6) {
            Some(bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))?)
        } else {
            None
        };
        // A fresh socket reports writable only once the runtime has seen it so: until then
        // a send that does not wait would fail.
        for socket in [&v4, &v6].into_iter().flatten() {
            socket.writable().await?;
        }
        let (tx, rx) = mpsc::channel(1024);
        let client = Arc::new(Self {
            v4: v4.clone(),
            v6: v6.clone(),
            domain,
            session: random_u32(),
            duplicate: duplicate.clamp(1, resolvers.len().max(1)),
            state: Mutex::new(ClientState {
                resolvers: resolvers.iter().copied().map(Resolver::new).collect(),
                inflight: HashMap::new(),
                next_packet: random_u16(),
                nonce: random_u16(),
                last_data: Instant::now(),
                extra: 0,
                scratch: Vec::with_capacity(512),
            }),
            inbound: tokio::sync::Mutex::new(rx),
            wake: Arc::new(Notify::new()),
            _tasks: Mutex::new(None),
        });
        let mut tasks = Vec::new();
        for socket in [v4, v6].into_iter().flatten() {
            tasks.push(tokio::spawn(read_answers(
                socket,
                Arc::downgrade(&client),
                tx.clone(),
            )));
        }
        tasks.push(tokio::spawn(keep_polling(Arc::downgrade(&client))));
        *client._tasks.lock().unwrap_or_else(|e| e.into_inner()) = Some(Tasks(tasks));
        Ok(client)
    }

    /// The local address of the first socket (for the status).
    pub fn local_addr(&self) -> SocketAddr {
        self.v4
            .as_ref()
            .or(self.v6.as_ref())
            .and_then(|s| s.local_addr().ok())
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    }

    /// The resolver answering best now (what the status shows as the peer).
    pub fn best(&self) -> SocketAddr {
        let st = lock(&self.state);
        let now = Instant::now();
        st.resolvers
            .iter()
            .filter(|r| r.usable(now))
            .min_by(|a, b| a.score().total_cmp(&b.score()))
            .unwrap_or(&st.resolvers[0])
            .addr
    }

    /// The next packet the listener sent.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let packet = self
            .inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "dns carrier closed"))?;
        let n = packet.len().min(buf.len());
        buf[..n].copy_from_slice(&packet[..n]);
        Ok(n)
    }

    /// Sends a packet: fragments, each in a query of its own, to the best resolvers.
    pub fn try_send(&self, payload: &[u8]) -> io::Result<usize> {
        let cap = self.domain.fragment_capacity();
        let count = payload.len().div_ceil(cap).max(1);
        if count > wire::MAX_FRAGMENTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too large for dns query names: lower tunnel.kcp.mtu or use a shorter domain",
            ));
        }
        let mut st = lock(&self.state);
        let packet = st.next_packet;
        st.next_packet = st.next_packet.wrapping_add(1);
        st.last_data = Instant::now();
        for (index, data) in payload.chunks(cap).enumerate() {
            let up = Upstream {
                session: self.session,
                nonce: 0,
                packet,
                index: index as u8,
                count: count as u8,
                data,
            };
            for resolver in self.pick(&st, self.duplicate) {
                self.send(&mut st, resolver, &up, false);
            }
        }
        drop(st);
        self.wake.notify_one();
        Ok(payload.len())
    }

    /// `n` different resolvers to send to: the best ones, now and then a random one.
    fn pick(&self, st: &ClientState, n: usize) -> Vec<usize> {
        let now = Instant::now();
        let mut usable: Vec<usize> = (0..st.resolvers.len())
            .filter(|&i| st.resolvers[i].usable(now))
            .collect();
        if usable.is_empty() {
            usable = (0..st.resolvers.len()).collect();
        }
        usable.sort_by(|&a, &b| st.resolvers[a].score().total_cmp(&st.resolvers[b].score()));
        if usable.len() > 1 && random_unit() < EXPLORE {
            let i = 1 + usize::from(random_u16()) % (usable.len() - 1);
            usable.swap(0, i);
        }
        usable.truncate(n.max(1));
        usable
    }

    /// Sends one query to resolver `resolver`.
    fn send(&self, st: &mut ClientState, resolver: usize, up: &Upstream<'_>, poll: bool) {
        st.nonce = st.nonce.wrapping_add(1);
        let up = Upstream {
            nonce: st.nonce,
            ..up.clone()
        };
        let mut id = random_u16();
        while st.inflight.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        let mut out = std::mem::take(&mut st.scratch);
        if wire::encode_query(&mut out, id, &self.domain, &up).is_ok() {
            let addr = st.resolvers[resolver].addr;
            let socket = if addr.is_ipv4() { &self.v4 } else { &self.v6 };
            if let Some(socket) = socket {
                if socket.try_send_to(&out, addr).is_ok() {
                    st.resolvers[resolver].sent += 1;
                    st.inflight.insert(
                        id,
                        Inflight {
                            resolver,
                            sent: Instant::now(),
                            poll,
                        },
                    );
                }
            }
        }
        st.scratch = out;
    }

    /// Times out lost queries and keeps enough polls waiting at the listener.
    fn tick(&self) {
        let now = Instant::now();
        let mut st = lock(&self.state);
        let lost: Vec<u16> = st
            .inflight
            .iter()
            .filter(|(_, q)| now.duration_since(q.sent) >= QUERY_TIMEOUT)
            .map(|(id, _)| *id)
            .collect();
        for id in lost {
            if let Some(q) = st.inflight.remove(&id) {
                let r = &mut st.resolvers[q.resolver];
                r.lost_in_row += 1;
                if r.lost_in_row >= FAILS_TO_BENCH {
                    r.lost_in_row = 0;
                    let bench = BENCH.saturating_mul(1 << r.benched.min(4)).min(MAX_BENCH);
                    r.benched += 1;
                    r.off_until = Some(now + bench);
                }
            }
        }
        let target = if now.duration_since(st.last_data) < ACTIVE_FOR {
            POLLS_ACTIVE
        } else {
            POLLS_IDLE
        } + st.extra;
        st.extra = 0;
        let waiting = st.inflight.values().filter(|q| q.poll).count();
        for _ in waiting..target.min(POLLS_ACTIVE * 2) {
            let up = Upstream {
                session: self.session,
                nonce: 0,
                packet: 0,
                index: 0,
                count: 0,
                data: &[],
            };
            if let Some(&r) = self.pick(&st, 1).first() {
                self.send(&mut st, r, &up, true);
            }
        }
    }

    /// Takes in a resolver's answer.
    fn answered(&self, message: &[u8], tx: &mpsc::Sender<Vec<u8>>) {
        let Some(response) = wire::decode_response(message) else {
            return;
        };
        let now = Instant::now();
        let mut st = lock(&self.state);
        if let Some(q) = st.inflight.remove(&response.id) {
            let r = &mut st.resolvers[q.resolver];
            if response.rcode == 0 {
                r.answered += 1;
                r.lost_in_row = 0;
                r.benched = r.benched.saturating_sub(1);
                let ms = now.duration_since(q.sent).as_secs_f64() * 1000.0;
                // The hold is the listener's, not the resolver's: a poll's time says little.
                if !q.poll || response.payload.as_ref().is_some_and(|p| p.len() > 1) {
                    r.srtt = Some(r.srtt.map_or(ms, |s| s * 0.875 + ms * 0.125));
                }
            } else {
                r.lost_in_row += 1;
            }
        }
        let Some(payload) = response.payload else {
            return;
        };
        let Some((&flags, mut rest)) = payload.split_first() else {
            return;
        };
        let mut any = false;
        while rest.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
            let Some(packet) = rest.get(2..2 + len) else {
                break;
            };
            any = true;
            let _ = tx.try_send(packet.to_vec());
            rest = &rest[2 + len..];
        }
        if any {
            st.last_data = now;
        }
        if flags & 1 != 0 {
            // The listener has more: a few more polls to fetch it.
            st.extra += 4;
            drop(st);
            self.wake.notify_one();
        }
    }
}

async fn read_answers(socket: Arc<UdpSocket>, client: Weak<Client>, tx: mpsc::Sender<Vec<u8>>) {
    let mut buf = vec![0u8; 65_536];
    loop {
        let Ok((n, _)) = socket.recv_from(&mut buf).await else {
            tokio::time::sleep(TICK).await;
            continue;
        };
        let Some(client) = client.upgrade() else {
            return;
        };
        client.answered(&buf[..n], &tx);
    }
}

async fn keep_polling(client: Weak<Client>) {
    loop {
        let Some(c) = client.upgrade() else {
            return;
        };
        c.tick();
        let wake = c.wake.clone();
        drop(c);
        let woken = wake.notified();
        tokio::select! {
            () = woken => {}
            () = tokio::time::sleep(TICK) => {}
        }
    }
}

// ---------------------------------------------------------------- the listening side

/// A packet still missing fragments.
struct Partial {
    parts: Vec<Option<Vec<u8>>>,
    first: Instant,
}

/// A query waiting at the listener for something to answer with.
struct Parked {
    from: SocketAddr,
    message: Vec<u8>,
    deadline: Instant,
}

struct Session {
    partial: HashMap<u16, Partial>,
    /// Packets that came whole recently, so a duplicate is not delivered twice.
    recent: VecDeque<u16>,
    down: VecDeque<Vec<u8>>,
    queued: usize,
    parked: VecDeque<Parked>,
    last: Instant,
}

impl Session {
    fn new() -> Self {
        Self {
            partial: HashMap::new(),
            recent: VecDeque::new(),
            down: VecDeque::new(),
            queued: 0,
            parked: VecDeque::new(),
            last: Instant::now(),
        }
    }
}

/// The listening side: the authoritative server of the tunnel domain.
pub struct Authority {
    socket: Arc<UdpSocket>,
    domain: Domain,
    sessions: Mutex<HashMap<u32, Session>>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    _tasks: Mutex<Option<Tasks>>,
}

/// The made-up address a session stands for above the carrier (KCP sorts its
/// conversations by peer address; a session's queries come from any resolver).
pub fn session_addr(session: u32) -> SocketAddr {
    let [a, b, c, d] = session.to_be_bytes();
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(
            0xfd77,
            0x6e73,
            0,
            0,
            0,
            0,
            u16::from_be_bytes([a, b]),
            u16::from_be_bytes([c, d]),
        ),
        53,
        0,
        0,
    ))
}

fn addr_session(addr: SocketAddr) -> Option<u32> {
    match addr {
        SocketAddr::V6(v6) => {
            let s = v6.ip().segments();
            (s[0] == 0xfd77 && s[1] == 0x6e73).then(|| (u32::from(s[6]) << 16) | u32::from(s[7]))
        }
        SocketAddr::V4(_) => None,
    }
}

impl Authority {
    pub async fn start(addr: SocketAddr, domain: Domain, buffer: usize) -> io::Result<Arc<Self>> {
        let socket = Arc::new(crate::transport::kcp::bind_udp_socket(addr, buffer)?);
        socket.writable().await?;
        let (tx, rx) = mpsc::channel(4096);
        let me = Arc::new(Self {
            socket: socket.clone(),
            domain,
            sessions: Mutex::new(HashMap::new()),
            inbound: tokio::sync::Mutex::new(rx),
            _tasks: Mutex::new(None),
        });
        let tasks = vec![
            tokio::spawn(read_queries(socket, Arc::downgrade(&me), tx)),
            tokio::spawn(answer_late(Arc::downgrade(&me))),
        ];
        *me._tasks.lock().unwrap_or_else(|e| e.into_inner()) = Some(Tasks(tasks));
        Ok(me)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    }

    /// The next whole packet, and the session it came from (as [`session_addr`]).
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (packet, from) = self
            .inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "dns listener closed"))?;
        let n = packet.len().min(buf.len());
        buf[..n].copy_from_slice(&packet[..n]);
        Ok((n, from))
    }

    /// Queues a packet for a session; a poll waiting there takes it at once.
    pub fn try_send_to(&self, payload: &[u8], to: SocketAddr) -> io::Result<usize> {
        let Some(id) = addr_session(to) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a dns session",
            ));
        };
        let mut sessions = lock(&self.sessions);
        let Some(session) = sessions.get_mut(&id) else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "dns session gone",
            ));
        };
        if session.queued + payload.len() > MAX_QUEUED {
            // As a full socket buffer would: KCP sends it again.
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "dns session queue full",
            ));
        }
        session.queued += payload.len();
        session.down.push_back(payload.to_vec());
        if let Some(parked) = session.parked.pop_front() {
            self.answer(session, &parked.from, &parked.message);
        }
        Ok(payload.len())
    }

    /// Answers the query `message` from `from` with what the session has queued.
    fn answer(&self, session: &mut Session, from: &SocketAddr, message: &[u8]) {
        let Some(query) = wire::decode_query(message, &self.domain) else {
            return;
        };
        let cap = wire::answer_capacity(&query);
        let mut payload = Vec::with_capacity(cap.min(1400));
        payload.push(0);
        while let Some(front) = session.down.front() {
            if payload.len() + 2 + front.len() > cap {
                break;
            }
            let packet = session.down.pop_front().unwrap_or_default();
            session.queued -= packet.len();
            payload.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            payload.extend_from_slice(&packet);
        }
        if !session.down.is_empty() {
            payload[0] |= 1;
        }
        let mut out = Vec::with_capacity(payload.len() + 300);
        wire::encode_answer(&mut out, &query, Answer::Data(&payload));
        let _ = self.socket.try_send_to(&out, *from);
    }

    /// Takes in a query: answers what is not tunnel data at once, keeps fragments, and
    /// holds the query until there is something to answer with.
    fn query(&self, message: &[u8], from: SocketAddr, tx: &mpsc::Sender<(Vec<u8>, SocketAddr)>) {
        let Some(query) = wire::decode_query(message, &self.domain) else {
            return;
        };
        let up = query.data.as_deref().and_then(wire::parse_upstream);
        let Some(up) = up else {
            // Another domain: refused. One of ours without data (the domain itself, the
            // steps of a resolver's query-name minimisation, another type): no records.
            let answer = if query.under {
                Answer::Empty
            } else {
                Answer::Refused
            };
            let mut out = Vec::with_capacity(message.len() + 16);
            wire::encode_answer(&mut out, &query, answer);
            let _ = self.socket.try_send_to(&out, from);
            return;
        };
        let now = Instant::now();
        let mut sessions = lock(&self.sessions);
        if !sessions.contains_key(&up.session) && sessions.len() >= MAX_SESSIONS {
            return;
        }
        let session = sessions.entry(up.session).or_insert_with(Session::new);
        session.last = now;
        if up.count > 0 {
            let whole = if up.count == 1 {
                Some(up.data.to_vec())
            } else {
                let partial = session.partial.entry(up.packet).or_insert_with(|| Partial {
                    parts: vec![None; usize::from(up.count)],
                    first: now,
                });
                if partial.parts.len() == usize::from(up.count) {
                    partial.parts[usize::from(up.index)] = Some(up.data.to_vec());
                }
                if partial.parts.iter().all(Option::is_some) {
                    let parts = session
                        .partial
                        .remove(&up.packet)
                        .map(|p| p.parts)
                        .unwrap_or_default();
                    Some(parts.into_iter().flatten().flatten().collect())
                } else {
                    None
                }
            };
            if let Some(packet) = whole {
                if !session.recent.contains(&up.packet) {
                    session.recent.push_back(up.packet);
                    if session.recent.len() > 256 {
                        session.recent.pop_front();
                    }
                    let _ = tx.try_send((packet, session_addr(up.session)));
                }
            }
        }
        if !session.down.is_empty() {
            self.answer(session, &from, message);
            return;
        }
        session.parked.push_back(Parked {
            from,
            message: message.to_vec(),
            deadline: now + HOLD,
        });
        while session.parked.len() > MAX_PARKED {
            if let Some(old) = session.parked.pop_front() {
                self.answer(session, &old.from, &old.message);
            }
        }
    }

    /// Answers the polls whose hold is over, and forgets old sessions and fragments.
    fn tick(&self) {
        let now = Instant::now();
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, s| now.duration_since(s.last) < SESSION_IDLE);
        for session in sessions.values_mut() {
            while session.parked.front().is_some_and(|p| p.deadline <= now) {
                if let Some(p) = session.parked.pop_front() {
                    self.answer(session, &p.from, &p.message);
                }
            }
            session
                .partial
                .retain(|_, p| now.duration_since(p.first) < PARTIAL_TTL);
        }
    }
}

async fn read_queries(
    socket: Arc<UdpSocket>,
    me: Weak<Authority>,
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
) {
    let mut buf = vec![0u8; 65_536];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            tokio::time::sleep(TICK).await;
            continue;
        };
        let Some(me) = me.upgrade() else {
            return;
        };
        me.query(&buf[..n], from, &tx);
    }
}

async fn answer_late(me: Weak<Authority>) {
    loop {
        tokio::time::sleep(TICK).await;
        let Some(me) = me.upgrade() else {
            return;
        };
        me.tick();
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver that forwards every query to the listener and every answer back, and
    /// drops every `drop_every`-th message (0: none).
    async fn relay(listener: SocketAddr, drop_every: usize) -> SocketAddr {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            let mut asked: HashMap<u16, SocketAddr> = HashMap::new();
            let mut n_seen = 0usize;
            loop {
                let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                n_seen += 1;
                if drop_every > 0 && n_seen % drop_every == 0 {
                    continue;
                }
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                if from == listener {
                    if let Some(to) = asked.remove(&id) {
                        let _ = socket.send_to(&buf[..n], to).await;
                    }
                } else {
                    asked.insert(id, from);
                    let _ = socket.send_to(&buf[..n], listener).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn packets_cross_both_ways_through_resolvers() {
        let domain = Domain::parse("t.example.com").unwrap();
        let auth = Authority::start("127.0.0.1:0".parse().unwrap(), domain.clone(), 1 << 20)
            .await
            .unwrap();
        let listener = auth.local_addr();
        let resolvers = vec![relay(listener, 0).await, relay(listener, 0).await];
        let client = Client::start(domain, &resolvers, 1, 1 << 20).await.unwrap();

        // Up: a packet of several fragments arrives whole, once.
        let big: Vec<u8> = (0..700u32).map(|i| (i * 7) as u8).collect();
        client.try_send(&big).unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), auth.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], &big[..]);

        // Down: the listener's packets come back in answers to the waiting polls.
        for i in 0..20u8 {
            auth.try_send_to(&vec![i; 600], from).unwrap();
        }
        for i in 0..20u8 {
            let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], &vec![i; 600][..]);
        }
    }

    #[tokio::test]
    async fn a_dead_resolver_is_left_out() {
        let domain = Domain::parse("t.example.com").unwrap();
        let auth = Authority::start("127.0.0.1:0".parse().unwrap(), domain.clone(), 1 << 20)
            .await
            .unwrap();
        let good = relay(auth.local_addr(), 0).await;
        // Nothing answers here.
        let dead_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead = dead_socket.local_addr().unwrap();
        let client = Client::start(domain, &[dead, good], 1, 1 << 20)
            .await
            .unwrap();
        let mut buf = vec![0u8; 2048];
        let mut got = 0;
        let end = Instant::now() + Duration::from_secs(20);
        while Instant::now() < end && got < 10 {
            client.try_send(b"ping").unwrap();
            if tokio::time::timeout(Duration::from_millis(500), auth.recv_from(&mut buf))
                .await
                .is_ok()
            {
                got += 1;
            }
        }
        assert!(got >= 10, "only {got} packets crossed");
        assert_eq!(client.best(), good);
        let st = lock(&client.state);
        let dead_r = st.resolvers.iter().find(|r| r.addr == dead).unwrap();
        assert_eq!(dead_r.answered, 0);
    }

    #[tokio::test]
    async fn the_listener_answers_other_names_plainly() {
        let domain = Domain::parse("t.example.com").unwrap();
        let auth = Authority::start("127.0.0.1:0".parse().unwrap(), domain, 1 << 20)
            .await
            .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = vec![0u8; 2048];
        for (name, rcode) in [("other.net", 5u8), ("t.example.com", 0)] {
            let d = Domain::parse(name).unwrap();
            let mut q = Vec::new();
            // A poll-shaped query under another domain, or one for the domain itself.
            wire::encode_query(
                &mut q,
                9,
                &d,
                &Upstream {
                    session: 1,
                    nonce: 1,
                    packet: 0,
                    index: 0,
                    count: 0,
                    data: &[],
                },
            )
            .unwrap();
            if name == "t.example.com" {
                // The domain itself: rewrite the question to just the domain.
                q.clear();
                q.extend_from_slice(&[0, 9, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b't', 7]);
                q.extend_from_slice(b"example");
                q.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 2, 0, 1]);
            }
            socket.send_to(&q, auth.local_addr()).await.unwrap();
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let r = wire::decode_response(&buf[..n]).unwrap();
            assert_eq!(r.rcode, rcode, "{name}");
            assert!(r.payload.is_none());
        }
    }
}
