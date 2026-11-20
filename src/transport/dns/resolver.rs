//! The resolver path of `transport = "dns"`: the tunnel's packets carried through real
//! recursive resolvers (`[tunnel.dns] resolvers`) to a listener that is the authoritative
//! server of a domain delegated to it (`[tunnel.dns] domain`). Where only DNS still gets
//! out (a shutdown that leaves the country's resolvers working), this does.
//!
//! Three parts:
//!
//! - [`Pool`]: the resolvers of a tunnel, shared by all its connections. At the start it
//!   tests each one (many at a time) through the listener itself: does it answer, how
//!   large a query name it passes (upload) and how large an answer it brings back
//!   (download). The ones that answer are used; each query goes to one picked by the
//!   balancing strategy. One that stops answering is set aside and tested again later.
//! - [`Client`]: the dialing side of one connection. It splits each packet into fragments
//!   that fit the picked resolvers' upload size, one TXT query each (copies through other
//!   resolvers with `duplicate`), and keeps polls waiting at the listener so it can
//!   answer: many while data moves, fewer and rarer as the connection idles.
//! - [`Authority`]: the listening side, the authoritative server of the domains. It joins
//!   fragments into packets, answers probes, and answers each query with fragments of the
//!   packets it has for that session, as large as that query's resolver takes.
//!
//! KCP above resends whatever is lost, as on any other carrier. See [`super::wire`] for
//! the messages.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::JoinHandle;

pub use super::list::{expand_resolvers, resolver_entries, Balance, PoolConfig, MAX_RESOLVERS};
use super::wire::{self, Answer, Domain, DownFragment, Upstream};
use crate::stats::DnsResolverInfo;

/// How long the listener holds a poll before answering it empty: long enough that one
/// waiting poll covers a while, short of the second or so after which a resolver asks again.
const HOLD: Duration = Duration::from_millis(350);
/// Polls the listener keeps waiting per session; an older one is answered at once.
const MAX_PARKED: usize = 32;
/// What the listener keeps for a session that is not being asked often enough.
const MAX_QUEUED: usize = 512 * 1024;
/// A session not heard from for this long is forgotten.
const SESSION_IDLE: Duration = Duration::from_secs(180);
/// A packet missing a fragment for this long is dropped (KCP sends it again).
const PARTIAL_TTL: Duration = Duration::from_secs(10);
const MAX_SESSIONS: usize = 4096;
/// The smallest piece of a packet the listener puts in an answer, unless it is the rest.
const MIN_PIECE: usize = 16;

/// A query without an answer after this long counts as lost for its resolver: the
/// listener answers every query within [`HOLD`], so beyond that and a slow resolver's
/// round trip it is not coming (and a poll lost on the way must not hold its place).
const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// Polls kept waiting while data moves (and for [`ACTIVE_FOR`] after).
const POLLS_ACTIVE: usize = 8;
const ACTIVE_FOR: Duration = Duration::from_secs(3);
/// As the connection idles, polls thin out: one kept waiting until [`WARM`], then one
/// every [`LAZY`] until [`COOL`], every [`COOLDOWN`] until [`COLD`], then every
/// [`COLD_EVERY`]. Any data brings them back at once.
const WARM: Duration = Duration::from_secs(8);
const COOL: Duration = Duration::from_secs(20);
const COLD: Duration = Duration::from_secs(30);
const LAZY: Duration = Duration::from_millis(750);
const COOLDOWN: Duration = Duration::from_secs(2);
const COLD_EVERY: Duration = Duration::from_secs(15);
/// After a connection starts, its packets (the handshake) go out with `setup_duplicate`
/// copies for this long.
const SETUP_FOR: Duration = Duration::from_secs(3);
/// Lost queries in a row after which a resolver is set aside.
const FAILS_TO_BENCH: u32 = 4;
/// A resolver sent to for this long without one answer is set aside too.
const SILENT_WINDOW: Duration = Duration::from_secs(30);
/// How long a resolver set aside rests before it is tested again (doubling each time it
/// fails again, up to [`MAX_BENCH`]).
const BENCH: Duration = Duration::from_secs(20);
const MAX_BENCH: Duration = Duration::from_secs(600);
/// How often the resolvers set aside or dead are looked at for a new test.
const RECHECK_EVERY: Duration = Duration::from_secs(15);
/// The longest a new connection waits for the scan to find a resolver that answers.
const READY_WAIT: Duration = Duration::from_secs(60);
/// Of the picks that go by score, the share that goes to another resolver instead, so the
/// others' figures stay current.
const EXPLORE: f64 = 0.08;

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

fn random_below(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        random_u32() as usize % n
    }
}

fn random_unit() -> f64 {
    f64::from(random_u16()) / f64::from(u16::MAX)
}

fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        v.swap(i, random_below(i + 1));
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------- the resolvers

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Not tested yet (or being tested).
    Testing,
    Active,
    /// Set aside after losses, until it is tested again.
    Off,
    /// Did not pass its test; tested again now and then.
    Dead,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            Self::Testing => "testing",
            Self::Active => "active",
            Self::Off => "off",
            Self::Dead => "dead",
        }
    }
}

/// One resolver and how it has done.
#[derive(Debug, Clone)]
struct Res {
    addr: SocketAddr,
    state: State,
    /// The query data (header included) and answer payload it passes.
    up: usize,
    down: usize,
    /// Smoothed round trip, in milliseconds.
    srtt: Option<f64>,
    sent: u64,
    answered: u64,
    lost_in_row: u32,
    /// Since when it has been sent to without an answer.
    silent_since: Option<Instant>,
    benched: u32,
    retest_at: Option<Instant>,
}

impl Res {
    fn new(addr: SocketAddr, up: usize, down: usize, state: State) -> Self {
        Self {
            addr,
            state,
            up,
            down,
            srtt: None,
            sent: 0,
            answered: 0,
            lost_in_row: 0,
            silent_since: None,
            benched: 0,
            retest_at: None,
        }
    }

    /// Its share of queries lost (0 until it has a few to judge by).
    fn loss(&self) -> f64 {
        if self.sent >= 8 {
            1.0 - (self.answered as f64 / self.sent as f64).min(1.0)
        } else {
            0.0
        }
    }

    fn rtt(&self) -> f64 {
        self.srtt.unwrap_or(250.0)
    }

    fn hybrid(&self) -> f64 {
        self.rtt() * (1.0 + 4.0 * self.loss())
    }

    fn rest(&mut self) -> Duration {
        let rest = BENCH
            .saturating_mul(1 << self.benched.min(5))
            .min(MAX_BENCH);
        self.benched += 1;
        rest
    }
}

/// A resolver picked to send through.
#[derive(Debug, Clone, Copy)]
struct Pick {
    index: usize,
    addr: SocketAddr,
    up: usize,
    down: usize,
}

/// The resolvers of one tunnel: tested, picked, watched.
pub struct Pool {
    cfg: PoolConfig,
    res: Mutex<Vec<Res>>,
    rr: AtomicUsize,
    ready: Notify,
    any_ready: AtomicBool,
    scanned: AtomicBool,
    tasks: Mutex<Option<Tasks>>,
}

/// The pools of this process, for the status.
static POOLS: Mutex<Vec<Weak<Pool>>> = Mutex::new(Vec::new());

/// The resolvers of every pool of this process, the ones in use first (at most `limit`).
pub fn snapshot(limit: usize) -> Vec<DnsResolverInfo> {
    let pools: Vec<Arc<Pool>> = lock(&POOLS).iter().filter_map(Weak::upgrade).collect();
    let mut all = Vec::new();
    for pool in pools {
        all.extend(pool.infos());
    }
    let rank = |s: &str| match s {
        "active" => 0,
        "testing" => 1,
        "off" => 2,
        _ => 3,
    };
    all.sort_by(|a, b| {
        rank(&a.state)
            .cmp(&rank(&b.state))
            .then(b.answered.cmp(&a.answered))
            .then(
                a.rtt_ms
                    .unwrap_or(f64::MAX)
                    .total_cmp(&b.rtt_ms.unwrap_or(f64::MAX)),
            )
    });
    all.truncate(limit);
    all
}

impl Pool {
    /// Starts the pool: the resolvers are tested in the background (unless `scan` is
    /// off), and set aside or brought back as they answer.
    pub fn start(cfg: PoolConfig) -> Arc<Self> {
        let pool = Self::idle(cfg);
        let mut tasks = Vec::new();
        if pool.cfg.scan {
            tasks.push(tokio::spawn(scan_all(Arc::downgrade(&pool))));
        }
        tasks.push(tokio::spawn(recheck(Arc::downgrade(&pool))));
        *lock(&pool.tasks) = Some(Tasks(tasks));
        let mut pools = lock(&POOLS);
        pools.retain(|p| p.strong_count() > 0);
        pools.push(Arc::downgrade(&pool));
        pool
    }

    /// A pool with nothing running: for [`Pool::scan_now`].
    pub fn idle(cfg: PoolConfig) -> Arc<Self> {
        let up = cfg.upload.1.min(cfg.upload_ceiling());
        let state = if cfg.scan {
            State::Testing
        } else {
            State::Active
        };
        let res = cfg
            .resolvers
            .iter()
            .map(|&a| Res::new(a, up, cfg.download.1, state))
            .collect();
        Arc::new(Self {
            any_ready: AtomicBool::new(!cfg.scan),
            scanned: AtomicBool::new(!cfg.scan),
            cfg,
            res: Mutex::new(res),
            rr: AtomicUsize::new(0),
            ready: Notify::new(),
            tasks: Mutex::new(None),
        })
    }

    /// Waits until a resolver has passed its test (or the scan ended, or a minute passed).
    pub async fn wait_ready(&self) {
        let deadline = Instant::now() + READY_WAIT;
        while !self.any_ready.load(Ordering::Acquire) && !self.scanned.load(Ordering::Acquire) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let wait = left.min(Duration::from_millis(250));
            let _ = tokio::time::timeout(wait, self.ready.notified()).await;
        }
    }

    pub fn config(&self) -> &PoolConfig {
        &self.cfg
    }

    fn infos(&self) -> Vec<DnsResolverInfo> {
        lock(&self.res)
            .iter()
            .map(|r| DnsResolverInfo {
                addr: r.addr.to_string(),
                state: r.state.name().to_owned(),
                rtt_ms: r.srtt.map(|s| (s * 10.0).round() / 10.0),
                sent: r.sent,
                answered: r.answered,
                upload: r.up as u64,
                download: r.down as u64,
            })
            .collect()
    }

    /// `n` different resolvers to send through, by the balancing strategy. While none has
    /// passed its test, the ones not found dead; failing those, any.
    fn pick(&self, n: usize) -> Vec<Pick> {
        let res = lock(&self.res);
        let mut usable: Vec<usize> = (0..res.len())
            .filter(|&i| res[i].state == State::Active)
            .collect();
        if usable.is_empty() {
            usable = (0..res.len())
                .filter(|&i| res[i].state != State::Dead)
                .collect();
        }
        if usable.is_empty() {
            usable = (0..res.len()).collect();
        }
        if usable.is_empty() {
            return Vec::new();
        }
        let n = n.clamp(1, usable.len());
        let by = |v: &mut Vec<usize>, key: &dyn Fn(&Res) -> f64| {
            v.sort_by(|&a, &b| key(&res[a]).total_cmp(&key(&res[b])));
        };
        // The few with the fewest losses: those within 5 points of the best.
        let top = |v: &mut Vec<usize>| {
            let best = res[v[0]].loss();
            let keep = v
                .iter()
                .take_while(|&&i| res[i].loss() <= best + 0.05)
                .count();
            v.truncate(keep.max(n));
        };
        let turn = self.rr.fetch_add(1, Ordering::Relaxed);
        let scored = match self.cfg.balance {
            Balance::RoundRobin => {
                let len = usable.len();
                usable.rotate_left(turn % len);
                false
            }
            Balance::Random => {
                shuffle(&mut usable);
                false
            }
            Balance::LeastLoss => {
                by(&mut usable, &|r| r.loss());
                true
            }
            Balance::LowestLatency => {
                by(&mut usable, &Res::rtt);
                true
            }
            Balance::Hybrid => {
                by(&mut usable, &Res::hybrid);
                true
            }
            Balance::LossThenLatency => {
                by(&mut usable, &|r| (r.loss() * 20.0).round() * 1e6 + r.rtt());
                true
            }
            Balance::LeastLossTopRandom => {
                by(&mut usable, &|r| r.loss());
                top(&mut usable);
                shuffle(&mut usable);
                false
            }
            Balance::LeastLossTopRoundRobin => {
                by(&mut usable, &|r| r.loss());
                top(&mut usable);
                let len = usable.len();
                usable.rotate_left(turn % len);
                false
            }
        };
        if scored && usable.len() > n && random_unit() < EXPLORE {
            let other = n + random_below(usable.len() - n);
            usable.swap(n - 1, other);
        }
        usable.truncate(n);
        usable
            .into_iter()
            .map(|i| Pick {
                index: i,
                addr: res[i].addr,
                up: res[i].up,
                down: res[i].down,
            })
            .collect()
    }

    fn sent(&self, i: usize) {
        if let Some(r) = lock(&self.res).get_mut(i) {
            r.sent += 1;
            r.silent_since.get_or_insert_with(Instant::now);
        }
    }

    fn answered(&self, i: usize, rtt: Option<Duration>) {
        let mut res = lock(&self.res);
        if let Some(r) = res.get_mut(i) {
            r.answered += 1;
            r.lost_in_row = 0;
            r.silent_since = None;
            if let Some(rtt) = rtt {
                let ms = rtt.as_secs_f64() * 1000.0;
                r.srtt = Some(r.srtt.map_or(ms, |s| s * 0.875 + ms * 0.125));
            }
        }
    }

    /// A query lost (or refused): after enough of them in a row, or a long silence, the
    /// resolver is set aside until it is tested again.
    fn lost(&self, i: usize) {
        let now = Instant::now();
        let mut res = lock(&self.res);
        let Some(r) = res.get_mut(i) else {
            return;
        };
        r.lost_in_row += 1;
        let silent = r
            .silent_since
            .is_some_and(|t| now.duration_since(t) >= SILENT_WINDOW);
        if r.state != State::Active || (r.lost_in_row < FAILS_TO_BENCH && !silent) {
            return;
        }
        r.state = State::Off;
        r.lost_in_row = 0;
        r.silent_since = None;
        let rest = r.rest();
        r.retest_at = Some(now + rest);
        let addr = r.addr;
        let active = res.iter().filter(|r| r.state == State::Active).count();
        tracing::info!(resolver = %addr, active, "dns: resolver stopped answering, set aside");
    }

    /// Records a test's result.
    fn tested(&self, i: usize, result: Option<Measured>) {
        let mut res = lock(&self.res);
        let Some(r) = res.get_mut(i) else {
            return;
        };
        match result {
            Some(m) => {
                r.state = State::Active;
                r.up = m.up;
                r.down = m.down;
                r.srtt = Some(m.rtt.as_secs_f64() * 1000.0);
                r.lost_in_row = 0;
                r.silent_since = None;
                r.retest_at = None;
                drop(res);
                if !self.any_ready.swap(true, Ordering::AcqRel) {
                    self.ready.notify_waiters();
                }
            }
            None => {
                r.state = State::Dead;
                let rest = r.rest();
                r.retest_at = Some(Instant::now() + rest);
            }
        }
    }

    /// The resolvers that answered, with their upload and download sizes and round trip,
    /// quickest first: what the scan file and `wormhole dns-scan` show.
    pub fn answering(&self) -> Vec<(SocketAddr, usize, usize, Option<f64>)> {
        let mut out: Vec<_> = lock(&self.res)
            .iter()
            .filter(|r| r.state == State::Active)
            .map(|r| (r.addr, r.up, r.down, r.srtt))
            .collect();
        out.sort_by(|a, b| a.3.unwrap_or(f64::MAX).total_cmp(&b.3.unwrap_or(f64::MAX)));
        out
    }

    /// How many resolvers are in use, of how many.
    pub fn counts(&self) -> (usize, usize) {
        let res = lock(&self.res);
        let active = res.iter().filter(|r| r.state == State::Active).count();
        (active, res.len())
    }

    /// Tests every resolver now and waits for the results.
    pub async fn scan_now(self: &Arc<Self>) {
        scan_all(Arc::downgrade(self)).await;
    }
}

/// What a test found.
#[derive(Debug, Clone, Copy)]
struct Measured {
    up: usize,
    down: usize,
    rtt: Duration,
}

/// Tests every resolver (`parallel` at a time), then logs and saves the ones that
/// answered.
async fn scan_all(pool: Weak<Pool>) {
    let Some(p) = pool.upgrade() else {
        return;
    };
    let started = Instant::now();
    let total = lock(&p.res).len();
    let gate = Arc::new(Semaphore::new(p.cfg.parallel.max(1)));
    let mut jobs = Vec::with_capacity(total);
    for i in 0..total {
        let gate = gate.clone();
        let pool = pool.clone();
        jobs.push(tokio::spawn(async move {
            let Ok(_permit) = gate.acquire_owned().await else {
                return;
            };
            let Some(p) = pool.upgrade() else {
                return;
            };
            let addr = lock(&p.res)[i].addr;
            let result = measure(&p.cfg, addr).await;
            p.tested(i, result);
        }));
    }
    drop(p);
    for job in jobs {
        let _ = job.await;
    }
    let Some(p) = pool.upgrade() else {
        return;
    };
    p.scanned.store(true, Ordering::Release);
    p.ready.notify_waiters();
    let answering = p.answering();
    let ups: Vec<usize> = answering.iter().map(|a| a.1).collect();
    let downs: Vec<usize> = answering.iter().map(|a| a.2).collect();
    tracing::info!(
        answering = answering.len(),
        of = total,
        upload = %range(&ups),
        download = %range(&downs),
        secs = started.elapsed().as_secs(),
        "dns: resolvers tested"
    );
    if answering.is_empty() {
        tracing::warn!(
            "dns: no resolver brought an answer back from the tunnel domain; they are tested again in the background"
        );
    }
    if let Some(path) = &p.cfg.save {
        if let Err(e) = std::fs::write(path, scan_report(&answering)) {
            tracing::warn!(path = %path.display(), "dns: could not save the resolvers: {e}");
        }
    }
}

/// The resolvers that answered, one per line, in the form `resolvers_file` reads back.
pub fn scan_report(answering: &[(SocketAddr, usize, usize, Option<f64>)]) -> String {
    let mut text =
        String::from("# resolvers that answered through the tunnel domain, quickest first\n");
    for (addr, up, down, rtt) in answering {
        let rtt = rtt.map_or(0, |r| r.round() as u64);
        text.push_str(&format!("{addr}  # up {up} B, down {down} B, {rtt} ms\n"));
    }
    text
}

fn range(v: &[usize]) -> String {
    match (v.iter().min(), v.iter().max()) {
        (Some(a), Some(b)) if a == b => a.to_string(),
        (Some(a), Some(b)) => format!("{a}-{b}"),
        _ => "-".into(),
    }
}

/// Every [`RECHECK_EVERY`]: tests again the resolvers set aside or dead whose rest is over.
async fn recheck(pool: Weak<Pool>) {
    loop {
        tokio::time::sleep(RECHECK_EVERY).await;
        let Some(p) = pool.upgrade() else {
            return;
        };
        if !p.scanned.load(Ordering::Acquire) {
            continue;
        }
        let now = Instant::now();
        let due: Vec<(usize, SocketAddr)> = lock(&p.res)
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                matches!(r.state, State::Off | State::Dead) && r.retest_at.is_some_and(|t| now >= t)
            })
            .map(|(i, r)| (i, r.addr))
            .take(p.cfg.parallel.max(1))
            .collect();
        let jobs: Vec<_> = due
            .into_iter()
            .map(|(i, addr)| {
                let pool = pool.clone();
                let cfg = p.cfg.clone();
                tokio::spawn(async move {
                    let result = measure(&cfg, addr).await;
                    if let Some(p) = pool.upgrade() {
                        if result.is_some() {
                            tracing::info!(resolver = %addr, "dns: resolver answers again");
                        }
                        p.tested(i, result);
                    }
                })
            })
            .collect();
        drop(p);
        for job in jobs {
            let _ = job.await;
        }
    }
}

/// Tests a resolver: does a small probe come back through it, and what are the largest
/// query data (upload) and answer (download) it passes, each found by halving the range.
async fn measure(cfg: &PoolConfig, addr: SocketAddr) -> Option<Measured> {
    let bind: SocketAddr = if addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    let ceiling = cfg.upload_ceiling();
    let small_up = cfg
        .upload
        .0
        .clamp(wire::QUERY_HEADER + wire::PROBE_TOKEN, ceiling);
    let big_up = cfg.upload.1.clamp(small_up, ceiling);
    let small_down = cfg.download.0.max(1 + wire::PROBE_TOKEN);
    let big_down = cfg.download.1.max(small_down);
    let rtt = probe(cfg, &socket, addr, small_up, small_down).await?;
    // Upload: the largest name it passes, with a small answer.
    let (mut lo, mut hi) = (small_up, big_up);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if probe(cfg, &socket, addr, mid, small_down).await.is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let up = lo;
    // Download: the largest answer it brings back, asked with a name as long as the data
    // queries' (a resolver's limit is on the whole message, the question included).
    let (mut lo, mut hi) = (small_down, big_down);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if probe(cfg, &socket, addr, up, mid).await.is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Some(Measured { up, down: lo, rtt })
}

/// One probe: query data of `up` bytes asking for an answer of `down` bytes. Its round
/// trip if the answer came back whole and from the listener (its token echoed).
async fn probe(
    cfg: &PoolConfig,
    socket: &UdpSocket,
    addr: SocketAddr,
    up: usize,
    down: usize,
) -> Option<Duration> {
    let token = crate::crypto::random_bytes::<{ wire::PROBE_TOKEN }>().ok()?;
    let mut data = token.to_vec();
    data.resize(
        up.saturating_sub(wire::QUERY_HEADER).max(wire::PROBE_TOKEN),
        b'p',
    );
    let domain = &cfg.domains[random_below(cfg.domains.len())];
    let mut buf = vec![0u8; 4096];
    let mut out = Vec::with_capacity(300);
    for _ in 0..=cfg.retries {
        let id = random_u16();
        let q = Upstream {
            session: 0,
            nonce: random_u16(),
            packet: down.min(usize::from(u16::MAX)) as u16,
            index: 0,
            count: 0,
            down: 0,
            flags: if cfg.base64 { wire::BASE64 } else { 0 },
            data: &data,
        };
        wire::encode_query(&mut out, id, domain, &q).ok()?;
        let sent = Instant::now();
        socket.send_to(&out, addr).await.ok()?;
        let deadline = sent + cfg.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Ok(Ok((n, from))) = tokio::time::timeout(left, socket.recv_from(&mut buf)).await
            else {
                break;
            };
            let Some(r) = wire::decode_response(&buf[..n]) else {
                continue;
            };
            if from != addr || r.id != id {
                continue;
            }
            let payload = r.payload.and_then(|p| wire::answer_payload(p, cfg.base64));
            let whole = !r.truncated
                && r.rcode == 0
                && payload.as_ref().is_some_and(|p| {
                    p.len() == down && p[0] == b'P' && p[1..=wire::PROBE_TOKEN] == token
                });
            // An answer, but cut short or not ours: this size does not pass.
            return whole.then(|| sent.elapsed());
        }
    }
    None
}

// ---------------------------------------------------------------- the dialing side

struct Inflight {
    resolver: usize,
    sent: Instant,
    poll: bool,
}

/// A packet coming down in fragments.
struct Incoming {
    parts: Vec<Option<Vec<u8>>>,
    last: Option<usize>,
    first: Instant,
}

struct ClientState {
    inflight: HashMap<u16, Inflight>,
    next_packet: u16,
    nonce: u16,
    last_data: Instant,
    last_poll: Instant,
    /// Polls to send beyond the target, because the listener said it has more.
    extra: usize,
    incoming: HashMap<u16, Incoming>,
    scratch: Vec<u8>,
}

/// The dialing side of one connection: queries out through the pool's resolvers, packets
/// back from the answers.
pub struct Client {
    pool: Arc<Pool>,
    v4: Option<Arc<UdpSocket>>,
    v6: Option<Arc<UdpSocket>>,
    session: u32,
    started: Instant,
    state: Mutex<ClientState>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    wake: Arc<Notify>,
    tasks: Mutex<Option<Tasks>>,
}

impl Client {
    pub async fn start(pool: Arc<Pool>, buffer: usize) -> io::Result<Arc<Self>> {
        if pool.cfg.resolvers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no dns resolvers",
            ));
        }
        pool.wait_ready().await;
        let bind = |addr: SocketAddr| -> io::Result<Arc<UdpSocket>> {
            Ok(Arc::new(crate::transport::kcp::bind_udp_socket(
                addr, buffer,
            )?))
        };
        let v4 = if pool.cfg.resolvers.iter().any(SocketAddr::is_ipv4) {
            Some(bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?)
        } else {
            None
        };
        let v6 = if pool.cfg.resolvers.iter().any(SocketAddr::is_ipv6) {
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
        let now = Instant::now();
        let client = Arc::new(Self {
            pool,
            v4: v4.clone(),
            v6: v6.clone(),
            session: random_u32().max(1),
            started: now,
            state: Mutex::new(ClientState {
                inflight: HashMap::new(),
                next_packet: random_u16(),
                nonce: random_u16(),
                last_data: now,
                last_poll: now,
                extra: 0,
                incoming: HashMap::new(),
                scratch: Vec::with_capacity(512),
            }),
            inbound: tokio::sync::Mutex::new(rx),
            wake: Arc::new(Notify::new()),
            tasks: Mutex::new(None),
        });
        let mut tasks = Vec::new();
        for socket in [v4, v6].into_iter().flatten() {
            let me = Arc::downgrade(&client);
            tasks.push(tokio::spawn(read_answers(socket, me, tx.clone())));
        }
        tasks.push(tokio::spawn(keep_polling(Arc::downgrade(&client))));
        *lock(&client.tasks) = Some(Tasks(tasks));
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

    /// The resolver the pool would pick now (what the status shows as the peer).
    pub fn best(&self) -> SocketAddr {
        self.pool
            .pick(1)
            .first()
            .map_or(self.pool.cfg.resolvers[0], |p| p.addr)
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

    fn flags(&self) -> u8 {
        if self.pool.cfg.base64 {
            wire::BASE64
        } else {
            0
        }
    }

    /// Sends a packet through as many resolvers as the copies asked for. All copies are
    /// split alike (to fit the smallest of the picked resolvers), so the listener can join
    /// fragments from any of them.
    pub fn try_send(&self, payload: &[u8]) -> io::Result<usize> {
        let copies = if self.started.elapsed() < SETUP_FOR {
            self.pool.cfg.setup_duplicate.max(self.pool.cfg.duplicate)
        } else {
            self.pool.cfg.duplicate
        };
        let picked = self.pool.pick(copies);
        let up = picked
            .iter()
            .map(|p| p.up)
            .min()
            .unwrap_or_else(|| self.pool.cfg.upload_ceiling());
        let domain = self.domain_for(up);
        let room = up
            .min(domain.query_capacity())
            .saturating_sub(wire::QUERY_HEADER)
            .max(1);
        let count = payload.len().div_ceil(room).max(1);
        if count > wire::MAX_FRAGMENTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too large for the dns resolvers' query names: lower tunnel.kcp.mtu",
            ));
        }
        let mut st = lock(&self.state);
        let packet = st.next_packet;
        st.next_packet = st.next_packet.wrapping_add(1);
        st.last_data = Instant::now();
        let mut any = false;
        for pick in picked {
            for (index, data) in payload.chunks(room).enumerate() {
                let up = Upstream {
                    session: self.session,
                    nonce: 0,
                    packet,
                    index: index as u8,
                    count: count as u8,
                    down: down_units(pick.down),
                    flags: self.flags(),
                    data,
                };
                any |= self.send(&mut st, pick, domain, up, false);
            }
            // An empty packet still goes, as one empty fragment.
            if payload.is_empty() {
                let up = Upstream {
                    session: self.session,
                    nonce: 0,
                    packet,
                    index: 0,
                    count: 1,
                    down: down_units(pick.down),
                    flags: self.flags(),
                    data: &[],
                };
                any |= self.send(&mut st, pick, domain, up, false);
            }
        }
        drop(st);
        self.wake.notify_one();
        if any {
            Ok(payload.len())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "dns queries not sent",
            ))
        }
    }

    /// A domain to send `up` bytes under: a random one among those with room for it, or
    /// the one with the most.
    fn domain_for(&self, up: usize) -> &Domain {
        let ds = &self.pool.cfg.domains;
        let fits: Vec<&Domain> = ds.iter().filter(|d| d.query_capacity() >= up).collect();
        if fits.is_empty() {
            ds.iter()
                .max_by_key(|d| d.query_capacity())
                .unwrap_or(&ds[0])
        } else {
            fits[random_below(fits.len())]
        }
    }

    /// Sends one query through `pick`.
    fn send(
        &self,
        st: &mut ClientState,
        pick: Pick,
        domain: &Domain,
        up: Upstream<'_>,
        poll: bool,
    ) -> bool {
        st.nonce = st.nonce.wrapping_add(1);
        let up = Upstream {
            nonce: st.nonce,
            ..up
        };
        let mut id = random_u16();
        while st.inflight.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        let mut out = std::mem::take(&mut st.scratch);
        let mut sent = false;
        if wire::encode_query(&mut out, id, domain, &up).is_ok() {
            let socket = if pick.addr.is_ipv4() {
                &self.v4
            } else {
                &self.v6
            };
            if let Some(socket) = socket {
                if socket.try_send_to(&out, pick.addr).is_ok() {
                    self.pool.sent(pick.index);
                    let at = Instant::now();
                    st.inflight.insert(
                        id,
                        Inflight {
                            resolver: pick.index,
                            sent: at,
                            poll,
                        },
                    );
                    sent = true;
                }
            }
        }
        st.scratch = out;
        sent
    }

    /// Times out lost queries and keeps polls going at the pace the connection's activity
    /// calls for.
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
                self.pool.lost(q.resolver);
            }
        }
        st.incoming
            .retain(|_, p| now.duration_since(p.first) < PARTIAL_TTL);
        let idle = now.duration_since(st.last_data);
        let waiting = st.inflight.values().filter(|q| q.poll).count();
        let since_poll = now.duration_since(st.last_poll);
        let wanted = if idle < ACTIVE_FOR {
            POLLS_ACTIVE.saturating_sub(waiting)
        } else if idle < WARM {
            1usize.saturating_sub(waiting)
        } else {
            let every = if idle < COOL {
                LAZY
            } else if idle < COLD {
                COOLDOWN
            } else {
                COLD_EVERY
            };
            usize::from(waiting == 0 && since_poll >= every)
        };
        let wanted = (wanted + std::mem::take(&mut st.extra)).min(POLLS_ACTIVE * 2);
        for _ in 0..wanted {
            let Some(&pick) = self.pool.pick(1).first() else {
                break;
            };
            let poll = Upstream {
                session: self.session,
                nonce: 0,
                packet: 0,
                index: 0,
                count: 0,
                down: down_units(pick.down),
                flags: self.flags(),
                data: &[],
            };
            let domain = self.domain_for(wire::QUERY_HEADER);
            self.send(&mut st, pick, domain, poll, true);
            st.last_poll = now;
        }
    }

    /// Takes in a resolver's answer.
    fn answered(&self, message: &[u8], tx: &mpsc::Sender<Vec<u8>>) {
        let Some(response) = wire::decode_response(message) else {
            return;
        };
        let now = Instant::now();
        let mut st = lock(&self.state);
        let Some(q) = st.inflight.remove(&response.id) else {
            return;
        };
        if response.rcode != 0 {
            self.pool.lost(q.resolver);
            return;
        }
        // A held poll's time is the listener's, not the resolver's.
        let rtt = (!q.poll).then(|| now.duration_since(q.sent));
        self.pool.answered(q.resolver, rtt);
        let Some(payload) = response
            .payload
            .and_then(|p| wire::answer_payload(p, self.pool.cfg.base64))
        else {
            return;
        };
        let Some((flags, fragments)) = wire::read_fragments(&payload) else {
            return;
        };
        if !fragments.is_empty() {
            st.last_data = now;
        }
        for f in fragments {
            if f.index == 0 && f.last {
                let _ = tx.try_send(f.data.to_vec());
                continue;
            }
            let part = st.incoming.entry(f.packet).or_insert_with(|| Incoming {
                parts: Vec::new(),
                last: None,
                first: now,
            });
            let i = usize::from(f.index);
            if part.parts.len() <= i {
                part.parts.resize(i + 1, None);
            }
            part.parts[i] = Some(f.data.to_vec());
            if f.last {
                part.last = Some(i);
            }
            let whole = part.last.is_some_and(|l| {
                part.parts.len() == l + 1 && part.parts.iter().all(Option::is_some)
            });
            if whole {
                if let Some(p) = st.incoming.remove(&f.packet) {
                    let packet: Vec<u8> = p.parts.into_iter().flatten().flatten().collect();
                    let _ = tx.try_send(packet);
                }
            }
        }
        if flags & wire::MORE != 0 {
            // The listener has more queued: a few more polls to fetch it.
            st.extra += 4;
            st.last_data = now;
            drop(st);
            self.wake.notify_one();
        }
    }
}

/// A resolver's answer size, as a query's `down` field (8-byte units, 1 to 255).
fn down_units(down: usize) -> u8 {
    (down / 8).clamp(1, 255) as u8
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
        tokio::select! {
            () = wake.notified() => {}
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

/// A packet going down, and how much of it has gone.
struct Outgoing {
    packet: u16,
    data: Vec<u8>,
    sent: usize,
    next_index: u8,
}

struct Session {
    partial: HashMap<u16, Partial>,
    /// Packets that came whole lately, so a copy is not delivered twice.
    recent: VecDeque<u16>,
    recent_set: HashSet<u16>,
    down: VecDeque<Outgoing>,
    next_packet: u16,
    queued: usize,
    parked: VecDeque<Parked>,
    last: Instant,
}

impl Session {
    fn new() -> Self {
        Self {
            partial: HashMap::new(),
            recent: VecDeque::new(),
            recent_set: HashSet::new(),
            down: VecDeque::new(),
            next_packet: 0,
            queued: 0,
            parked: VecDeque::new(),
            last: Instant::now(),
        }
    }

    /// Notes a packet that came whole; `false` if it already had.
    fn first_time(&mut self, packet: u16) -> bool {
        if !self.recent_set.insert(packet) {
            return false;
        }
        self.recent.push_back(packet);
        if self.recent.len() > 1024 {
            if let Some(old) = self.recent.pop_front() {
                self.recent_set.remove(&old);
            }
        }
        true
    }
}

/// The listening side: the authoritative server of the tunnel domains.
pub struct Authority {
    socket: Arc<UdpSocket>,
    domains: Vec<Domain>,
    sessions: Mutex<HashMap<u32, Session>>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    /// Where queries for other names go (`fallback`), and who asked them.
    fallback: Option<(Arc<UdpSocket>, SocketAddr)>,
    asked: Mutex<HashMap<u16, (SocketAddr, u16, Instant)>>,
    tasks: Mutex<Option<Tasks>>,
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
    pub async fn start(
        addr: SocketAddr,
        domains: Vec<Domain>,
        fallback: Option<SocketAddr>,
        buffer: usize,
    ) -> io::Result<Arc<Self>> {
        let socket = Arc::new(crate::transport::kcp::bind_udp_socket(addr, buffer)?);
        socket.writable().await?;
        let fallback = match fallback {
            Some(to) => {
                let bind: SocketAddr = if to.is_ipv4() {
                    (Ipv4Addr::UNSPECIFIED, 0).into()
                } else {
                    (Ipv6Addr::UNSPECIFIED, 0).into()
                };
                let s = Arc::new(UdpSocket::bind(bind).await?);
                s.writable().await?;
                Some((s, to))
            }
            None => None,
        };
        let (tx, rx) = mpsc::channel(4096);
        let me = Arc::new(Self {
            socket: socket.clone(),
            domains,
            sessions: Mutex::new(HashMap::new()),
            inbound: tokio::sync::Mutex::new(rx),
            fallback: fallback.clone(),
            asked: Mutex::new(HashMap::new()),
            tasks: Mutex::new(None),
        });
        let mut tasks = vec![
            tokio::spawn(read_queries(socket, Arc::downgrade(&me), tx)),
            tokio::spawn(answer_late(Arc::downgrade(&me))),
        ];
        if let Some((s, _)) = fallback {
            tasks.push(tokio::spawn(relay_fallback(s, Arc::downgrade(&me))));
        }
        *lock(&me.tasks) = Some(Tasks(tasks));
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
        let packet = session.next_packet;
        session.next_packet = session.next_packet.wrapping_add(1);
        session.down.push_back(Outgoing {
            packet,
            data: payload.to_vec(),
            sent: 0,
            next_index: 0,
        });
        if let Some(parked) = session.parked.pop_front() {
            self.answer(session, parked.from, &parked.message);
        }
        Ok(payload.len())
    }

    /// Answers the query `message` from `from` with fragments of what the session has
    /// queued, as many and as large as that query's resolver takes.
    fn answer(&self, session: &mut Session, from: SocketAddr, message: &[u8]) {
        let Some(query) = wire::decode_query(message, &self.domains) else {
            return;
        };
        let Some(up) = query.data.as_deref().and_then(wire::parse_upstream) else {
            return;
        };
        let base64 = up.flags & wire::BASE64 != 0;
        let cap = wire::answer_capacity(&query, up.down, base64);
        let mut payload = Vec::with_capacity(cap.min(2048));
        payload.push(0);
        while let Some(front) = session.down.front_mut() {
            let room = cap.saturating_sub(payload.len() + wire::ANSWER_FRAGMENT_HEADER);
            let left = front.data.len() - front.sent;
            if room == 0 || (room < MIN_PIECE && left > room) {
                break;
            }
            let take = left.min(room);
            let last = take == left;
            if !last && usize::from(front.next_index) + 1 >= wire::MAX_FRAGMENTS {
                // It would take more fragments than an index holds: dropped, KCP resends.
                session.queued -= left;
                session.down.pop_front();
                continue;
            }
            wire::push_fragment(
                &mut payload,
                &DownFragment {
                    packet: front.packet,
                    index: front.next_index,
                    last,
                    data: &front.data[front.sent..front.sent + take],
                },
            );
            front.sent += take;
            front.next_index = front.next_index.wrapping_add(1);
            session.queued -= take;
            if last {
                session.down.pop_front();
            }
        }
        if !session.down.is_empty() {
            payload[0] |= wire::MORE;
        }
        let mut out = Vec::with_capacity(payload.len() * 4 / 3 + 300);
        wire::encode_answer(&mut out, &query, Answer::Data(&payload), base64);
        let _ = self.socket.try_send_to(&out, from);
    }

    /// Answers a query that carries no tunnel data: passed on to the fallback server if it
    /// is for another name and one is set, else refused (another domain) or answered with
    /// no records (the domain itself, the steps of a resolver's query-name minimisation,
    /// another type).
    fn not_data(&self, query: &wire::Query<'_>, message: &[u8], from: SocketAddr) {
        if !query.under {
            if let Some((socket, to)) = &self.fallback {
                let id = random_u16();
                let now = Instant::now();
                let mut asked = lock(&self.asked);
                asked.retain(|_, (_, _, t)| now.duration_since(*t) < Duration::from_secs(10));
                asked.insert(id, (from, query.id, now));
                drop(asked);
                let mut forward = message.to_vec();
                forward[..2].copy_from_slice(&id.to_be_bytes());
                let _ = socket.try_send_to(&forward, *to);
                return;
            }
        }
        let answer = if query.under {
            Answer::Empty
        } else {
            Answer::Refused
        };
        let mut out = Vec::with_capacity(message.len() + 16);
        wire::encode_answer(&mut out, query, answer, false);
        let _ = self.socket.try_send_to(&out, from);
    }

    /// Answers a probe: an answer of the size it asks for (as far as the asker's buffer
    /// takes), its token first.
    fn probe(&self, query: &wire::Query<'_>, up: &Upstream<'_>, from: SocketAddr) {
        let base64 = up.flags & wire::BASE64 != 0;
        let size = usize::from(up.packet).min(wire::answer_capacity(query, 0, base64));
        let payload = wire::probe_answer(up.data, size);
        let mut out = Vec::with_capacity(size * 4 / 3 + 300);
        wire::encode_answer(&mut out, query, Answer::Data(&payload), base64);
        let _ = self.socket.try_send_to(&out, from);
    }

    /// Takes in a query: answers at once what is not tunnel data and probes, keeps
    /// fragments, and holds the query until there is something to answer with.
    fn query(&self, message: &[u8], from: SocketAddr, tx: &mpsc::Sender<(Vec<u8>, SocketAddr)>) {
        let Some(query) = wire::decode_query(message, &self.domains) else {
            return;
        };
        let Some(up) = query.data.as_deref().and_then(wire::parse_upstream) else {
            self.not_data(&query, message, from);
            return;
        };
        if up.is_probe() {
            self.probe(&query, &up, from);
            return;
        }
        let now = Instant::now();
        let mut sessions = lock(&self.sessions);
        if !sessions.contains_key(&up.session) && sessions.len() >= MAX_SESSIONS {
            return;
        }
        let session = sessions.entry(up.session).or_insert_with(Session::new);
        session.last = now;
        if up.count > 0 && !session.recent_set.contains(&up.packet) {
            let whole = if up.count == 1 {
                Some(up.data.to_vec())
            } else {
                let count = usize::from(up.count);
                let partial = session.partial.entry(up.packet).or_insert_with(|| Partial {
                    parts: vec![None; count],
                    first: now,
                });
                if partial.parts.len() == count {
                    partial.parts[usize::from(up.index)] = Some(up.data.to_vec());
                }
                if partial.parts.iter().all(Option::is_some) {
                    session
                        .partial
                        .remove(&up.packet)
                        .map(|p| p.parts.into_iter().flatten().flatten().collect())
                } else {
                    None
                }
            };
            if let Some(packet) = whole {
                if session.first_time(up.packet) {
                    let _ = tx.try_send((packet, session_addr(up.session)));
                }
            }
        }
        if !session.down.is_empty() {
            self.answer(session, from, message);
            return;
        }
        session.parked.push_back(Parked {
            from,
            message: message.to_vec(),
            deadline: now + HOLD,
        });
        while session.parked.len() > MAX_PARKED {
            if let Some(old) = session.parked.pop_front() {
                self.answer(session, old.from, &old.message);
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
                    self.answer(session, p.from, &p.message);
                }
            }
            // Waiting polls take what is queued.
            while !session.down.is_empty() {
                let Some(p) = session.parked.pop_front() else {
                    break;
                };
                self.answer(session, p.from, &p.message);
            }
            session
                .partial
                .retain(|_, p| now.duration_since(p.first) < PARTIAL_TTL);
        }
    }

    /// Relays the fallback server's answer back to whoever asked.
    fn fallback_answer(&self, message: &mut [u8]) {
        if message.len() < wire::HEADER {
            return;
        }
        let id = u16::from_be_bytes([message[0], message[1]]);
        let Some((to, original, _)) = lock(&self.asked).remove(&id) else {
            return;
        };
        message[..2].copy_from_slice(&original.to_be_bytes());
        let _ = self.socket.try_send_to(message, to);
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

async fn relay_fallback(socket: Arc<UdpSocket>, me: Weak<Authority>) {
    let mut buf = vec![0u8; 65_536];
    loop {
        let Ok((n, _)) = socket.recv_from(&mut buf).await else {
            tokio::time::sleep(TICK).await;
            continue;
        };
        let Some(me) = me.upgrade() else {
            return;
        };
        me.fallback_answer(&mut buf[..n]);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver: forwards every query to the listener and every answer back, dropping
    /// answers larger than `max_answer` (a resolver with a small buffer) and, if
    /// `dead_after` is set, everything once it has relayed that many queries.
    async fn relay(
        listener: SocketAddr,
        max_answer: usize,
        dead_after: Option<usize>,
    ) -> SocketAddr {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            let mut asked: HashMap<u16, SocketAddr> = HashMap::new();
            let mut relayed = 0usize;
            loop {
                let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                if from == listener {
                    if n > max_answer {
                        continue;
                    }
                    if let Some(to) = asked.remove(&id) {
                        let _ = socket.send_to(&buf[..n], to).await;
                    }
                } else {
                    relayed += 1;
                    if dead_after.is_some_and(|d| relayed > d) {
                        continue;
                    }
                    asked.insert(id, from);
                    let _ = socket.send_to(&buf[..n], listener).await;
                }
            }
        });
        addr
    }

    fn domain() -> Domain {
        Domain::parse("t.example.com").unwrap()
    }

    fn cfg(resolvers: Vec<SocketAddr>) -> PoolConfig {
        PoolConfig {
            domains: vec![domain()],
            resolvers,
            duplicate: 1,
            setup_duplicate: 1,
            balance: Balance::Hybrid,
            base64: false,
            scan: true,
            upload: (40, 400),
            download: (100, 1200),
            timeout: Duration::from_millis(400),
            retries: 0,
            parallel: 16,
            save: None,
        }
    }

    async fn authority() -> Arc<Authority> {
        Authority::start(
            "127.0.0.1:0".parse().unwrap(),
            vec![domain()],
            None,
            1 << 20,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn the_scan_measures_each_resolver_and_leaves_out_the_dead() {
        let auth = authority().await;
        let at = auth.local_addr();
        let big = relay(at, 4096, None).await;
        let small = relay(at, 600, None).await;
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead = dead.local_addr().unwrap();
        let save = std::env::temp_dir().join(format!("wormhole-dns-scan-{}.txt", random_u32()));
        let mut c = cfg(vec![big, small, dead]);
        c.save = Some(save.clone());
        let pool = Pool::idle(c);
        pool.scan_now().await;
        let found = pool.answering();
        assert_eq!(found.len(), 2, "{found:?}");
        let get = |a: SocketAddr| *found.iter().find(|f| f.0 == a).unwrap();
        // The upload is all the domain leaves room for; the small resolver brings back less.
        assert_eq!(get(big).1, domain().query_capacity());
        // The large one: what the 1232-byte EDNS0 buffer leaves after a full question.
        assert!(get(big).2 > 800 && get(big).2 < 1000, "{:?}", get(big));
        assert!(get(small).2 < 350 && get(small).2 > 150, "{:?}", get(small));
        let saved = std::fs::read_to_string(&save).unwrap();
        let _ = std::fs::remove_file(&save);
        assert!(saved.contains(&big.to_string()) && saved.contains(&small.to_string()));
        assert!(!saved.contains(&dead.to_string()));
        assert_eq!(pool.counts(), (2, 3));
        // What it saved reads back as a resolver list.
        let back = expand_resolvers(resolver_entries(&saved)).unwrap();
        assert_eq!(back.len(), 2);
    }

    #[tokio::test]
    async fn packets_cross_both_ways_split_to_each_resolvers_size() {
        let auth = authority().await;
        let at = auth.local_addr();
        let resolvers = vec![relay(at, 4096, None).await, relay(at, 500, None).await];
        let mut c = cfg(resolvers);
        c.duplicate = 2;
        let pool = Pool::start(c);
        let client = Client::start(pool.clone(), 1 << 20).await.unwrap();
        pool.wait_ready().await;

        // Up: a packet of several fragments arrives whole, and once, though sent twice.
        let big: Vec<u8> = (0..900u32).map(|i| (i * 7) as u8).collect();
        client.try_send(&big).unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), auth.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], &big[..]);
        client.try_send(b"next").unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), auth.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"next");

        // Down: packets larger than one answer come back whole through either resolver.
        for i in 0..20u8 {
            auth.try_send_to(&vec![i; 1500], from).unwrap();
        }
        for i in 0..20u8 {
            let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], &vec![i; 1500][..]);
        }
    }

    #[tokio::test]
    async fn base64_answers_cross_too() {
        let auth = authority().await;
        let resolvers = vec![relay(auth.local_addr(), 4096, None).await];
        let mut c = cfg(resolvers);
        c.base64 = true;
        let pool = Pool::start(c);
        let client = Client::start(pool.clone(), 1 << 20).await.unwrap();
        assert_eq!(pool.counts().0, 1);
        client.try_send(b"hello").unwrap();
        let mut buf = vec![0u8; 4096];
        let (_, from) = auth.recv_from(&mut buf).await.unwrap();
        auth.try_send_to(&[9u8; 2000], from).unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], &[9u8; 2000][..]);
    }

    #[tokio::test]
    async fn a_resolver_that_stops_answering_is_set_aside() {
        let auth = authority().await;
        let at = auth.local_addr();
        let good = relay(at, 4096, None).await;
        // Enough for its scan, then silent.
        let failing = relay(at, 4096, Some(40)).await;
        let mut c = cfg(vec![good, failing]);
        c.balance = Balance::RoundRobin;
        let pool = Pool::start(c);
        let client = Client::start(pool.clone(), 1 << 20).await.unwrap();
        pool.scan_now().await;
        assert_eq!(pool.counts().0, 2);
        // Traffic through both: the silent one's queries time out, and it is set aside.
        let mut buf = vec![0u8; 4096];
        for i in 0..30u8 {
            client.try_send(&[i; 50]).unwrap();
            let _ =
                tokio::time::timeout(Duration::from_millis(100), auth.recv_from(&mut buf)).await;
        }
        tokio::time::sleep(QUERY_TIMEOUT + Duration::from_millis(500)).await;
        assert_eq!(pool.counts().0, 1, "{:?}", snapshot(10));
        for _ in 0..10 {
            assert_eq!(pool.pick(1)[0].addr, good);
        }
        let shown = snapshot(100);
        assert!(shown
            .iter()
            .any(|r| r.addr == failing.to_string() && r.state == "off"));
    }

    #[test]
    fn the_strategies_pick_as_they_say() {
        let addrs: Vec<SocketAddr> = (1..=4).map(|i| ([10, 0, 0, i], 53).into()).collect();
        let mut c = cfg(addrs.clone());
        c.scan = false;
        let setup = |balance: Balance| {
            let pool = Pool::idle(PoolConfig {
                balance,
                ..c.clone()
            });
            for (i, r) in lock(&pool.res).iter_mut().enumerate() {
                r.sent = 100;
                r.answered = [50, 100, 80, 99][i];
                r.srtt = Some([100.0, 300.0, 20.0, 200.0][i]);
            }
            pool
        };
        for (balance, want) in [
            (Balance::LowestLatency, addrs[2]),
            (Balance::LeastLoss, addrs[1]),
            (Balance::Hybrid, addrs[2]),
            (Balance::LossThenLatency, addrs[3]),
        ] {
            let pool = setup(balance);
            let hits = (0..200).filter(|_| pool.pick(1)[0].addr == want).count();
            assert!(hits >= 160, "{balance:?}: {hits}");
        }
        // The top by loss is the two within 5 points of the best: 1 and 3.
        for balance in [Balance::LeastLossTopRandom, Balance::LeastLossTopRoundRobin] {
            let pool = setup(balance);
            let seen: HashSet<SocketAddr> = (0..100).map(|_| pool.pick(1)[0].addr).collect();
            assert_eq!(seen, HashSet::from([addrs[1], addrs[3]]), "{balance:?}");
        }
        c.balance = Balance::RoundRobin;
        let pool = Pool::idle(c.clone());
        let seen: HashSet<SocketAddr> = (0..4).map(|_| pool.pick(1)[0].addr).collect();
        assert_eq!(seen.len(), 4);
        let three = pool.pick(3);
        let distinct: HashSet<SocketAddr> = three.iter().map(|p| p.addr).collect();
        assert_eq!(distinct.len(), 3);
        assert_eq!(pool.pick(9).len(), 4);
        for name in Balance::NAMES {
            assert!(Balance::parse(name).is_some());
        }
        assert_eq!(Balance::parse("fastest"), None);
    }

    #[test]
    fn resolver_lists_take_ips_ports_and_ranges() {
        let text = "8.8.8.8, 1.1.1.1:5353\n10.0.0.0/30 192.168.1.0/31:5300\n[2001:db8::/126]:53\n  # a comment\n8.8.8.8 # again";
        let got = expand_resolvers(resolver_entries(text)).unwrap();
        let s: Vec<String> = got.iter().map(ToString::to_string).collect();
        assert_eq!(
            s,
            [
                "8.8.8.8:53",
                "1.1.1.1:5353",
                "10.0.0.1:53",
                "10.0.0.2:53",
                "192.168.1.0:5300",
                "192.168.1.1:5300",
                "[2001:db8::]:53",
                "[2001:db8::1]:53",
                "[2001:db8::2]:53",
                "[2001:db8::3]:53",
            ]
        );
        assert!(expand_resolvers(["dns.google"]).is_err());
        assert!(expand_resolvers(["10.0.0.0/8"]).is_err());
        assert!(expand_resolvers(["10.0.0.0/33"]).is_err());
        assert_eq!(expand_resolvers(["10.1.2.3/16"]).unwrap().len(), 65_534);
        assert_eq!(expand_resolvers(["10.1.2.3/32"]).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_listener_answers_other_names_and_can_pass_them_on() {
        // A stand-in DNS server that answers everything NXDOMAIN.
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = upstream.recv_from(&mut buf).await {
                buf[2] |= 0x80;
                buf[3] = (buf[3] & 0xf0) | 3;
                let _ = upstream.send_to(&buf[..n], from).await;
            }
        });
        let with_fallback = Authority::start(
            "127.0.0.1:0".parse().unwrap(),
            vec![domain(), Domain::parse("x.example.org").unwrap()],
            Some(upstream_addr),
            1 << 20,
        )
        .await
        .unwrap();
        let plain = authority().await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let ask = |name: &str| {
            let mut q = vec![0, 9, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            for l in name.split('.') {
                q.push(l.len() as u8);
                q.extend_from_slice(l.as_bytes());
            }
            q.extend_from_slice(&[0, 0, 1, 0, 1]);
            q
        };
        for (server, name, rcode) in [
            (plain.local_addr(), "other.net", 5u8),
            (plain.local_addr(), "t.example.com", 0),
            (with_fallback.local_addr(), "other.net", 3),
            (with_fallback.local_addr(), "t.example.com", 0),
            (with_fallback.local_addr(), "x.example.org", 0),
        ] {
            socket.send_to(&ask(name), server).await.unwrap();
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let r = wire::decode_response(&buf[..n]).unwrap();
            assert_eq!((r.id, r.rcode), (9, rcode), "{name} at {server}");
            assert!(r.payload.is_none());
        }
    }

    #[tokio::test]
    async fn every_domain_carries_data() {
        let domains = vec![domain(), Domain::parse("a.b.example.org").unwrap()];
        let auth = Authority::start(
            "127.0.0.1:0".parse().unwrap(),
            domains.clone(),
            None,
            1 << 20,
        )
        .await
        .unwrap();
        let mut c = cfg(vec![relay(auth.local_addr(), 4096, None).await]);
        c.domains = domains;
        c.scan = false;
        let pool = Pool::start(c);
        let client = Client::start(pool, 1 << 20).await.unwrap();
        let mut buf = vec![0u8; 4096];
        for i in 0..20u8 {
            client.try_send(&[i; 30]).unwrap();
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), auth.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], &[i; 30]);
        }
    }
}
