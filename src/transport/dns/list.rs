//! What the resolver path of `dns` is set to, and its resolver lists: apart from the
//! carrier itself ([`super::resolver`]), so the config reads them in every build.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use super::wire::{self, Domain};

/// The most resolvers a tunnel takes (after ranges are expanded).
pub const MAX_RESOLVERS: usize = 65_536;

/// How the next resolver is picked among those that answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Balance {
    RoundRobin,
    Random,
    LeastLoss,
    LowestLatency,
    /// Round trip weighed up by losses (the default).
    #[default]
    Hybrid,
    /// The fewest losses, then the shortest round trip among equals.
    LossThenLatency,
    /// A random one of the few with the fewest losses.
    LeastLossTopRandom,
    /// The few with the fewest losses, in turn.
    LeastLossTopRoundRobin,
}

impl Balance {
    pub const NAMES: [&'static str; 8] = [
        "round-robin",
        "random",
        "least-loss",
        "lowest-latency",
        "hybrid",
        "loss-then-latency",
        "least-loss-top-random",
        "least-loss-top-round-robin",
    ];

    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "round-robin" => Self::RoundRobin,
            "random" => Self::Random,
            "least-loss" => Self::LeastLoss,
            "lowest-latency" => Self::LowestLatency,
            "hybrid" => Self::Hybrid,
            "loss-then-latency" => Self::LossThenLatency,
            "least-loss-top-random" => Self::LeastLossTopRandom,
            "least-loss-top-round-robin" => Self::LeastLossTopRoundRobin,
            _ => return None,
        })
    }
}

/// What a tunnel's resolver path is set to (from `[tunnel.dns]`).
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub domains: Vec<Domain>,
    pub resolvers: Vec<SocketAddr>,
    pub duplicate: usize,
    pub setup_duplicate: usize,
    pub balance: Balance,
    pub base64: bool,
    /// Test the resolvers first; without it, all are used as they are, at the most sizes.
    pub scan: bool,
    /// The bounds of the sizes tested: query data (upload, header included) and answer
    /// payload (download).
    pub upload: (usize, usize),
    pub download: (usize, usize),
    pub timeout: Duration,
    pub retries: usize,
    pub parallel: usize,
    /// Where to write the resolvers that answered, with their sizes.
    pub save: Option<PathBuf>,
}

impl PoolConfig {
    /// The most query data the domains leave room for (the longest domain rules).
    pub fn upload_ceiling(&self) -> usize {
        self.domains
            .iter()
            .map(Domain::query_capacity)
            .min()
            .unwrap_or(wire::QUERY_HEADER + 1)
    }
}

/// The resolvers as `[tunnel.dns]` gives them, expanded: `IP`, `IP:port`, `CIDR` or
/// `CIDR:port` (IPv6 in brackets with a port: `[2001:db8::/120]:53`), port 53 if left off;
/// text after `#` is a comment. A CIDR stands for every address in it (its network and
/// broadcast addresses left out of an IPv4 range of four or more). Repeats are dropped;
/// at most [`MAX_RESOLVERS`] in all.
pub fn expand_resolvers<'a>(
    entries: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in entries {
        let entry = raw.split('#').next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        let addrs = expand_one(entry)
            .ok_or_else(|| format!("{entry:?} is not an IP, IP:port, CIDR or CIDR:port"))?;
        if addrs.len() > MAX_RESOLVERS {
            return Err(format!("{entry:?} is more than {MAX_RESOLVERS} addresses"));
        }
        for addr in addrs {
            if seen.insert(addr) {
                out.push(addr);
            }
        }
        if out.len() > MAX_RESOLVERS {
            return Err(format!("more than {MAX_RESOLVERS} resolvers"));
        }
    }
    Ok(out)
}

/// Splits a list file or text box into entries: one or more per line, by commas or spaces.
pub fn resolver_entries(text: &str) -> Vec<&str> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .flat_map(|l| l.split(|c: char| c == ',' || c.is_whitespace()))
        .filter(|e| !e.is_empty())
        .collect()
}

fn expand_one(entry: &str) -> Option<Vec<SocketAddr>> {
    if let Ok(a) = entry.parse::<SocketAddr>() {
        return Some(vec![a]);
    }
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(vec![(ip, 53).into()]);
    }
    let (net, port) = if let Some(rest) = entry.strip_prefix('[') {
        let (net, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => 53,
            None => return None,
        };
        (net, port)
    } else {
        let (ip, bits) = entry.split_once('/')?;
        match bits.split_once(':') {
            Some((bits, port)) => (&entry[..ip.len() + 1 + bits.len()], port.parse().ok()?),
            None => (entry, 53),
        }
    };
    let (ip, bits) = net.split_once('/')?;
    let bits: u32 = bits.parse().ok()?;
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            if !(16..=32).contains(&bits) {
                return None;
            }
            let mask = if bits == 32 {
                u32::MAX
            } else {
                !(u32::MAX >> bits)
            };
            let base = u32::from(v4) & mask;
            let size = 1u32 << (32 - bits);
            let (first, end) = if size >= 4 { (1, size - 1) } else { (0, size) };
            Some(
                (first..end)
                    .map(|i| SocketAddr::from((Ipv4Addr::from(base + i), port)))
                    .collect(),
            )
        }
        IpAddr::V6(v6) => {
            if !(112..=128).contains(&bits) {
                return None;
            }
            let mask = if bits == 128 {
                u128::MAX
            } else {
                !(u128::MAX >> bits)
            };
            let base = u128::from(v6) & mask;
            let size = 1u128 << (128 - bits);
            Some(
                (0..size)
                    .map(|i| SocketAddr::from((Ipv6Addr::from(base + i), port)))
                    .collect(),
            )
        }
    }
}
