//! `transport = "multi"`: one tunnel over several transports at once.
//!
//! Each transport listed in `[tunnel.multi]` gets a port of its own (the tunnel's port for
//! the first and the ports after it, or the ones listed). The dialing side keeps mux
//! sessions over every one of them, the accepting side listens on all of them, and both
//! put every session into one pool. New user connections and UDP flows go to the session
//! with the least expected wait (its streams weighed by its round trip, see
//! `session::manager`), so the load is shared over all the transports, a faster one takes
//! proportionally more, and when one is blocked its sessions drop and the others carry on.
//!
//! A member runs exactly as a tunnel of that transport alone would: [`Config::member`]
//! is the config it runs and is checked as, so every transport's own settings and checks
//! apply unchanged.

use anyhow::{bail, Context, Result};

use crate::config::{Config, TransportKind};

/// The fewest and most transports a `multi` tunnel takes.
pub const MEMBERS: std::ops::RangeInclusive<usize> = 2..=8;

/// A member transport as it runs: in `multi` every member is multiplexed, so `tcp` is
/// `tcpmux`.
pub fn normalize(kind: TransportKind) -> TransportKind {
    match kind {
        TransportKind::Tcp => TransportKind::Tcpmux,
        other => other,
    }
}

/// Sessions to keep over each member when the tunnel wants `total` (`mux.connections`):
/// the total shared out, rounded up, and at least one each, so a multi tunnel keeps about
/// as many sessions as a plain one.
pub fn connections_each(total: usize, members: usize) -> usize {
    total.div_ceil(members.max(1)).max(1)
}

/// The port of `addr` (`host:port`, `[v6]:port`).
pub fn port_of(addr: &str) -> Result<u16> {
    let (_, port) = addr
        .rsplit_once(':')
        .with_context(|| format!("{addr} has no port"))?;
    port.parse()
        .with_context(|| format!("{addr} does not end in a port"))
}

/// `addr` with its port replaced by `port`.
pub fn with_port(addr: &str, port: u16) -> Result<String> {
    let (host, _) = addr
        .rsplit_once(':')
        .with_context(|| format!("{addr} has no port"))?;
    Ok(format!("{host}:{port}"))
}

/// The ports of `transports` members on a tunnel whose own port is `base`: the ones
/// listed, or `base`, `base + 1`, ... in order.
pub fn ports(base: u16, count: usize, listed: &[u16]) -> Result<Vec<u16>> {
    if !listed.is_empty() {
        return Ok(listed.to_vec());
    }
    (0..count)
        .map(|i| {
            u16::try_from(usize::from(base) + i)
                .ok()
                .filter(|p| *p != 0)
                .with_context(|| {
                    format!("tunnel.multi: the port after {base} for member {} is past 65535; list the ports", i + 1)
                })
        })
        .collect()
}

impl Config {
    /// The members of a `multi` tunnel: each transport (normalized) and the address it
    /// listens on or dials (`tunnel.listen` or `tunnel.remote` on its own port).
    pub fn multi_members(&self) -> Result<Vec<(TransportKind, String)>> {
        let Some(multi) = &self.tunnel.multi else {
            bail!("transport = \"multi\" needs a [tunnel.multi] section listing its transports");
        };
        let addr = if self.is_acceptor() {
            self.tunnel.listen.as_deref()
        } else {
            self.tunnel.remote.as_deref()
        }
        .context("the tunnel has no address")?;
        let ports = ports(port_of(addr)?, multi.transports.len(), &multi.ports)?;
        multi
            .transports
            .iter()
            .zip(ports)
            .map(|(kind, port)| Ok((normalize(*kind), with_port(addr, port)?)))
            .collect()
    }

    /// The config the `multi` member `kind` runs as, at `addr`: this one with that
    /// transport, its address on the member's port, and only the sections that transport
    /// reads (the others belong to other members).
    pub fn member(&self, kind: TransportKind, addr: &str) -> Config {
        let mut c = self.clone();
        let t = &mut c.tunnel;
        t.transport = kind;
        t.multi = None;
        if self.is_acceptor() {
            t.listen = Some(addr.to_owned());
        } else {
            t.remote = Some(addr.to_owned());
        }
        if !reads_ws(kind) {
            t.ws = None;
        }
        if kind != TransportKind::Wss {
            t.tls = None;
        }
        if kind != TransportKind::Quic {
            t.quic = None;
        }
        if !reads_kcp(kind) {
            t.kcp = None;
        }
        if kind != TransportKind::Spoof {
            t.spoof = None;
        }
        if kind != TransportKind::Shadowtls {
            t.shadowtls = None;
        }
        c
    }

    /// Checks a `multi` tunnel: its list, its ports, and every member as the tunnel it
    /// runs as ([`Self::member`]).
    pub(crate) fn validate_multi(&self) -> Result<()> {
        let Some(multi) = &self.tunnel.multi else {
            bail!("transport = \"multi\" needs a [tunnel.multi] section listing its transports");
        };
        let n = multi.transports.len();
        if !MEMBERS.contains(&n) {
            bail!(
                "tunnel.multi.transports must list {} to {} transports (one is just that transport)",
                MEMBERS.start(),
                MEMBERS.end()
            );
        }
        let mut seen = Vec::new();
        for kind in &multi.transports {
            if matches!(kind, TransportKind::Auto | TransportKind::Multi) {
                bail!("tunnel.multi.transports cannot contain \"{}\"", kind.name());
            }
            let kind = normalize(*kind);
            if seen.contains(&kind) {
                bail!(
                    "tunnel.multi.transports lists {} twice (\"tcp\" and \"tcpmux\" are the same here)",
                    kind.name()
                );
            }
            seen.push(kind);
        }
        if !multi.ports.is_empty() {
            if multi.ports.len() != n {
                bail!("tunnel.multi.ports must have one port for each transport ({n}), or be left out");
            }
            if multi.ports.contains(&0) {
                bail!("tunnel.multi.ports cannot contain 0");
            }
        }
        if self.tunnel.mux.enabled == Some(false) {
            bail!("transport = \"multi\" always uses mux; tunnel.mux cannot be disabled");
        }
        if self.tunnel.mux.spread.is_some() {
            bail!("tunnel.mux.spread is for transport = \"auto\"; multi always spreads over its transports");
        }
        // A section no member reads is a mistake (a typo, or a transport left out).
        let used = |reads: fn(TransportKind) -> bool| seen.iter().any(|k| reads(*k));
        for (present, reads, name) in [
            (
                self.tunnel.ws.is_some(),
                reads_ws as fn(TransportKind) -> bool,
                "ws",
            ),
            (
                self.tunnel.tls.is_some(),
                |k| k == TransportKind::Wss,
                "tls",
            ),
            (
                self.tunnel.quic.is_some(),
                |k| k == TransportKind::Quic,
                "quic",
            ),
            (self.tunnel.kcp.is_some(), reads_kcp, "kcp"),
            (
                self.tunnel.spoof.is_some(),
                |k| k == TransportKind::Spoof,
                "spoof",
            ),
            (
                self.tunnel.shadowtls.is_some(),
                |k| k == TransportKind::Shadowtls,
                "shadowtls",
            ),
        ] {
            if present && !used(reads) {
                bail!("[tunnel.{name}] is not used by any of the tunnel.multi.transports");
            }
        }
        let members = self.multi_members()?;
        let mut ports: Vec<u16> = Vec::with_capacity(n);
        for (kind, addr) in &members {
            let port = port_of(addr)?;
            if ports.contains(&port) {
                bail!("tunnel.multi: two transports on port {port}; each needs a port of its own");
            }
            ports.push(port);
            self.member(*kind, addr)
                .validate()
                .with_context(|| format!("tunnel.multi member {} on {addr}", kind.name()))?;
        }
        Ok(())
    }
}

/// Transports that read `[tunnel.ws]`.
fn reads_ws(kind: TransportKind) -> bool {
    matches!(kind, TransportKind::Ws | TransportKind::Wss)
}

/// Transports that read `[tunnel.kcp]`.
fn reads_kcp(kind: TransportKind) -> bool {
    matches!(
        kind,
        TransportKind::Kcp
            | TransportKind::Paqet
            | TransportKind::Spoof
            | TransportKind::Icmp
            | TransportKind::Dns
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_share_the_connections_and_take_the_next_ports() {
        assert_eq!(connections_each(4, 3), 2);
        assert_eq!(connections_each(4, 2), 2);
        assert_eq!(connections_each(1, 3), 1);
        assert_eq!(ports(443, 3, &[]).unwrap(), vec![443, 444, 445]);
        assert_eq!(ports(443, 2, &[80, 8443]).unwrap(), vec![80, 8443]);
        assert!(ports(65535, 2, &[]).is_err());
        assert_eq!(with_port("[::]:443", 445).unwrap(), "[::]:445");
        assert_eq!(
            with_port("203.0.113.5:443", 8443).unwrap(),
            "203.0.113.5:8443"
        );
        assert_eq!(port_of("[2001:db8::1]:51820").unwrap(), 51820);
        assert_eq!(normalize(TransportKind::Tcp), TransportKind::Tcpmux);
    }
}
