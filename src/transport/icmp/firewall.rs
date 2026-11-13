//! The host firewall rules one `icmp` socket needs, added when the socket opens and
//! removed when it closes.
//!
//! `icmp` carries the tunnel in ICMP echo requests. Two things on the host get in the
//! way without rules:
//!
//! - the kernel answers every echo request it receives with an echo reply of its own, so
//!   a tunnel that only sends echo requests still leaves a stream of kernel echo replies
//!   on the wire. Because the tunnel itself never sends an echo reply, one rule that
//!   drops outgoing echo replies to the peer removes exactly that noise and nothing else;
//! - connection tracking marks the echo requests invalid (no matching outgoing request
//!   for an incoming one, and the reverse), and a host firewall that drops invalid
//!   packets or accepts only established replies (ufw, firewalld) drops them before the
//!   raw socket sees them.
//!
//! So each socket gets four rules, inserted at the top of their chains. A listener's are
//! scoped to its address; a dialer's to its address and the peer's, so every dial to one
//! peer shares them and a reconnect runs no `iptables`:
//!
//! ```text
//! raw    PREROUTING  incoming echo requests   CT --notrack
//! raw    OUTPUT      outgoing echo requests    CT --notrack
//! filter INPUT       incoming echo requests    ACCEPT
//! filter OUTPUT      outgoing echo replies     DROP  (the kernel's auto-answers)
//! ```
//!
//! Every rule carries the comment `wormhole-icmp pid=<pid>`. A process that was killed
//! cannot remove its rules, so the first socket of a process removes the rules of
//! processes that are gone. Without `iptables` (or without the right to run it) the
//! tunnel still starts, with a warning: the rules in `docs/transports.md` are then the
//! host's to add.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, Once, Weak};

use tracing::{debug, warn};

/// The marker every `icmp` rule carries, before ` pid=`.
const MARK: &str = "wormhole-icmp";
const IPTABLES: &str = "iptables";
const TABLES: [&str; 2] = ["raw", "filter"];

/// One rule: its table, chain and match/target arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rule {
    table: &'static str,
    chain: &'static str,
    spec: Vec<String>,
}

/// What a set of rules is for: the local address and, on the dialing side, the peer.
type Scope = (Ipv4Addr, Option<Ipv4Addr>);

/// The rules in place, by scope: every socket of one scope shares them, so a dialer that
/// reconnects runs no `iptables` at all.
static INSTALLED: Mutex<Vec<(Scope, Weak<Installed>)>> = Mutex::new(Vec::new());

/// A socket's hold on the rules of its scope; the last one dropped removes them.
pub(crate) struct Rules {
    _installed: Arc<Installed>,
}

struct Installed {
    scope: Scope,
    added: Vec<Rule>,
}

impl Rules {
    /// The rules of a listening socket on `local`: echo requests from anyone.
    pub(crate) fn listener(local: Ipv4Addr) -> Self {
        Self::install((local, None))
    }

    /// The rules of a dialing socket on `local` that talks only to `peer`.
    pub(crate) fn dialer(local: Ipv4Addr, peer: Ipv4Addr) -> Self {
        Self::install((local, Some(peer)))
    }

    fn install(scope: Scope) -> Self {
        static CLEANUP: Once = Once::new();
        CLEANUP.call_once(remove_stale);

        // Held while the rules are added, so two sockets of one scope never both add them.
        let mut installed = lock(&INSTALLED);
        installed.retain(|(_, weak)| weak.strong_count() > 0);
        if let Some(rules) = installed
            .iter()
            .find(|(s, _)| *s == scope)
            .and_then(|(_, weak)| weak.upgrade())
        {
            return Self { _installed: rules };
        }
        let rules = Arc::new(Installed {
            scope,
            added: add_rules(scope),
        });
        installed.push((scope, Arc::downgrade(&rules)));
        Self { _installed: rules }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn add_rules(scope: Scope) -> Vec<Rule> {
    let (local, peer) = scope;
    let comment = format!("{MARK} pid={}", std::process::id());
    let mut added = Vec::new();

    for rule in rules_for(local, peer, &comment) {
        match run(&rule_args("-I", &rule)) {
            Ok(()) => added.push(rule),
            Err(e) => {
                warn!(
                    error = %e,
                    table = rule.table,
                    chain = rule.chain,
                    "icmp could not add a firewall rule; add the rules in docs/transports.md \
                     yourself if the tunnel does not connect"
                );
                // Without iptables every rule fails alike: say it once.
                if e.kind() == std::io::ErrorKind::NotFound {
                    break;
                }
            }
        }
    }

    if !added.is_empty() {
        debug!(%local, ?peer, rules = added.len(), "icmp firewall rules added");
    }
    added
}

impl Drop for Installed {
    fn drop(&mut self) {
        // Under the lock: a socket of this scope that opens meanwhile adds the same rules
        // again, and `-D` removes one copy of each, so its copy stays.
        let mut installed = lock(&INSTALLED);
        for rule in self.added.iter().rev() {
            if let Err(e) = run(&rule_args("-D", rule)) {
                debug!(error = %e, chain = rule.chain, "could not remove an icmp firewall rule");
            }
        }
        installed.retain(|(scope, weak)| *scope != self.scope || weak.strong_count() > 0);
    }
}

/// The four rules of a socket on `local` (see the module documentation): a dialer also
/// names the `peer`. A listener on every address (`local` is `0.0.0.0`) gets rules that
/// match on any of them.
pub(crate) fn rules_for(local: Ipv4Addr, peer: Option<Ipv4Addr>, comment: &str) -> Vec<Rule> {
    // Incoming: from the peer (when known) to this socket. Outgoing: the reverse.
    let mut incoming = Vec::new();
    let mut outgoing = Vec::new();
    if let Some(peer) = peer {
        incoming.extend(["-s".into(), peer.to_string()]);
    }
    if !local.is_unspecified() {
        incoming.extend(["-d".into(), local.to_string()]);
        outgoing.extend(["-s".into(), local.to_string()]);
    }
    incoming.extend(["-p".into(), "icmp".into()]);
    if let Some(peer) = peer {
        outgoing.extend(["-d".into(), peer.to_string()]);
    }
    outgoing.extend(["-p".into(), "icmp".into()]);

    // Matches, then the comment, then the target: the order `iptables -S` prints.
    let with = |base: &[String], matches: &[&str], target: &[&str]| -> Vec<String> {
        let mut spec = base.to_vec();
        spec.extend(matches.iter().map(|s| (*s).to_string()));
        spec.extend([
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            comment.to_string(),
        ]);
        spec.extend(target.iter().map(|s| (*s).to_string()));
        spec
    };
    let request = ["--icmp-type", "echo-request"];
    let reply = ["--icmp-type", "echo-reply"];
    let notrack = ["-j", "CT", "--notrack"];
    vec![
        Rule {
            table: "raw",
            chain: "PREROUTING",
            spec: with(&incoming, &request, &notrack),
        },
        Rule {
            table: "raw",
            chain: "OUTPUT",
            spec: with(&outgoing, &request, &notrack),
        },
        Rule {
            table: "filter",
            chain: "INPUT",
            spec: with(&incoming, &request, &["-j", "ACCEPT"]),
        },
        // Only the kernel's own echo replies reach this: the tunnel never sends one.
        Rule {
            table: "filter",
            chain: "OUTPUT",
            spec: with(&outgoing, &reply, &["-j", "DROP"]),
        },
    ]
}

/// `iptables -w 5 -t <table> <action> <chain> [1] <spec...>`.
fn rule_args(action: &str, rule: &Rule) -> Vec<String> {
    let mut args = vec![
        "-w".into(),
        "5".into(),
        "-t".into(),
        rule.table.into(),
        action.into(),
        rule.chain.into(),
    ];
    if action == "-I" {
        args.push("1".into());
    }
    args.extend(rule.spec.iter().cloned());
    args
}

fn run(args: &[String]) -> std::io::Result<()> {
    let out = Command::new(IPTABLES)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&out.stderr);
    Err(std::io::Error::other(format!(
        "iptables {}: {}",
        args.join(" "),
        text.trim()
    )))
}

/// Removes the `icmp` rules of processes that are no longer running.
fn remove_stale() {
    for table in TABLES {
        let listing = match Command::new(IPTABLES)
            .args(["-w", "5", "-t", table, "-S"])
            .stdin(Stdio::null())
            .output()
        {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
            Ok(_) | Err(_) => continue,
        };
        for args in stale_deletions(&listing, table, |pid| {
            Path::new(&format!("/proc/{pid}")).exists()
        }) {
            if let Err(e) = run(&args) {
                debug!(error = %e, "could not remove a stale icmp firewall rule");
            }
        }
    }
}

/// The `iptables` arguments that delete each `icmp` rule in an `iptables -S` listing
/// whose process is gone (`alive` says whether a pid still runs).
pub(crate) fn stale_deletions(
    listing: &str,
    table: &str,
    alive: impl Fn(u32) -> bool,
) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for line in listing.lines() {
        let words = split_words(line);
        if words.first().map(String::as_str) != Some("-A") || words.len() < 2 {
            continue;
        }
        let Some(pid) = words.iter().find_map(|w| {
            w.strip_prefix(MARK)?
                .strip_prefix(" pid=")?
                .parse::<u32>()
                .ok()
        }) else {
            continue;
        };
        if pid == std::process::id() || alive(pid) {
            continue;
        }
        let mut args = vec![
            "-w".to_string(),
            "5".into(),
            "-t".into(),
            table.into(),
            "-D".into(),
        ];
        args.extend(words.into_iter().skip(1));
        out.push(args);
    }
    out
}

/// Splits an `iptables -S` line into words: spaces separate them, double quotes group
/// them (and `\"` is a quote inside a group).
fn split_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut any = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if quoted => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any || !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                    any = false;
                }
            }
            c => word.push(c),
        }
    }
    if any || !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(a: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, a)
    }

    fn joined(rule: &Rule) -> String {
        format!("{} {} {}", rule.table, rule.chain, rule.spec.join(" "))
    }

    #[test]
    fn a_listener_accepts_echo_requests_and_drops_the_kernels_replies() {
        let rules: Vec<String> = rules_for(addr(21), None, "wormhole-icmp pid=7")
            .iter()
            .map(joined)
            .collect();
        assert_eq!(
            rules,
            [
                "raw PREROUTING -d 192.0.2.21 -p icmp --icmp-type echo-request -m comment --comment wormhole-icmp pid=7 -j CT --notrack",
                "raw OUTPUT -s 192.0.2.21 -p icmp --icmp-type echo-request -m comment --comment wormhole-icmp pid=7 -j CT --notrack",
                "filter INPUT -d 192.0.2.21 -p icmp --icmp-type echo-request -m comment --comment wormhole-icmp pid=7 -j ACCEPT",
                "filter OUTPUT -s 192.0.2.21 -p icmp --icmp-type echo-reply -m comment --comment wormhole-icmp pid=7 -j DROP",
            ]
        );
    }

    #[test]
    fn a_listener_on_every_address_is_scoped_to_the_protocol_alone() {
        let rules: Vec<String> = rules_for(Ipv4Addr::UNSPECIFIED, None, "c")
            .iter()
            .map(joined)
            .collect();
        assert_eq!(
            rules[2],
            "filter INPUT -p icmp --icmp-type echo-request -m comment --comment c -j ACCEPT"
        );
        assert_eq!(
            rules[3],
            "filter OUTPUT -p icmp --icmp-type echo-reply -m comment --comment c -j DROP"
        );
    }

    #[test]
    fn a_dialer_is_scoped_to_its_peer() {
        let rules: Vec<String> = rules_for(addr(22), Some(addr(21)), "c")
            .iter()
            .map(joined)
            .collect();
        assert_eq!(
            rules[0],
            "raw PREROUTING -s 192.0.2.21 -d 192.0.2.22 -p icmp --icmp-type echo-request -m comment --comment c -j CT --notrack"
        );
        assert_eq!(
            rules[3],
            "filter OUTPUT -s 192.0.2.22 -d 192.0.2.21 -p icmp --icmp-type echo-reply -m comment --comment c -j DROP"
        );
    }

    #[test]
    fn insert_goes_to_the_top_and_delete_names_the_same_rule() {
        let rule = &rules_for(addr(21), None, "c")[2];
        let insert = rule_args("-I", rule);
        assert_eq!(
            &insert[..7],
            ["-w", "5", "-t", "filter", "-I", "INPUT", "1"]
        );
        let delete = rule_args("-D", rule);
        assert_eq!(&delete[4..6], ["-D", "INPUT"]);
        assert_eq!(delete[6..], insert[7..]);
    }

    #[test]
    fn only_rules_of_dead_processes_are_removed() {
        let listing = "-P INPUT ACCEPT\n\
            -A INPUT -d 192.0.2.21/32 -p icmp -m comment --comment \"wormhole-icmp pid=100\" -j ACCEPT\n\
            -A INPUT -d 192.0.2.21/32 -p icmp -m comment --comment \"wormhole-icmp pid=200\" -j ACCEPT\n\
            -A INPUT -p tcp --dport 22 -m comment --comment \"ssh\" -j ACCEPT\n";
        let gone = stale_deletions(listing, "filter", |pid| pid == 200);
        assert_eq!(gone.len(), 1);
        assert_eq!(
            gone[0].join(" "),
            "-w 5 -t filter -D INPUT -d 192.0.2.21/32 -p icmp -m comment --comment wormhole-icmp pid=100 -j ACCEPT"
        );
    }
}
