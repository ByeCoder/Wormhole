# Changelog

## 1.2.0 - 2026-11-14

New transports, each a sibling of an existing one, so the handshake, encryption, mux and KCP
layers above them are unchanged. Both servers need 1.2.0.

- **`icmp`** — the encrypted KCP of `paqet`, carried in the payload of ICMP echo (ping)
  packets over a raw socket, for the hardest routes where both UDP and TCP are blocked or
  throttled but ping still gets through. IPv4 and Linux only, needs root (or `CAP_NET_RAW`).
  The service opens the raw socket and adds scoped host firewall rules of its own (dropping
  only the kernel's own echo replies to the peer, so the traffic does not double), and removes
  them when it stops. The ICMP echo identifier stands in for a port, so several tunnels — and
  the host's own `ping` — stay apart. In the panel: pick *ICMP (ping)* as the transport in the
  tunnel wizard and editor. Sample configs: `configs/entry-icmp.toml`, `configs/exit-icmp.toml`.
  Guide: [Transports](docs/transports.md#icmp).
- **`dns`** — the encrypted KCP of `kcp`, wrapped in DNS query/response messages over UDP
  (port 53 on the listening side), for paths that pass only DNS. A direct server-to-server
  tunnel, so the sealed packet rides whole in a record's RDATA (not squeezed into the query
  name) and does not go through a recursive resolver. Works over IPv4 and IPv6; binding port
  53 needs root. The KCP MTU is capped so each DNS message stays within a common EDNS0 buffer,
  so throughput is lower — DNS is a last resort. In the panel: pick *DNS* as the transport.
  Sample configs: `configs/entry-dns.toml`, `configs/exit-dns.toml`. Guide:
  [Transports](docs/transports.md#dns).
- **`grpc`** — the tunnel carried as one bidirectional gRPC call over HTTP/2 (the `h2`
  crate, behind the default-on `grpc` cargo feature), to pass through CDNs and reverse
  proxies that speak gRPC. A stream transport like `tcp`/`ws`: the handshake, encryption and
  mux run on top, and the bytes travel in gRPC length-prefixed messages. This phase is
  cleartext HTTP/2 (h2c), so run it behind a TLS-terminating CDN or proxy; native TLS with
  ALPN `h2` is a planned follow-up. No root; IPv4 or IPv6. In the panel: pick *gRPC* as the
  transport. Sample configs: `configs/entry-grpc.toml`, `configs/exit-grpc.toml`. Guide:
  [Transports](docs/transports.md#grpc).
- **`xhttp`** — the tunnel streamed over one ordinary HTTP/1.1 request and response with
  chunked bodies (like XHTTP in Xray), for paths that pass only HTTP or that sit behind an
  HTTP CDN/proxy. A stream transport like `tcp`/`ws`, with no new dependency (the HTTP is
  written and parsed directly). Cleartext HTTP/1.1 in this phase, so run it behind a
  TLS-terminating front; native TLS is a planned follow-up. No root; IPv4 or IPv6. In the
  panel: pick *XHTTP* as the transport. Sample configs: `configs/entry-xhttp.toml`,
  `configs/exit-xhttp.toml`. Guide: [Transports](docs/transports.md#xhttp).

- **`shadowtls`** — a TLS tunnel disguised as a connection to a real HTTPS site
  (ShadowTLS v3 idea, behind the default-on `shadowtls` cargo feature). The listening side
  reads the TLS ClientHello: a real client proves itself with a token-keyed server name
  (SNI) and gets the tunnel; any other probe is relayed byte-for-byte to the genuine
  `[tunnel.shadowtls] handshake` site, so an active prober sees that site's real
  certificate and cannot tell the port from a reverse proxy in front of it. A stream
  transport like `tcp`/`ws`; needs no certificate of your own (unlike `wss`). No root; IPv4
  or IPv6. In the panel: pick *ShadowTLS* and fill in the handshake site. Sample configs:
  `configs/entry-shadowtls.toml`, `configs/exit-shadowtls.toml`. Guide:
  [Transports](docs/transports.md#shadowtls).

Private networks:

- **IPIP** and **Geneve** link kinds, beside GRE and VXLAN, in the panel's private networks.
  IPIP is the lightest (IPv4 in IPv4, 20 bytes per packet, no key or port); Geneve is VXLAN's
  IETF-standard cousin (UDP port 6081 by default, 50 bytes). Both work over IPv4 and IPv6, are
  offered in *Add server* and when making a network, and the agent reports whether the kernel
  can make each. Guide: [Private networks](docs/networks.md#ipip-and-geneve).
- **WireGuard** private networks, the first **encrypted** link kind. The panel generates a
  Curve25519 key pair for each end (as `wg genkey` does), stores them, and hands each server only
  its own private key and the peer's public key — nothing is typed by hand. UDP (port 51820 by
  default), 60 bytes per packet, over IPv4 or IPv6; needs the `wireguard` module and the `wg`
  tool. Offered in *Add server* alongside GRE/VXLAN/IPIP/Geneve. Guide:
  [Private networks](docs/networks.md#wireguard).

## 1.1.0 - 2026-11-13

- **Two new ways to carry a `ws` / `wss` tunnel** (`[tunnel.ws] mode`, both servers 1.1.0):
  - `httpupgrade`: the same HTTP upgrade a CDN sees, then the tunnel's bytes with no WebSocket
    framing or masking: less CPU and overhead, through the same CDNs.
  - `tls` (wss only): TLS with the tunnel right inside, no HTTP: the lightest HTTPS look-alike
    for direct routes.
  In the panel: *Carried as*, under the transport in the tunnel wizard and editor.
- **A new look, in space.** The panel floats in a living galaxy (one light canvas behind every
  screen); the map is a 3D neon planet where servers stand in their cities and every tunnel is
  an arc of light from one side of the world to the other, drawn as a beam when it comes up;
  each tunnel's page shows it as a wormhole between two worlds. Drag the planet to turn it.
- **Lighter:** the panel's script is 16 % smaller (UTF-8 instead of escaped text), cards no
  longer blur the moving background, and every scene pauses off screen.
- The author's GitHub account is now **ByeCoder** (`github.com/ByeCoder/Wormhole`): update
  links, the manager script and the panel's update check follow it.

## 1.0.0 - 2026-11-13

The first release of Wormhole: a fast, encrypted tunnel between two servers, and a web panel to
run it.

- **The tunnel core.** One small Rust program per side (about 8 MiB of memory, no garbage
  collector) that carries TCP and UDP traffic from the **entry** to the **exit**, in `reverse`
  (the exit dials the entry) or `direct` mode.
- **Eight transports:** `tcp`, `tcpmux`, `ws`, `wss` (also behind a CDN), `quic` (optionally
  sealed with `obfs`), `kcp`, `paqet` (KCP in synthetic TCP over a raw socket, firewall rules
  added by itself) and `spoof` (like `paqet`, with a forged source address for a Layer-3
  whitelist firewall). `auto` picks a working one, and with `[tunnel.mux] spread = true` keeps
  `tcpmux`, `kcp` and `ws` together and spreads users over them.
- **Profiles and tuning** for speed, games and lossy routes; UDP over any transport; real user
  addresses for Xray and others with the PROXY protocol; per-address and UDP flow limits.
- **The web panel:** servers and tunnels on a live map, a tunnel wizard, charts, logs, usage,
  a speed test and a benchmark that finds the transport that gets through best, GRE and VXLAN
  private networks, Telegram alerts, encrypted backups and signed updates for the panel and
  every agent.
- **The manager script** (`wormhole-manager`): install, update, uninstall, the panel and the
  agent, with signed release checks.
