# Changelog

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
