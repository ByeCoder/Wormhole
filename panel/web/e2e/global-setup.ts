import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { exe, freePort, waitForPort, writeStack } from "./stack";

// A real panel in a folder of its own: its settings, its database, tunnels run as child
// processes (no systemd needed), and the `wormhole` program that goes with `wormhole-panel`.
export default async function globalSetup() {
  const bin = path.resolve(process.env.WORMHOLE_PANEL_BIN ?? `../../target/debug/wormhole-panel${exe}`);
  if (!fs.existsSync(bin)) throw new Error(`build wormhole-panel first (cargo build -p wormhole -p wormhole-panel): ${bin}`);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wormhole-e2e-"));
  const cfg = path.join(root, "panel.toml");
  const port = await freePort();
  execFileSync(bin, ["init", "-c", cfg, "--data-dir", path.join(root, "data"), "--port", String(port)]);
  const wormhole = path.join(root, "wormhole");
  fs.mkdirSync(wormhole);
  const text = fs
    .readFileSync(cfg, "utf8")
    .replace(/^wormhole_dir = .*$/m, `wormhole_dir = ${JSON.stringify(wormhole)}`)
    .replace(/^services = .*$/m, 'services = "process"');
  fs.writeFileSync(cfg, text);
  const secret = /^path = "(.*)"$/m.exec(text)?.[1];
  if (!secret) throw new Error("no secret path in the settings");
  const log = fs.openSync(path.join(root, "panel.log"), "a");
  const child = spawn(bin, ["serve", "-c", cfg], { stdio: ["ignore", log, log] });
  await waitForPort(port);
  writeStack({ base: `https://127.0.0.1:${port}/${secret}/`, cfg, bin, root, pids: [child.pid ?? 0] });
}
