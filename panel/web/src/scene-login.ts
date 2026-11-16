// The login scene: planets in space, tied together by tunnels. A small system of worlds
// turns slowly in 3D around a ringed hub; light runs along the links between them like
// traffic. A wrong password sends a shudder and a red flash through the links; a right one
// flies the camera into the hub and on to the dashboard.
//
// Built to stay light: every planet is painted once into a small sprite (again only on a
// theme change), so a frame is a dozen image copies, a few lines and dots. It draws at most
// 24 times a second at no more than 1.5× pixel density, does not follow the pointer, and in
// low-power mode (or for reduced motion) it is drawn twice a second without motion.
// Space itself (stars, the galaxy) is the panel's background (scene-cosmos) showing through.
import { clamp, easeInOut, rng } from "./draw";
import type { Palette } from "./draw";

export interface LoginSceneOptions {
  palette: () => Palette;
  low: () => boolean;
  rtl: () => boolean;
}

export interface LoginScene {
  /** Starts the dive; `done` runs when it ends. */
  descend: (done: () => void) => void;
  ripple: () => void;
  stop: () => void;
}

type RGB = [number, number, number];

interface Planet {
  /** Position on the unit scale, before the turn. */
  x: number;
  y: number;
  z: number;
  /** Radius in the same units. */
  r: number;
  color: number;
  ring: boolean;
}

interface Link {
  a: number;
  b: number;
  /** Where along the link the packet is (0…1), and how fast it goes. */
  at: number;
  speed: number;
}

/** Light, base and shadow of each planet's colour. */
const COLORS: [RGB, RGB, RGB][] = [
  [[189, 252, 255], [34, 200, 235], [6, 40, 70]], // cyan ice
  [[226, 210, 255], [139, 92, 255], [30, 14, 70]], // violet
  [[255, 205, 240], [236, 72, 190], [60, 10, 50]], // magenta
  [[255, 236, 200], [240, 170, 80], [70, 34, 10]], // amber
  [[200, 255, 225], [40, 200, 150], [8, 50, 40]], // teal
  [[230, 236, 255], [120, 140, 220], [20, 24, 60]], // slate blue
];

const FPS = 24;
const CAMERA = 3.6; // distance of the eye from the centre, in planet-space units

const rgb = (c: RGB, a = 1) => `rgba(${c[0] | 0},${c[1] | 0},${c[2] | 0},${a})`;

/** A lit sphere with a thin atmosphere, painted once: `size` px across, the planet in the
 *  middle 70% so the glow has room. */
function paintPlanet(size: number, [light, base, shade]: [RGB, RGB, RGB], ring: boolean, night: boolean, seed: number): HTMLCanvasElement {
  const c = document.createElement("canvas");
  c.width = c.height = size;
  const g = c.getContext("2d")!;
  const R = size * 0.35;
  const m = size / 2;
  // atmosphere
  const glow = g.createRadialGradient(m, m, R * 0.9, m, m, R * 1.42);
  glow.addColorStop(0, rgb(base, night ? 0.45 : 0.25));
  glow.addColorStop(1, rgb(base, 0));
  g.fillStyle = glow;
  g.fillRect(0, 0, size, size);
  if (ring) drawRing(g, m, R, base, light, "back");
  // body, lit from the upper left
  const body = g.createRadialGradient(m - R * 0.4, m - R * 0.45, R * 0.08, m, m, R);
  body.addColorStop(0, rgb(light));
  body.addColorStop(0.45, rgb(base));
  body.addColorStop(1, rgb(shade));
  g.fillStyle = body;
  g.beginPath();
  g.arc(m, m, R, 0, Math.PI * 2);
  g.fill();
  // a few soft bands, so the planets are not all billiard balls
  const r = rng(seed);
  g.save();
  g.beginPath();
  g.arc(m, m, R, 0, Math.PI * 2);
  g.clip();
  g.globalAlpha = 0.18;
  for (let i = 0; i < 4; i++) {
    g.fillStyle = r() < 0.5 ? rgb(light) : rgb(shade);
    const y = m - R + r() * R * 2;
    g.fillRect(m - R, y, R * 2, R * (0.06 + r() * 0.14));
  }
  g.restore();
  // night side
  const dark = g.createLinearGradient(m - R, m - R, m + R, m + R);
  dark.addColorStop(0.45, "rgba(0,0,0,0)");
  dark.addColorStop(1, `rgba(0,0,8,${night ? 0.55 : 0.3})`);
  g.fillStyle = dark;
  g.beginPath();
  g.arc(m, m, R, 0, Math.PI * 2);
  g.fill();
  if (ring) drawRing(g, m, R, base, light, "front");
  return c;
}

/** A tilted ring around the planet: the half behind it, or the half in front. */
function drawRing(g: CanvasRenderingContext2D, m: number, R: number, base: RGB, light: RGB, half: "back" | "front") {
  g.save();
  g.translate(m, m);
  g.rotate(-0.38);
  g.scale(1, 0.26);
  g.lineWidth = R * 0.5;
  const grad = g.createLinearGradient(-R * 1.7, 0, R * 1.7, 0);
  grad.addColorStop(0, rgb(base, 0.15));
  grad.addColorStop(0.5, rgb(light, 0.75));
  grad.addColorStop(1, rgb(base, 0.15));
  g.strokeStyle = grad;
  g.beginPath();
  if (half === "back") g.arc(0, 0, R * 1.45, Math.PI, Math.PI * 2);
  else g.arc(0, 0, R * 1.45, 0, Math.PI);
  g.stroke();
  g.restore();
}

/** The system: a hub in the middle and worlds around it on a loose shell, each tied to the
 *  hub and to its nearest neighbours. Fixed (seeded), so it looks the same every visit. */
function buildSystem(): { planets: Planet[]; links: Link[] } {
  const r = rng(29);
  const planets: Planet[] = [{ x: 0, y: 0, z: 0, r: 0.2, color: 0, ring: true }];
  const n = 9;
  for (let i = 0; i < n; i++) {
    // spread over the sphere (a golden-angle spiral), at a varying distance
    const t = (i + 0.5) / n;
    const lat = Math.acos(1 - 2 * t) - Math.PI / 2;
    const lon = i * 2.39996 + r() * 0.4;
    const d = 0.95 + r() * 0.45;
    planets.push({
      x: Math.cos(lat) * Math.cos(lon) * d * 1.25,
      y: Math.sin(lat) * d * 0.75,
      z: Math.cos(lat) * Math.sin(lon) * d,
      r: 0.06 + r() * 0.07,
      color: 1 + (i % (COLORS.length - 1)),
      ring: i === 2 || i === 6,
    });
  }
  const links: Link[] = [];
  const seen = new Set<string>();
  const add = (a: number, b: number) => {
    const k = a < b ? `${a}-${b}` : `${b}-${a}`;
    if (a === b || seen.has(k)) return;
    seen.add(k);
    links.push({ a, b, at: r(), speed: 0.12 + r() * 0.18 });
  };
  for (let i = 1; i <= n; i++) {
    if (i % 2 === 1 || i === 2) add(0, i);
    const near = planets
      .map((p, j) => ({ j, d: (p.x - planets[i].x) ** 2 + (p.y - planets[i].y) ** 2 + (p.z - planets[i].z) ** 2 }))
      .filter(({ j }) => j !== 0 && j !== i)
      .sort((a, b) => a.d - b.d);
    add(i, near[0].j);
    if (i % 3 === 0) add(i, near[1].j);
  }
  return { planets, links };
}

export function startLoginScene(canvas: HTMLCanvasElement, opts: LoginSceneOptions): LoginScene {
  let raf = 0;
  let stopped = false;
  let diveStart = -1;
  let onDone: (() => void) | null = null;
  let shockAt = -1;
  let lastDraw = 0;
  let angle = 0.6;
  let lastT = 0;
  const { planets, links } = buildSystem();
  let sprites: HTMLCanvasElement[] = [];
  let spritesFor = "";
  const order = planets.map((_, i) => i);
  const screen = planets.map(() => ({ x: 0, y: 0, s: 0, z: 0 }));

  const frame = (now: number) => {
    if (stopped) return;
    raf = requestAnimationFrame(frame);
    const still = opts.low();
    const busy = diveStart >= 0 || shockAt >= 0;
    if (now - lastDraw < (still && !busy ? 2000 : 1000 / FPS)) return;
    lastDraw = now;

    const P = opts.palette();
    const night = P.night;
    const dpr = Math.min(devicePixelRatio || 1, 1.5);
    const W = innerWidth;
    const H = innerHeight;
    const cw = Math.round(W * dpr);
    const ch = Math.round(H * dpr);
    if (canvas.width !== cw || canvas.height !== ch) {
      canvas.width = cw;
      canvas.height = ch;
    }
    const ctx = canvas.getContext("2d")!;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    const key = `${night}`;
    if (key !== spritesFor) {
      spritesFor = key;
      sprites = planets.map((p, i) => paintPlanet(p.ring ? 160 : 112, COLORS[p.color], p.ring, night, 40 + i));
    }

    const t = now / 1000;
    const dt = Math.min(0.1, lastT ? t - lastT : 0);
    lastT = t;

    // The dive: the camera closes in on the hub and the system spins up, then a white-out.
    let p = 0;
    if (diveStart >= 0) p = clamp((now - diveStart) / (still ? 300 : 1400), 0, 1);
    const e = easeInOut(p);
    let shock = -1;
    if (shockAt >= 0) {
      shock = (now - shockAt) / 900;
      if (shock > 1) {
        shockAt = -1;
        shock = -1;
      }
    }
    const shake = shock >= 0 ? Math.sin(shock * Math.PI) : 0;
    if (!still) angle += dt * (0.07 + e * 2.4);

    // Project: turn round the vertical axis, lean the whole system toward the viewer.
    // The system fills the screen's long side, so the worlds sit around the form, not
    // behind it: wide on a desktop, tall on a phone.
    const S = Math.min(W, H) * 0.34;
    const SX = S * clamp((W / H) * 0.95, 1, 1.7);
    const SY = S * clamp((H / W) * 0.8, 1, 2);
    const cx = W / 2;
    const cy = H / 2;
    const cam = CAMERA - e * 3.2;
    const ca = Math.cos(angle);
    const sa = Math.sin(angle);
    const tilt = 0.32;
    const ct = Math.cos(tilt);
    const st = Math.sin(tilt);
    planets.forEach((pl, i) => {
      const x1 = pl.x * ca - pl.z * sa;
      const z1 = pl.x * sa + pl.z * ca;
      const y2 = pl.y * ct - z1 * st;
      const z2 = pl.y * st + z1 * ct;
      const depth = Math.max(0.15, cam + z2);
      const k = CAMERA / depth;
      const jitter = shake ? Math.sin(t * 60 + i * 1.7) * 3 * shake : 0;
      screen[i] = { x: cx + x1 * SX * k + jitter, y: cy + y2 * SY * k, s: k, z: z2 };
    });

    // Links, far ones fainter; light runs along each one.
    const red: RGB = [255, 77, 109];
    ctx.lineCap = "round";
    for (const l of links) {
      const a = screen[l.a];
      const b = screen[l.b];
      const near = clamp(1 - ((a.z + b.z) / 2 + 1.2) / 2.6, 0.15, 1);
      const col: RGB = shake > 0 ? red : night ? [120, 220, 255] : [90, 34, 230];
      ctx.strokeStyle = rgb(col, (night ? 0.32 : 0.22) * near * (1 - e) + shake * 0.35);
      ctx.lineWidth = 0.7 + near * 0.9;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
      if (!still) l.at = (l.at + dt * l.speed * (1 + e * 6)) % 1;
      const px = a.x + (b.x - a.x) * l.at;
      const py = a.y + (b.y - a.y) * l.at;
      const pr = 1.2 + near * 1.6;
      ctx.fillStyle = rgb(shake > 0 ? red : night ? [210, 250, 255] : [120, 60, 240], 0.9 * near * (1 - e));
      ctx.fillRect(px - pr, py - pr, pr * 2, pr * 2);
      ctx.fillStyle = rgb(shake > 0 ? red : night ? [34, 243, 255] : [90, 34, 230], 0.18 * near * (1 - e));
      ctx.fillRect(px - pr * 3, py - pr * 3, pr * 6, pr * 6);
    }

    // Planets, back to front.
    order.sort((i, j) => screen[j].z - screen[i].z);
    for (const i of order) {
      const pl = planets[i];
      const sp = screen[i];
      const img = sprites[i];
      // the sprite holds the planet in its middle 70%, with the ring a little wider
      const size = (pl.r * S * sp.s * 2) / 0.7;
      if (size < 1 || sp.s > 40) continue;
      const fade = clamp(1 - (sp.z + 1.4) / 3.4, 0.35, 1);
      ctx.globalAlpha = fade * (night ? 1 : 0.85);
      ctx.drawImage(img, sp.x - size / 2, sp.y - size / 2, size, size);
    }
    ctx.globalAlpha = 1;

    // The end of the dive: a white-out, then the dashboard.
    if (p > 0.55) {
      const k = smoothstep((p - 0.55) / 0.45);
      ctx.fillStyle = night ? `rgba(235,250,255,${k})` : `rgba(255,255,255,${k})`;
      ctx.fillRect(0, 0, W, H);
    }
    if (p >= 1 && onDone) {
      const done = onDone;
      onDone = null;
      done();
    }
  };
  const onVisible = () => {
    lastDraw = 0;
    lastT = 0;
  };
  document.addEventListener("visibilitychange", onVisible);
  raf = requestAnimationFrame(frame);

  return {
    descend(done) {
      if (diveStart >= 0) return;
      diveStart = performance.now();
      onDone = done;
    },
    ripple() {
      shockAt = performance.now();
    },
    stop() {
      stopped = true;
      cancelAnimationFrame(raf);
      document.removeEventListener("visibilitychange", onVisible);
    },
  };
}

function smoothstep(x: number) {
  const k = clamp(x, 0, 1);
  return k * k * (3 - 2 * k);
}
