// The map: the servers stand on a small neon planet, where their cities are, and every tunnel
// is an arc of light that leaves the planet at one server and comes down at the other,
// over the curve of the world. A tunnel that comes up is drawn as a beam shooting across;
// traffic is the light running along it. The planet turns gently, and a drag turns it.
//
// Drawn on a 2D canvas with a small 3D camera of its own (no WebGL, no library): a few
// thousand dots for the surface, a cached sprite for the body and its air, and a few
// dozen points per arc. It pauses while it is off screen, and in low-power mode it is
// redrawn every few seconds without motion.
import { clamp, fitCanvas, rgba, uiFont } from "./draw";
import type { Palette } from "./draw";
import { isLand, placeOf } from "./geo";

export interface MapServer {
  id: string;
  name: string;
  /** Under the name: the role or place. */
  sub: string;
  st: "up" | "warn" | "down";
  /** Words that may say where it is: its name and host name. */
  place?: string;
}

export interface MapTunnel {
  id: string;
  a: string;
  b: string;
  st: "up" | "down" | "off";
  /** Mbit/s, both directions together. */
  rate: number;
  /** The tunnel's name, on the arc. */
  label: string;
  /** Next to the name: the rate while it flows, else its state. */
  value: string;
}

export interface MapData {
  servers: MapServer[];
  tunnels: MapTunnel[];
}

export interface MapHit {
  kind: "server" | "tunnel";
  id: string;
  x: number;
  y: number;
}

export interface MapOptions {
  data: () => MapData;
  palette: () => Palette;
  low: () => boolean;
  rtl: () => boolean;
  onHover: (hit: MapHit | null) => void;
  onOpen: (hit: MapHit) => void;
}

type V3 = [number, number, number];
interface Pt {
  x: number;
  y: number;
  z: number;
  /** Perspective scale at this point. */
  s: number;
  /** Hidden behind the planet. */
  back: boolean;
}

/** Camera distance, in planet radii: small enough to feel the depth. */
const F = 3.4;
const SEA_DOTS = 2200;
const ARC_STEPS = 56;
const CYAN = "#22f3ff";
const VIOLET = "#8b5cff";
const MAGENTA = "#ff3fd8";
const INK = "#f1efff";
const INK3 = "#a9a4d6";

const vec = (lat: number, lon: number): V3 => {
  const p = (lat * Math.PI) / 180;
  const l = (lon * Math.PI) / 180;
  return [Math.cos(p) * Math.sin(l), Math.sin(p), Math.cos(p) * Math.cos(l)];
};
const norm = (v: V3): V3 => {
  const n = Math.hypot(v[0], v[1], v[2]) || 1;
  return [v[0] / n, v[1] / n, v[2] / n];
};

/** The surface, worked out once: the land as a fine even grid of dots (so the continents
 *  read), the sea as a sparse one. */
let surface: { pos: Float32Array; land: Uint8Array; count: number } | null = null;
function surfaceDots() {
  if (surface) return surface;
  const pts: number[] = [];
  const land: number[] = [];
  const step = 1.5;
  for (let lat = -88; lat <= 88; lat += step) {
    const c = Math.cos((lat * Math.PI) / 180);
    // fewer dots toward the poles, so they are as far apart there as at the equator
    const lonStep = step / Math.max(0.08, c);
    for (let lon = -180; lon < 180; lon += lonStep) {
      if (!isLand(lat, lon)) continue;
      pts.push(...vec(lat, lon));
      land.push(1);
    }
  }
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < SEA_DOTS; i++) {
    const y = 1 - (2 * (i + 0.5)) / SEA_DOTS;
    const r = Math.sqrt(1 - y * y);
    const a = golden * i;
    const x = Math.sin(a) * r;
    const z = Math.cos(a) * r;
    if (isLand((Math.asin(y) * 180) / Math.PI, (Math.atan2(x, z) * 180) / Math.PI)) continue;
    pts.push(x, y, z);
    land.push(0);
  }
  surface = { pos: new Float32Array(pts), land: new Uint8Array(land), count: land.length };
  return surface;
}

/** The planet's body and air, cached per size. */
function paintBody(R: number): HTMLCanvasElement {
  const pad = R * 0.45;
  const size = Math.ceil((R + pad) * 2);
  const c = document.createElement("canvas");
  c.width = c.height = size;
  const g = c.getContext("2d")!;
  const o = size / 2;
  // the air: a thin glow just outside the rim
  const air = g.createRadialGradient(o, o, R * 0.92, o, o, R + pad);
  air.addColorStop(0, "rgba(34,243,255,0)");
  air.addColorStop(0.1, "rgba(34,243,255,0.42)");
  air.addColorStop(0.28, "rgba(139,92,255,0.22)");
  air.addColorStop(1, "rgba(139,92,255,0)");
  g.fillStyle = air;
  g.fillRect(0, 0, size, size);
  // the body, lit from the upper left
  const body = g.createRadialGradient(o - R * 0.35, o - R * 0.4, R * 0.1, o, o, R);
  body.addColorStop(0, "#2a1a6e");
  body.addColorStop(0.55, "#120a3a");
  body.addColorStop(1, "#05031a");
  g.fillStyle = body;
  g.beginPath();
  g.arc(o, o, R, 0, Math.PI * 2);
  g.fill();
  // a rim of light on the night side, the way thin air catches a sun behind it
  const rim = g.createRadialGradient(o, o, R * 0.82, o, o, R);
  rim.addColorStop(0, "rgba(255,63,216,0)");
  rim.addColorStop(1, "rgba(255,63,216,0.35)");
  g.fillStyle = rim;
  g.beginPath();
  g.arc(o, o, R, 0, Math.PI * 2);
  g.fill();
  return c;
}

function glowSprite(color: string): HTMLCanvasElement {
  const c = document.createElement("canvas");
  c.width = c.height = 32;
  const g = c.getContext("2d")!;
  const grd = g.createRadialGradient(16, 16, 0, 16, 16, 16);
  grd.addColorStop(0, "#ffffff");
  grd.addColorStop(0.3, rgba(color, 0.7));
  grd.addColorStop(1, rgba(color, 0));
  g.fillStyle = grd;
  g.fillRect(0, 0, 32, 32);
  return c;
}

interface Arc {
  key: string;
  pts: V3[];
}

interface Flow {
  k: number;
  dir: number;
  s: number;
}

export function startMap(canvas: HTMLCanvasElement, opts: MapOptions): () => void {
  let raf = 0;
  let stopped = false;
  let visible = true;
  let lastLow = 0;
  let last = 0;
  let mouse: { x: number; y: number } | null = null;
  let hover: MapHit | null = null;
  let drag: { x: number; y: number; moved: boolean } | null = null;
  let userYaw = 0;
  let userPitch = 0;
  let body: { R: number; c: HTMLCanvasElement } | null = null;
  const sprites = { cyan: glowSprite(CYAN), mint: glowSprite("#3dffb4"), red: glowSprite("#ff4d7d"), violet: glowSprite(VIOLET), amber: glowSprite("#ffb547") };
  const arcs = new Map<string, Arc>();
  const grow = new Map<string, number>();
  const was = new Map<string, MapTunnel["st"]>();
  const flows = new Map<string, Flow[]>();
  const places = new Map<string, V3>();
  // what was drawn last, for pointing at it
  let shownServers: { id: string; x: number; y: number; bx: number; by: number }[] = [];
  let shownArcs: { id: string; pts: Pt[] }[] = [];

  const placeFor = (s: MapServer): V3 => {
    const key = `${s.id}|${s.place ?? s.name}`;
    let v = places.get(key);
    if (!v) {
      const [lat, lon] = placeOf(s.id, `${s.name} ${s.place ?? ""}`);
      v = vec(lat, lon);
      places.set(key, v);
    }
    return v;
  };

  /** A great-circle path lifted off the ground, higher the farther it goes. */
  const arcFor = (a: V3, b: V3, rank: number): V3[] => {
    const dot = clamp(a[0] * b[0] + a[1] * b[1] + a[2] * b[2], -1, 1);
    let w = Math.acos(dot);
    let bb = b;
    if (w < 1e-3 || w > Math.PI - 1e-3) {
      // the same spot, or exactly the far side: nudge one end, so the path is defined
      bb = norm([b[0] + 0.05, b[1] + 0.04, b[2] + 0.03]);
      w = Math.acos(clamp(a[0] * bb[0] + a[1] * bb[1] + a[2] * bb[2], -1, 1));
    }
    const sw = Math.sin(w) || 1;
    // tunnels between the same two servers fly at different heights, so each one shows
    const lift = (0.16 + 0.5 * (w / Math.PI)) * (1 + rank * 0.55);
    const pts: V3[] = [];
    for (let i = 0; i <= ARC_STEPS; i++) {
      const t = i / ARC_STEPS;
      const k0 = Math.sin((1 - t) * w) / sw;
      const k1 = Math.sin(t * w) / sw;
      const p: V3 = [a[0] * k0 + bb[0] * k1, a[1] * k0 + bb[1] * k1, a[2] * k0 + bb[2] * k1];
      const h = 1 + lift * Math.sin(t * Math.PI);
      pts.push([p[0] * h, p[1] * h, p[2] * h]);
    }
    return pts;
  };

  const io = new IntersectionObserver((e) => {
    visible = e.some((x) => x.isIntersecting);
  });
  io.observe(canvas);

  const frame = (now: number) => {
    if (stopped) return;
    raf = requestAnimationFrame(frame);
    if (!visible) return;
    const calm = opts.low();
    if (calm && !drag && now - lastLow < 2500) return;
    lastLow = now;
    const time = now / 1000;
    const dt = Math.min(0.05, last ? time - last : 0.016);
    last = time;

    const { ctx, W, H } = fitCanvas(canvas);
    const P = opts.palette();
    const rtl = opts.rtl();
    const data = opts.data();
    const narrow = W < 640;

    // Aim the camera at the middle of the servers, from a little above.
    const pos = new Map<string, V3>();
    let m: V3 = [0, 0, 0];
    for (const s of data.servers) {
      const v = placeFor(s);
      pos.set(s.id, v);
      m = [m[0] + v[0], m[1] + v[1], m[2] + v[2]];
    }
    const mid = data.servers.length ? norm(m) : ([0.3, 0.55, 0.78] as V3);
    // Servers close together (one region) bring the camera nearer, so their arcs are not
    // a few pixels long; spread over the world, the whole planet shows.
    let spread = 0;
    for (const a of pos.values()) {
      for (const b of pos.values()) spread = Math.max(spread, Math.acos(clamp(a[0] * b[0] + a[1] * b[1] + a[2] * b[2], -1, 1)));
    }
    const zoom = pos.size > 1 ? clamp(1.5 / (spread + 0.35), 1, 2.1) : 1.15;
    const R = (narrow ? Math.min(W * 0.34, H * 0.34) : Math.min(W * 0.25, H * 0.34)) * zoom;
    const cx = W / 2;
    const cy = H * 0.5 + (pos.size ? R * 0.5 : 0);
    const Rd = (R * F) / Math.sqrt(F * F - 1);
    const midLat = Math.asin(clamp(mid[1], -1, 1));
    const midLon = Math.atan2(mid[0], mid[2]);
    const sway = calm ? 0 : Math.sin(time * 0.07) * 0.55;
    const yaw = -midLon + sway + userYaw;
    // looking from above and behind them, so the arcs are seen rising off the ground
    const tiltDown = pos.size ? -0.42 : 0.2;
    const pitch = clamp(midLat * 0.9 + tiltDown + userPitch, -0.6, 1.45);
    const cyaw = Math.cos(yaw);
    const syaw = Math.sin(yaw);
    const cp = Math.cos(pitch);
    const sp = Math.sin(pitch);
    const rot = (v: V3): V3 => {
      const x1 = v[0] * cyaw + v[2] * syaw;
      const z1 = -v[0] * syaw + v[2] * cyaw;
      return [x1, v[1] * cp - z1 * sp, v[1] * sp + z1 * cp];
    };
    /** Hidden by the planet: the line from the eye to the point passes through it first. */
    const hidden = (p: V3) => {
      const dx = p[0];
      const dy = p[1];
      const dz = p[2] - F;
      const a = dx * dx + dy * dy + dz * dz;
      const b = 2 * F * dz;
      const c = F * F - 1;
      const disc = b * b - 4 * a * c;
      if (disc <= 0) return false;
      const t = (-b - Math.sqrt(disc)) / (2 * a);
      return t > 0 && t < 0.999;
    };
    const project = (v: V3): Pt => {
      const p = rot(v);
      const s = F / (F - p[2]);
      return { x: cx + p[0] * R * s, y: cy - p[1] * R * s, z: p[2], s, back: hidden(p) };
    };

    ctx.clearRect(0, 0, W, H);
    ctx.lineCap = "round";
    ctx.lineJoin = "round";

    // ---- the ring, behind
    const ringPts = (r: number) => {
      const out: Pt[] = [];
      for (let i = 0; i <= 120; i++) {
        const a = (i / 120) * Math.PI * 2;
        out.push(project([Math.cos(a) * r, 0, Math.sin(a) * r]));
      }
      return out;
    };
    const rings = [1.32, 1.42, 1.52].map((r) => ringPts(r));
    const strokeRing = (front: boolean) => {
      rings.forEach((pts, j) => {
        ctx.strokeStyle = rgba(j === 1 ? MAGENTA : j ? CYAN : VIOLET, front ? 0.55 - j * 0.1 : 0.22);
        ctx.lineWidth = j === 1 ? 2.2 : 1.1;
        ctx.beginPath();
        let open = false;
        for (const p of pts) {
          const ok = front ? p.z >= 0 : p.z < 0;
          if (ok) {
            if (open) ctx.lineTo(p.x, p.y);
            else ctx.moveTo(p.x, p.y);
            open = true;
          } else open = false;
        }
        ctx.stroke();
      });
    };
    ctx.globalCompositeOperation = "lighter";
    strokeRing(false);

    // ---- arcs and their light, the parts behind the planet first
    const known = new Set<string>();
    const projected: { t: MapTunnel; pts: Pt[]; reach: number }[] = [];
    const pairs = new Map<string, number>();
    for (const t of data.tunnels) {
      const a = pos.get(t.a);
      const b = pos.get(t.b);
      if (!a || !b) continue;
      known.add(t.id);
      const pair = [t.a, t.b].sort().join("|");
      const rank = pairs.get(pair) ?? 0;
      pairs.set(pair, rank + 1);
      const key = `${a.join()}|${b.join()}|${rank}`;
      let arc = arcs.get(t.id);
      if (!arc || arc.key !== key) {
        arc = { key, pts: arcFor(a, b, rank) };
        arcs.set(t.id, arc);
      }
      // A tunnel that comes up shoots across from the entry; a broken one stops halfway.
      const before = was.get(t.id);
      if (t.st === "up" && before !== undefined && before !== "up") grow.set(t.id, 0);
      was.set(t.id, t.st);
      let g = grow.get(t.id) ?? 1;
      g = calm ? 1 : Math.min(1, g + dt / 1.6);
      grow.set(t.id, g);
      const reach = t.st === "up" ? g : t.st === "down" ? 0.5 : 0;
      projected.push({ t, pts: arc.pts.map(project), reach });
    }
    for (const id of [...arcs.keys()]) if (!known.has(id)) arcs.delete(id);

    const strokeArc = (pts: Pt[], from: number, to: number, back: boolean, style: string | CanvasGradient, width: number, dash?: number[]) => {
      const i0 = Math.floor(from * ARC_STEPS);
      const i1 = Math.ceil(to * ARC_STEPS);
      ctx.strokeStyle = style;
      ctx.lineWidth = width;
      ctx.setLineDash(dash ?? []);
      ctx.beginPath();
      let open = false;
      for (let i = i0; i <= i1 && i < pts.length; i++) {
        const p = pts[i];
        if (p.back === back) {
          if (open) ctx.lineTo(p.x, p.y);
          else {
            // start from the previous point, so front and back halves meet
            const q = pts[i - 1];
            if (q && i > i0) ctx.moveTo(q.x, q.y);
            else ctx.moveTo(p.x, p.y);
            if (q && i > i0) ctx.lineTo(p.x, p.y);
          }
          open = true;
        } else open = false;
      }
      ctx.stroke();
      ctx.setLineDash([]);
    };

    const drawArcs = (back: boolean) => {
      for (const { t, pts, reach } of projected) {
        const lit = hover?.kind === "tunnel" && hover.id === t.id;
        const dim = back ? 0.3 : 1;
        const a = pts[0];
        const b = pts[pts.length - 1];
        // the empty channel
        strokeArc(pts, 0, 1, back, rgba(t.st === "down" ? P.danger : VIOLET, (t.st === "off" ? 0.35 : 0.22) * dim), 1.2, t.st === "up" ? undefined : [4, 6]);
        if (reach <= 0) continue;
        const grad = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
        if (t.st === "up") {
          grad.addColorStop(0, rgba(CYAN, dim));
          grad.addColorStop(1, rgba(P.water, dim));
        } else {
          grad.addColorStop(0, rgba(P.warn, dim));
          grad.addColorStop(1, rgba(P.danger, dim));
        }
        strokeArc(pts, 0, reach, back, rgba(t.st === "up" ? CYAN : P.danger, 0.16 * dim), lit ? 12 : 8);
        strokeArc(pts, 0, reach, back, grad, lit ? 3.2 : 2.2);
      }
    };
    drawArcs(true);

    // ---- traffic: light running along the arcs (most of it comes back: downloads)
    const drawFlows = (back: boolean) => {
      for (const { t, pts, reach } of projected) {
        if (t.st !== "up" || calm) continue;
        let list = flows.get(t.id);
        const want = Math.round(clamp(5 + t.rate / 8, 5, 48));
        if (!list) flows.set(t.id, (list = []));
        if (!back) {
          while (list.length < want) list.push({ k: Math.random(), dir: Math.random() < 0.78 ? -1 : 1, s: 0.6 + Math.random() * 0.6 });
          list.length = want;
          const v = clamp(0.1 + t.rate / 3000, 0.1, 0.45);
          for (const f of list) f.k = (f.k + f.dir * v * dt * f.s + 1) % 1;
        }
        for (const f of list) {
          if (f.k > reach) continue;
          const i = f.k * ARC_STEPS;
          const i0 = Math.floor(i);
          const p0 = pts[i0];
          const p1 = pts[Math.min(ARC_STEPS, i0 + 1)];
          if (p0.back !== back) continue;
          const u = i - i0;
          const x = p0.x + (p1.x - p0.x) * u;
          const y = p0.y + (p1.y - p0.y) * u;
          const r = (f.dir < 0 ? 5 : 3.6) * p0.s * (back ? 0.7 : 1);
          ctx.globalAlpha = back ? 0.35 : f.dir < 0 ? 1 : 0.6;
          ctx.drawImage(f.dir < 0 ? sprites.mint : sprites.cyan, x - r, y - r, r * 2, r * 2);
        }
        ctx.globalAlpha = 1;
      }
    };
    drawFlows(true);

    // ---- the planet
    ctx.globalCompositeOperation = "source-over";
    if (!body || Math.abs(body.R - Rd) > 0.5) body = { R: Rd, c: paintBody(Rd) };
    ctx.drawImage(body.c, cx - body.c.width / 2, cy - body.c.height / 2);

    // its surface: land bright, sea a faint grid of dots
    const dots = surfaceDots();
    const paths = [new Path2D(), new Path2D(), new Path2D(), new Path2D(), new Path2D(), new Path2D()];
    const horizon = 1 / F;
    for (let i = 0; i < dots.count; i++) {
      const v: V3 = [dots.pos[i * 3], dots.pos[i * 3 + 1], dots.pos[i * 3 + 2]];
      const p = rot(v);
      if (p[2] <= horizon) continue;
      const s = F / (F - p[2]);
      const x = cx + p[0] * R * s;
      const y = cy - p[1] * R * s;
      const edge = clamp((p[2] - horizon) * 3.2, 0, 1);
      const band = edge > 0.66 ? 2 : edge > 0.33 ? 1 : 0;
      if (dots.land[i]) {
        const d = (1 + 0.9 * edge) * Math.min(1.5, zoom);
        paths[band].rect(x - d / 2, y - d / 2, d, d);
      } else {
        paths[3 + band].rect(x - 0.6, y - 0.6, 1.2, 1.2);
      }
    }
    ctx.globalCompositeOperation = "lighter";
    const landCol = ["rgba(34,243,255,0.35)", "rgba(61,255,210,0.7)", "rgba(150,255,235,0.95)"];
    const seaCol = ["rgba(139,92,255,0.10)", "rgba(139,92,255,0.16)", "rgba(160,130,255,0.22)"];
    for (let b = 0; b < 3; b++) {
      ctx.fillStyle = landCol[b];
      ctx.fill(paths[b]);
      ctx.fillStyle = seaCol[b];
      ctx.fill(paths[3 + b]);
    }
    // a few lines of latitude and longitude, on the near side only
    ctx.lineWidth = 0.8;
    ctx.strokeStyle = "rgba(139,92,255,0.22)";
    ctx.beginPath();
    const line = (f: (k: number) => V3) => {
      let open = false;
      for (let i = 0; i <= 72; i++) {
        const p = rot(f(i / 72));
        if (p[2] > horizon) {
          const s = F / (F - p[2]);
          const x = cx + p[0] * R * s;
          const y = cy - p[1] * R * s;
          if (open) ctx.lineTo(x, y);
          else ctx.moveTo(x, y);
          open = true;
        } else open = false;
      }
    };
    for (let j = 0; j < 8; j++) line((k) => vec(-85 + k * 170, j * 45));
    for (const lat of [-50, -25, 0, 25, 50]) line((k) => vec(lat, -180 + k * 360));
    ctx.stroke();
    // the day side's shine
    const shine = ctx.createRadialGradient(cx - Rd * 0.45, cy - Rd * 0.5, 0, cx - Rd * 0.45, cy - Rd * 0.5, Rd * 1.1);
    shine.addColorStop(0, "rgba(160,220,255,0.10)");
    shine.addColorStop(1, "rgba(160,220,255,0)");
    ctx.fillStyle = shine;
    ctx.beginPath();
    ctx.arc(cx, cy, Rd, 0, Math.PI * 2);
    ctx.fill();

    // ---- the near side: the ring, the arcs, the light, the moon
    strokeRing(true);
    drawArcs(false);
    drawFlows(false);
    const moonA = calm ? 1.1 : time * 0.16;
    const moon = project([Math.cos(moonA) * 2.35, Math.sin(moonA) * 0.55, Math.sin(moonA) * 2.35]);
    if (!moon.back) {
      const mr = R * 0.07 * moon.s;
      const mg = ctx.createRadialGradient(moon.x - mr * 0.4, moon.y - mr * 0.4, 0, moon.x, moon.y, mr);
      mg.addColorStop(0, "rgba(255,230,250,0.95)");
      mg.addColorStop(0.6, "rgba(190,150,255,0.6)");
      mg.addColorStop(1, "rgba(90,60,200,0.2)");
      ctx.globalCompositeOperation = "source-over";
      ctx.fillStyle = mg;
      ctx.beginPath();
      ctx.arc(moon.x, moon.y, mr, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalCompositeOperation = "lighter";
    }

    // ---- the flash where a beam lands
    for (const { t, pts, reach } of projected) {
      if (t.st !== "up" || reach >= 1 || reach < 0.02) continue;
      const i = Math.min(ARC_STEPS, Math.round(reach * ARC_STEPS));
      const p = pts[i];
      if (p.back) continue;
      const r = 16 * p.s;
      ctx.drawImage(sprites.cyan, p.x - r, p.y - r, r * 2, r * 2);
    }
    // ---- the break in a broken tunnel
    for (const { t, pts } of projected) {
      if (t.st !== "down") continue;
      const p = pts[Math.round(ARC_STEPS / 2)];
      if (p.back) continue;
      const k = calm ? 0.5 : (time * 0.8) % 1;
      ctx.strokeStyle = rgba(P.danger, 1 - k);
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 5 + k * 16, 0, Math.PI * 2);
      ctx.stroke();
      ctx.drawImage(sprites.red, p.x - 9, p.y - 9, 18, 18);
    }

    // ---- the servers: a beacon standing up from the ground
    shownServers = [];
    ctx.textAlign = "center";
    ctx.direction = rtl ? "rtl" : "ltr";
    const servers = data.servers
      .map((s) => ({ s, v: pos.get(s.id)! }))
      .map((x) => ({ ...x, base: project(x.v), top: project([x.v[0] * 1.13, x.v[1] * 1.13, x.v[2] * 1.13]), n: rot(x.v) }))
      .sort((a, b) => a.base.z - b.base.z);
    for (const { s, base, top, n } of servers) {
      if (n[2] <= horizon * 0.6) continue;
      const lit = hover?.kind === "server" && hover.id === s.id;
      const col = s.st === "up" ? P.water : s.st === "warn" ? P.warn : P.danger;
      const fade = clamp((n[2] - horizon * 0.6) * 4, 0.15, 1);
      ctx.globalAlpha = fade;
      // a ring on the ground, lying in its slope
      const ang = Math.atan2(base.y - cy, base.x - cx);
      for (let k = 0; k < 2; k++) {
        const ph = calm ? 0.5 : (time * 0.55 + k * 0.5) % 1;
        const rr = (6 + ph * 16) * base.s * (lit ? 1.3 : 1);
        ctx.strokeStyle = rgba(col, (1 - ph) * 0.9);
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.ellipse(base.x, base.y, Math.max(0.2, rr * Math.max(0.18, n[2])), rr, ang, 0, Math.PI * 2);
        ctx.stroke();
      }
      const beam = ctx.createLinearGradient(base.x, base.y, top.x, top.y);
      beam.addColorStop(0, rgba(col, 0.9));
      beam.addColorStop(1, rgba(col, 0));
      ctx.strokeStyle = beam;
      ctx.lineWidth = lit ? 4 : 3;
      ctx.beginPath();
      ctx.moveTo(base.x, base.y);
      ctx.lineTo(top.x, top.y);
      ctx.stroke();
      const gr = (lit ? 15 : 11) * base.s;
      ctx.drawImage(s.st === "up" ? sprites.mint : s.st === "warn" ? sprites.amber : sprites.red, base.x - gr, base.y - gr, gr * 2, gr * 2);
      ctx.globalAlpha = 1;
      shownServers.push({ id: s.id, x: base.x, y: base.y, bx: top.x, by: top.y });
    }
    // their names, on top of everything, and kept apart
    ctx.globalCompositeOperation = "source-over";
    const placed: { x: number; y: number; w: number }[] = [];
    for (const { s, top, n } of servers) {
      if (n[2] <= horizon) continue;
      ctx.font = uiFont(600, narrow ? 11 : 13);
      const w = ctx.measureText(s.name).width + 24;
      let y = top.y - 10;
      for (let tries = 0; tries < 6; tries++) {
        const clash = placed.find((p) => Math.abs(p.x - top.x) < (p.w + w) / 2 && Math.abs(p.y - y) < 24);
        if (!clash) break;
        y = clash.y - 26;
      }
      const x = clamp(top.x, w / 2 + 4, W - w / 2 - 4);
      const more = !narrow && hover?.kind === "server" && hover.id === s.id;
      placed.push({ x, y, w });
      ctx.fillStyle = "rgba(7,4,26,0.72)";
      ctx.strokeStyle = rgba(s.st === "up" ? P.water : s.st === "warn" ? P.warn : P.danger, 0.55);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.roundRect(x - w / 2, y - 15, w, more ? 34 : 21, 9);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = INK;
      ctx.fillText(s.name, x, y);
      if (more) {
        ctx.font = uiFont(400, 10.5);
        ctx.fillStyle = INK3;
        ctx.fillText(s.sub, x, y + 13);
      }
    }
    // the tunnels' names at the top of their arcs
    shownArcs = [];
    for (const { t, pts } of projected) {
      shownArcs.push({ id: t.id, pts });
      const p = pts[Math.round(ARC_STEPS / 2)];
      if (p.back) continue;
      ctx.direction = "ltr";
      ctx.font = uiFont(600, 11.5);
      const text = `${t.label} · ${t.value}`;
      const w = ctx.measureText(text).width + 22;
      let y = p.y - 16;
      for (let tries = 0; tries < 6; tries++) {
        const clash = placed.find((q) => Math.abs(q.x - p.x) < (q.w + w) / 2 && Math.abs(q.y - y) < 24);
        if (!clash) break;
        y = clash.y + 26;
      }
      placed.push({ x: p.x, y, w });
      const col = t.st === "up" ? P.water : t.st === "down" ? P.danger : INK3;
      ctx.fillStyle = "rgba(7,4,26,0.78)";
      ctx.strokeStyle = rgba(col, 0.6);
      ctx.beginPath();
      ctx.roundRect(p.x - w / 2, y - 12, w, 20, 10);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = col;
      ctx.beginPath();
      ctx.arc(p.x - w / 2 + 10, y - 2, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = INK;
      ctx.textAlign = "center";
      ctx.fillText(text, p.x + 5, y + 2);
    }
    ctx.direction = rtl ? "rtl" : "ltr";

    if (mouse && !drag?.moved) {
      const h = hit(mouse.x, mouse.y);
      if (h?.id !== hover?.id || h?.kind !== hover?.kind) {
        hover = h;
        canvas.style.cursor = h ? "pointer" : "grab";
      }
      opts.onHover(h);
    }
  };

  const hit = (x: number, y: number): MapHit | null => {
    for (const s of shownServers) {
      if (Math.hypot(s.x - x, s.y - y) < 16 || Math.hypot(s.bx - x, s.by - y) < 16) return { kind: "server", id: s.id, x, y };
    }
    let best: MapHit | null = null;
    let bd = 12;
    for (const a of shownArcs) {
      for (const p of a.pts) {
        if (p.back) continue;
        const d = Math.hypot(p.x - x, p.y - y);
        if (d < bd) {
          bd = d;
          best = { kind: "tunnel", id: a.id, x, y };
        }
      }
    }
    return best;
  };

  const local = (e: PointerEvent) => {
    const r = canvas.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  };
  const onDown = (e: PointerEvent) => {
    const p = local(e);
    drag = { x: p.x, y: p.y, moved: false };
    canvas.setPointerCapture?.(e.pointerId);
  };
  const onMove = (e: PointerEvent) => {
    const p = local(e);
    mouse = p;
    if (drag) {
      const dx = p.x - drag.x;
      const dy = p.y - drag.y;
      if (!drag.moved && Math.hypot(dx, dy) > 4) {
        drag.moved = true;
        canvas.style.cursor = "grabbing";
        if (hover) opts.onHover(null);
        hover = null;
      }
      if (drag.moved) {
        userYaw += dx * 0.008;
        userPitch = clamp(userPitch + dy * 0.006, -1.2, 1.2);
        drag.x = p.x;
        drag.y = p.y;
      }
    }
  };
  const onUp = () => {
    const moved = drag?.moved;
    drag = null;
    canvas.style.cursor = hover ? "pointer" : "grab";
    if (!moved && hover) opts.onOpen(hover);
  };
  const onLeave = () => {
    mouse = null;
    if (hover) opts.onHover(null);
    hover = null;
  };
  canvas.style.cursor = "grab";
  canvas.style.touchAction = "pan-y";
  canvas.addEventListener("pointerdown", onDown);
  canvas.addEventListener("pointermove", onMove);
  canvas.addEventListener("pointerup", onUp);
  canvas.addEventListener("pointercancel", onUp);
  canvas.addEventListener("pointerleave", onLeave);
  raf = requestAnimationFrame(frame);

  return () => {
    stopped = true;
    cancelAnimationFrame(raf);
    io.disconnect();
    canvas.removeEventListener("pointerdown", onDown);
    canvas.removeEventListener("pointermove", onMove);
    canvas.removeEventListener("pointerup", onUp);
    canvas.removeEventListener("pointercancel", onUp);
    canvas.removeEventListener("pointerleave", onLeave);
  };
}
