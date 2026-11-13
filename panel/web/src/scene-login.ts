// The login scene: a wormhole seen from inside. Neon rings fall toward the viewer along a
// gently curving throat, and streaks of light rush past. A wrong password sends a shock
// through the rings; a right one goes to warp and dives into the dashboard.
import { clamp, easeInOut, fitCanvas, lerp, rng } from "./draw";
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

interface Streak {
  a: number;
  r: number;
  z: number;
  s: number;
  hue: number;
}

interface Dust {
  x: number;
  y: number;
  z: number;
  ph: number;
}

const RINGS = 30;
const NEAR = 0.06;

/** cyan → violet → magenta, by k in [0,1]. */
function neon(k: number, night: boolean): [number, number, number] {
  const stops: [number, number, number][] = night
    ? [
        [34, 243, 255],
        [139, 92, 255],
        [255, 63, 216],
        [34, 243, 255],
      ]
    : [
        [0, 170, 220],
        [90, 34, 230],
        [200, 20, 160],
        [0, 170, 220],
      ];
  const x = ((k % 1) + 1) % 1 * 3;
  const i = Math.floor(x);
  const f = x - i;
  const a = stops[i];
  const b = stops[i + 1];
  return [lerp(a[0], b[0], f), lerp(a[1], b[1], f), lerp(a[2], b[2], f)];
}

const rgb = (c: [number, number, number], a: number) => `rgba(${c[0] | 0},${c[1] | 0},${c[2] | 0},${a})`;

export function startLoginScene(canvas: HTMLCanvasElement, opts: LoginSceneOptions): LoginScene {
  let raf = 0;
  let stopped = false;
  let diveStart = -1;
  let onDone: (() => void) | null = null;
  let shockAt = -1;
  let mx = 0.5;
  let my = 0.5;
  let sx = 0.5;
  let sy = 0.5;
  let travel = 0;
  let last = 0;
  let lastLow = 0;
  const r = rng(13);
  const streaks: Streak[] = Array.from({ length: 220 }, () => ({ a: r() * 6.283, r: 0.75 + r() * 0.5, z: r(), s: 0.6 + r() * 0.8, hue: r() }));
  let dust: Dust[] = [];
  let seededFor = "";

  const onMove = (e: PointerEvent) => {
    mx = e.clientX / innerWidth;
    my = e.clientY / innerHeight;
  };
  addEventListener("pointermove", onMove, { passive: true });

  const frame = (now: number) => {
    if (stopped) return;
    raf = requestAnimationFrame(frame);
    const still = opts.low();
    // In low-power mode the scene is drawn twice a second, without motion.
    if (still && diveStart < 0 && shockAt < 0 && now - lastLow < 500) return;
    lastLow = now;
    const P = opts.palette();
    const night = P.night;
    const { ctx, W, H } = fitCanvas(canvas);
    if (seededFor !== `${W}x${H}`) {
      const d = rng(5);
      dust = Array.from({ length: Math.round((W * H) / 6000) }, () => ({ x: d(), y: d(), z: 0.2 + d() * 0.8, ph: d() * 6.28 }));
      seededFor = `${W}x${H}`;
    }
    const time = now / 1000;
    const dt = Math.min(0.05, last ? time - last : 0.016);
    last = time;

    // The dive: speed climbs, the throat opens, then a flash.
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
    const speed = still ? 0 : 0.11 + e * 2.6 + (shock >= 0 ? Math.sin(shock * Math.PI) * -0.08 : 0);
    travel += speed * dt;

    sx += (mx - sx) * 0.05;
    sy += (my - sy) * 0.05;
    const S = Math.min(W, H);
    const cx = W / 2 + (sx - 0.5) * -60;
    const cy = H * 0.5 + (sy - 0.5) * -40;
    // the throat curves: its far end sways a little
    const bend = (z: number) => ({
      x: cx + Math.sin(time * 0.35 + z * 2.2) * z * S * 0.14 + (sx - 0.5) * z * S * 0.3,
      y: cy + Math.cos(time * 0.28 + z * 1.7) * z * S * 0.08 + (sy - 0.5) * z * S * 0.22,
    });
    const R = S * 0.11 * (1 + e * 0.9);

    // Space itself is the panel's background (scene-cosmos) showing through; this canvas
    // adds the dust that rushes by and the throat.
    ctx.globalCompositeOperation = "source-over";
    ctx.clearRect(0, 0, W, H);
    for (const s of dust) {
      const a = (night ? 0.75 : 0.35) * s.z * (still ? 0.8 : 0.55 + 0.45 * Math.sin(time * 1.4 + s.ph));
      ctx.fillStyle = night ? `rgba(220,235,255,${a})` : `rgba(90,34,230,${a * 0.6})`;
      const px = s.x * W + (sx - 0.5) * -20 * s.z;
      const py = s.y * H + (sy - 0.5) * -20 * s.z;
      ctx.fillRect(px, py, s.z * 1.7, s.z * 1.7);
    }

    if (night) ctx.globalCompositeOperation = "lighter";

    // The core: the far end of the throat.
    const far = bend(1);
    const coreR = S * (0.16 + e * 0.6);
    const core = ctx.createRadialGradient(far.x, far.y, 0, far.x, far.y, coreR);
    core.addColorStop(0, night ? "rgba(255,255,255,0.95)" : "rgba(255,255,255,1)");
    core.addColorStop(0.18, night ? "rgba(160,250,255,0.55)" : "rgba(120,80,255,0.35)");
    core.addColorStop(0.5, night ? "rgba(139,92,255,0.18)" : "rgba(255,63,216,0.12)");
    core.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = core;
    ctx.beginPath();
    ctx.arc(far.x, far.y, coreR, 0, 6.283);
    ctx.fill();

    // The rings: far to near.
    const step = 1 / RINGS;
    const off = (travel * 3) % step;
    for (let i = RINGS; i >= 0; i--) {
      let z = i * step - off + step;
      if (z <= NEAR) continue;
      if (z > 1) z = 1;
      const c = bend(z);
      const rad = R / z;
      if (rad > Math.hypot(W, H) * 1.2) continue;
      const fade = clamp((1 - z) * 1.4, 0, 1) * clamp((z - NEAR) * 6, 0, 1);
      const idx = Math.floor((travel * 3) / step) - i;
      let col = neon(idx * 0.06 + time * 0.05, night);
      let a = fade * (night ? 0.75 : 0.55);
      // the shock: a pink pulse runs out along the rings
      if (shock >= 0) {
        const front = shock * 1.1;
        const d = Math.abs(1 - z - front);
        const k = clamp(1 - d * 6, 0, 1) * (1 - shock);
        if (k > 0) {
          col = [lerp(col[0], 255, k), lerp(col[1], 60, k), lerp(col[2], 110, k)];
          a = Math.min(1, a + k * 0.8);
        }
      }
      const tilt = 0.82 + 0.1 * Math.sin(time * 0.5);
      ctx.lineWidth = clamp(2.2 / z, 1, 7) * (night ? 1 : 0.8);
      ctx.strokeStyle = rgb(col, a * 0.22);
      ctx.beginPath();
      ctx.ellipse(c.x, c.y, rad, rad * tilt, Math.sin(time * 0.2) * 0.15, 0, 6.283);
      ctx.stroke();
      ctx.lineWidth = clamp(0.9 / z, 0.6, 2.6);
      ctx.strokeStyle = rgb(col, a);
      ctx.stroke();
      // beads of light running round each ring
      if (!still) {
        const n = 6;
        for (let j = 0; j < n; j++) {
          const ang = (j / n) * 6.283 + time * (0.4 + (i % 3) * 0.12) * (i % 2 ? 1 : -1);
          const bx = c.x + Math.cos(ang) * rad;
          const by = c.y + Math.sin(ang) * rad * tilt;
          const br = clamp(1.6 / z, 0.8, 5);
          ctx.fillStyle = rgb(col, a);
          ctx.beginPath();
          ctx.arc(bx, by, br, 0, 6.283);
          ctx.fill();
        }
      }
    }

    // Streaks of light rushing past along the walls.
    if (!still || p > 0) {
      ctx.lineCap = "round";
      for (const s of streaks) {
        s.z -= speed * dt * s.s * 1.6;
        if (s.z <= NEAR) {
          s.z = 1;
          s.a = Math.random() * 6.283;
        }
        const z0 = s.z;
        const z1 = Math.min(1, s.z + (0.012 + speed * 0.1 * s.s) * s.z);
        const c0 = bend(z0);
        const c1 = bend(z1);
        const x0 = c0.x + Math.cos(s.a) * s.r * (R / z0);
        const y0 = c0.y + Math.sin(s.a) * s.r * (R / z0) * 0.85;
        const x1 = c1.x + Math.cos(s.a) * s.r * (R / z1);
        const y1 = c1.y + Math.sin(s.a) * s.r * (R / z1) * 0.85;
        const a = clamp((1 - z0) * 1.6, 0, 1) * (night ? 0.9 : 0.6);
        ctx.strokeStyle = rgb(neon(s.hue, night), a);
        ctx.lineWidth = clamp(1 / z0, 0.5, 2.6);
        ctx.beginPath();
        ctx.moveTo(x0, y0);
        ctx.lineTo(x1, y1);
        ctx.stroke();
      }
    }
    ctx.globalCompositeOperation = "source-over";

    // A soft vignette keeps the edges deep.
    const vig = ctx.createRadialGradient(W / 2, H / 2, S * 0.35, W / 2, H / 2, Math.hypot(W, H) * 0.62);
    vig.addColorStop(0, "rgba(0,0,0,0)");
    vig.addColorStop(1, night ? "rgba(2,1,8,0.55)" : "rgba(120,100,200,0.14)");
    ctx.fillStyle = vig;
    ctx.fillRect(0, 0, W, H);

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
      removeEventListener("pointermove", onMove);
    },
  };
}

function smoothstep(x: number) {
  const k = clamp(x, 0, 1);
  return k * k * (3 - 2 * k);
}
