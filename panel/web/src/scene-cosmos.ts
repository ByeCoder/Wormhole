// The space behind the whole panel: a nebula, a slowly turning spiral galaxy seen at an
// angle, three depths of stars that move with the pointer, and now and then a falling star.
//
// Built to stay light: everything that does not move is painted once into offscreen
// canvases (again only on a resize or a theme change), so a frame is two image copies and a
// few hundred star dots. It draws at most 30 times a second, stops while the tab is hidden,
// and in low-power mode (or for reduced motion) it is painted once, still.
import { clamp, rng } from "./draw";

type RGB = [number, number, number];

interface Star {
  x: number;
  y: number;
  /** 0 far … 1 near: size, brightness and parallax. */
  z: number;
  ph: number;
  c: RGB;
}

const STAR_COLORS: RGB[] = [
  [255, 255, 255],
  [189, 246, 255],
  [216, 204, 255],
  [255, 198, 245],
  [159, 248, 255],
];

const night = () => document.documentElement.dataset.theme !== "dawn";
const still = () =>
  document.documentElement.dataset.low === "1" || matchMedia("(prefers-reduced-motion: reduce)").matches;

/** A spiral galaxy, face on, painted once; the frame squashes and turns it. */
export function paintGalaxy(size: number, dark: boolean, seed = 7): HTMLCanvasElement {
  const c = document.createElement("canvas");
  c.width = c.height = size;
  const g = c.getContext("2d")!;
  const R = size / 2;
  const r = rng(seed);
  const gauss = () => (r() + r() + r() - 1.5) / 1.5;
  g.globalCompositeOperation = "lighter";
  const halo = g.createRadialGradient(R, R, 0, R, R, R);
  halo.addColorStop(0, dark ? "rgba(255,225,250,0.55)" : "rgba(255,200,240,0.5)");
  halo.addColorStop(0.08, dark ? "rgba(190,140,255,0.35)" : "rgba(160,110,255,0.3)");
  halo.addColorStop(0.35, dark ? "rgba(90,60,200,0.12)" : "rgba(120,90,255,0.1)");
  halo.addColorStop(1, "rgba(0,0,0,0)");
  g.fillStyle = halo;
  g.fillRect(0, 0, size, size);
  const arms = 3;
  const n = Math.round(size * 7);
  for (let i = 0; i < n; i++) {
    const k = Math.pow(r(), 0.7);
    const arm = i % arms;
    const wind = k * 5.2;
    const spread = 0.45 * (1 - k * 0.55);
    const a = (arm / arms) * Math.PI * 2 + wind + gauss() * spread;
    const d = k * R * 0.96 + gauss() * R * 0.025;
    const x = R + Math.cos(a) * d;
    const y = R + Math.sin(a) * d;
    // warm white in the bulge, violet in the arms, cyan at the rim
    const col: RGB = k < 0.18 ? [255, 228, 246] : k < 0.55 ? [176, 132, 255] : k < 0.8 ? [120, 170, 255] : [80, 235, 255];
    const alpha = (0.18 + r() * 0.5) * (1 - k * 0.55);
    const s = r() < 0.04 ? 1.8 : 0.6 + r() * 0.8;
    g.fillStyle = `rgba(${col[0]},${col[1]},${col[2]},${alpha})`;
    g.fillRect(x, y, s, s);
  }
  // dust lanes of pink gas along the arms
  for (let i = 0; i < 70; i++) {
    const k = 0.2 + r() * 0.7;
    const a = ((i % arms) / arms) * Math.PI * 2 + k * 5.2 + gauss() * 0.2;
    const x = R + Math.cos(a) * k * R;
    const y = R + Math.sin(a) * k * R;
    const rad = R * (0.05 + r() * 0.07);
    const cl = g.createRadialGradient(x, y, 0, x, y, rad);
    cl.addColorStop(0, i % 3 ? "rgba(255,63,216,0.07)" : "rgba(34,243,255,0.06)");
    cl.addColorStop(1, "rgba(0,0,0,0)");
    g.fillStyle = cl;
    g.fillRect(x - rad, y - rad, rad * 2, rad * 2);
  }
  return c;
}

/** The deep sky: the gradient and the nebula clouds, painted once per size and theme. */
function paintSky(W: number, H: number, dark: boolean): HTMLCanvasElement {
  const c = document.createElement("canvas");
  c.width = Math.max(1, Math.round(W));
  c.height = Math.max(1, Math.round(H));
  const g = c.getContext("2d")!;
  const bg = g.createLinearGradient(0, 0, W * 0.3, H);
  if (dark) {
    bg.addColorStop(0, "#03020c");
    bg.addColorStop(0.5, "#070420");
    bg.addColorStop(1, "#040213");
  } else {
    bg.addColorStop(0, "#f7f4ff");
    bg.addColorStop(1, "#e7e0ff");
  }
  g.fillStyle = bg;
  g.fillRect(0, 0, W, H);
  const r = rng(31);
  const S = Math.max(W, H);
  const clouds: [number, number, number, string][] = dark
    ? [
        [0.86, 0.06, 0.55, "rgba(139,92,255,0.30)"],
        [0.05, 0.25, 0.5, "rgba(34,243,255,0.13)"],
        [0.55, 1.05, 0.6, "rgba(255,63,216,0.16)"],
        [0.3, 0.6, 0.35, "rgba(90,60,220,0.12)"],
        [0.95, 0.7, 0.4, "rgba(34,180,255,0.10)"],
      ]
    : [
        [0.86, 0.06, 0.55, "rgba(139,92,255,0.22)"],
        [0.05, 0.25, 0.5, "rgba(34,200,255,0.16)"],
        [0.55, 1.05, 0.6, "rgba(255,63,216,0.12)"],
      ];
  for (const [x, y, rad, col] of clouds) {
    // each cloud is a few overlapping puffs, so its edge is not a perfect circle
    for (let k = 0; k < 5; k++) {
      const cx = (x + (r() - 0.5) * 0.12) * W;
      const cy = (y + (r() - 0.5) * 0.12) * H;
      const rr = rad * S * (0.5 + r() * 0.5);
      const gr = g.createRadialGradient(cx, cy, 0, cx, cy, rr);
      gr.addColorStop(0, col);
      gr.addColorStop(1, "rgba(0,0,0,0)");
      g.fillStyle = gr;
      g.fillRect(0, 0, W, H);
    }
  }
  // faint distant stars, baked in
  const n = Math.round((W * H) / (dark ? 1400 : 3000));
  for (let i = 0; i < n; i++) {
    const a = dark ? 0.15 + r() * 0.35 : 0.08 + r() * 0.15;
    g.fillStyle = dark ? `rgba(220,230,255,${a})` : `rgba(90,34,230,${a})`;
    const s = r() < 0.05 ? 1.2 : 0.7;
    g.fillRect(r() * W, r() * H, s, s);
  }
  return c;
}

export interface Cosmos {
  stop: () => void;
}

/** Starts the panel's background on a fixed, full-window canvas. */
export function startCosmos(canvas: HTMLCanvasElement): Cosmos {
  let raf = 0;
  let stopped = false;
  let lastDraw = 0;
  let sky: HTMLCanvasElement | null = null;
  let galaxy: HTMLCanvasElement | null = null;
  let key = "";
  let stars: Star[] = [];
  let mx = 0;
  let my = 0;
  let px = 0;
  let py = 0;
  let meteor: { x: number; y: number; vx: number; vy: number; life: number } | null = null;
  let nextMeteor = performance.now() + 6000;

  const onMove = (e: PointerEvent) => {
    mx = e.clientX / innerWidth - 0.5;
    my = e.clientY / innerHeight - 0.5;
  };
  addEventListener("pointermove", onMove, { passive: true });

  const frame = (now: number) => {
    if (stopped) return;
    raf = requestAnimationFrame(frame);
    const calm = still();
    // 30 frames a second is plenty for a background; once every two seconds when still.
    if (now - lastDraw < (calm ? 2000 : 33)) return;
    lastDraw = now;
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
    const dark = night();
    const k = `${W}x${H}:${dark}`;
    if (k !== key) {
      key = k;
      sky = paintSky(W, H, dark);
      galaxy = paintGalaxy(Math.round(clamp(Math.max(W, H) * 0.7, 420, 1100)), dark);
      const r = rng(97);
      stars = Array.from({ length: Math.round(clamp((W * H) / 5200, 120, 420)) }, () => ({
        x: r() * 1.1 - 0.05,
        y: r() * 1.1 - 0.05,
        z: Math.pow(r(), 2.2),
        ph: r() * 6.28,
        c: STAR_COLORS[Math.floor(r() * STAR_COLORS.length)],
      }));
    }
    const t = now / 1000;
    px += (mx - px) * 0.04;
    py += (my - py) * 0.04;
    ctx.globalCompositeOperation = "source-over";
    ctx.drawImage(sky!, 0, 0, W, H);

    // The galaxy, tilted away from us, turning once in a few minutes.
    const G = galaxy!;
    const gs = Math.max(W, H) * 0.62;
    ctx.save();
    ctx.globalAlpha = dark ? 0.85 : 0.35;
    ctx.globalCompositeOperation = dark ? "lighter" : "source-over";
    ctx.translate(W * 0.74 - px * 18, H * 0.3 - py * 12);
    ctx.rotate(-0.42);
    ctx.scale(1, 0.38);
    ctx.rotate(calm ? 0 : t * 0.02);
    ctx.drawImage(G, -gs / 2, -gs / 2, gs, gs);
    ctx.restore();

    // Stars: the nearer, the bigger, brighter and more they move with the pointer.
    ctx.globalCompositeOperation = dark ? "lighter" : "source-over";
    for (const s of stars) {
      const x = s.x * W - px * 40 * s.z;
      const y = s.y * H - py * 30 * s.z;
      const tw = calm ? 0.8 : 0.55 + 0.45 * Math.sin(t * (0.6 + s.z * 1.6) + s.ph);
      const a = (0.25 + 0.75 * s.z) * tw * (dark ? 1 : 0.5);
      const size = 0.6 + s.z * 1.9;
      const [r, g, b] = dark ? s.c : [90, 34, 230];
      ctx.fillStyle = `rgba(${r},${g},${b},${a})`;
      ctx.fillRect(x, y, size, size);
      // the brightest few get a cross of light
      if (s.z > 0.82 && dark) {
        ctx.fillStyle = `rgba(${r},${g},${b},${a * 0.35})`;
        ctx.fillRect(x - size * 2, y + size / 2 - 0.4, size * 5, 0.8);
        ctx.fillRect(x + size / 2 - 0.4, y - size * 2, 0.8, size * 5);
      }
    }

    // Now and then, a falling star.
    if (!calm && dark) {
      if (!meteor && now > nextMeteor) {
        const fromLeft = Math.random() < 0.5;
        meteor = { x: fromLeft ? Math.random() * W * 0.5 : W * (0.5 + Math.random() * 0.5), y: Math.random() * H * 0.4, vx: (fromLeft ? 1 : -1) * (500 + Math.random() * 300), vy: 220 + Math.random() * 120, life: 1 };
        nextMeteor = now + 7000 + Math.random() * 9000;
      }
      if (meteor) {
        const m = meteor;
        m.x += m.vx * 0.033;
        m.y += m.vy * 0.033;
        m.life -= 0.033 * 1.1;
        const tail = ctx.createLinearGradient(m.x, m.y, m.x - m.vx * 0.18, m.y - m.vy * 0.18);
        tail.addColorStop(0, `rgba(220,250,255,${0.9 * m.life})`);
        tail.addColorStop(1, "rgba(139,92,255,0)");
        ctx.strokeStyle = tail;
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.moveTo(m.x, m.y);
        ctx.lineTo(m.x - m.vx * 0.18, m.y - m.vy * 0.18);
        ctx.stroke();
        if (m.life <= 0) meteor = null;
      }
    }
    ctx.globalCompositeOperation = "source-over";
  };
  const onVisible = () => {
    // a hidden tab gets no frames anyway; draw at once on return
    lastDraw = 0;
  };
  document.addEventListener("visibilitychange", onVisible);
  raf = requestAnimationFrame(frame);
  return {
    stop() {
      stopped = true;
      cancelAnimationFrame(raf);
      removeEventListener("pointermove", onMove);
      document.removeEventListener("visibilitychange", onVisible);
    },
  };
}
