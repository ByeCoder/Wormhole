// A tunnel drawn as a wormhole: two small worlds, the entry and the exit, and between them a
// throat of neon rings that narrows in the middle and opens at both mouths. When the tunnel
// comes up, light shoots through the throat from the entry to the exit; while it is up, the
// rings run and the traffic is the light inside; a broken one goes dark halfway, with a
// pulse at the break; a stopped one is an empty, grey throat.
import { useEffect, useRef } from "react";
import { clamp, fitCanvas, paletteNow, rgba, uiFont } from "./draw";
import type { Tunnel } from "./derive";
import { rateParts } from "./derive";
import { useApp } from "./store";

const CYAN = "#22f3ff";
const VIOLET = "#8b5cff";
const MAGENTA = "#ff3fd8";
const RINGS = 26;

/** cyan → violet → magenta → mint along the throat. */
function hue(k: number, mint: string): string {
  const stops = [CYAN, VIOLET, MAGENTA, mint];
  const x = clamp(k, 0, 0.999) * 3;
  return stops[Math.floor(x + 0.5)];
}

function world(ctx: CanvasRenderingContext2D, x: number, y: number, r: number, col: string, spin: number, alive: boolean) {
  const air = ctx.createRadialGradient(x, y, r * 0.8, x, y, r * 1.9);
  air.addColorStop(0, rgba(col, alive ? 0.35 : 0.12));
  air.addColorStop(1, rgba(col, 0));
  ctx.fillStyle = air;
  ctx.beginPath();
  ctx.arc(x, y, r * 1.9, 0, Math.PI * 2);
  ctx.fill();
  const body = ctx.createRadialGradient(x - r * 0.35, y - r * 0.4, r * 0.1, x, y, r);
  body.addColorStop(0, alive ? "#3a2a8e" : "#2a2550");
  body.addColorStop(0.6, "#140b40");
  body.addColorStop(1, "#06031a");
  ctx.fillStyle = body;
  ctx.beginPath();
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.fill();
  // a few bands of light across it
  ctx.save();
  ctx.beginPath();
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.clip();
  ctx.strokeStyle = rgba(col, alive ? 0.45 : 0.18);
  ctx.lineWidth = 1;
  for (let i = -2; i <= 2; i++) {
    ctx.beginPath();
    ctx.ellipse(x + ((spin * 12) % (r * 0.6)) - r * 0.3, y + i * r * 0.32, r * 1.2, r * 0.12, -0.25, 0, Math.PI * 2);
    ctx.stroke();
  }
  ctx.restore();
  // its ring, the far half under the body was already covered; draw the near half over it
  ctx.strokeStyle = rgba(col, alive ? 0.9 : 0.35);
  ctx.lineWidth = 1.8;
  ctx.setLineDash([10, 6]);
  ctx.lineDashOffset = -spin * 30;
  ctx.beginPath();
  ctx.ellipse(x, y, r * 1.65, r * 0.42, -0.3, 0, Math.PI);
  ctx.stroke();
  ctx.setLineDash([]);
}

export function RouteScene({ tunnel }: { tunnel: Tunnel }) {
  const { t, num, low } = useApp();
  const canvas = useRef<HTMLCanvasElement>(null);
  const live = useRef({ tunnel, t, num, low });
  live.current = { tunnel, t, num, low };

  useEffect(() => {
    const cv = canvas.current;
    if (!cv) return;
    type Part = { k: number; dir: number; s: number; a: number };
    const parts: Part[] = [];
    let raf = 0;
    let last = 0;
    let reachUp = 1;
    let before: Tunnel["state"] | null = null;
    let visible = true;
    const io = new IntersectionObserver((e) => (visible = e.some((x) => x.isIntersecting)));
    io.observe(cv);

    const draw = (now: number) => {
      raf = requestAnimationFrame(draw);
      const { tunnel: tn, t, num, low } = live.current;
      if (!visible) return;
      const dt = Math.min(0.05, (now - last) / 1000);
      if (low && now - last < 2500 && before === tn.state) return;
      last = now;
      const P = paletteNow();
      const { ctx, W, H } = fitCanvas(cv);
      const rtl = document.documentElement.dir === "rtl";
      const time = low ? 0 : now / 1000;
      const narrow = W < 560;
      const wr = narrow ? 24 : 38;
      const x0 = rtl ? W - (wr + 54) : wr + 54;
      const x1 = rtl ? wr + 54 : W - (wr + 54);
      const y0 = H * 0.56;
      // the throat: a curve that rises between the two worlds
      const lift = H * 0.3;
      const at = (k: number) => {
        const m = 1 - k;
        const cx = (x0 + x1) / 2;
        const cy = y0 - lift * 2;
        return { x: m * m * x0 + 2 * m * k * cx + k * k * x1, y: m * m * y0 + 2 * m * k * cy + k * k * y0 };
      };
      const tangent = (k: number) => {
        const a = at(Math.max(0, k - 0.01));
        const b = at(Math.min(1, k + 0.01));
        return Math.atan2(b.y - a.y, b.x - a.x);
      };
      const radius = (k: number) => (narrow ? 26 : 44) * (0.42 + 0.58 * Math.pow(Math.abs(2 * k - 1), 1.3));

      if (before !== null && before !== "up" && tn.state === "up") reachUp = 0;
      before = tn.state;
      reachUp = low ? 1 : Math.min(1, reachUp + dt / 1.4);
      const reach = tn.state === "up" ? reachUp : tn.state === "down" ? 0.5 : 0;

      ctx.clearRect(0, 0, W, H);
      ctx.lineCap = "round";
      ctx.globalCompositeOperation = "lighter";

      // the rings of the throat, far half first, from the mouths inward
      const flow = low ? 0 : (time * 0.35) % (1 / RINGS);
      const ring = (k: number, half: 0 | 1) => {
        const p = at(k);
        const r = radius(k);
        const ang = tangent(k) + Math.PI / 2;
        const lit = k <= reach;
        const col = tn.state === "off" ? "#8a86b0" : !lit && tn.state === "down" ? P.danger : hue(k, P.water);
        const a = tn.state === "off" ? 0.22 : lit ? 0.85 : 0.18;
        ctx.strokeStyle = rgba(col, a * (half ? 1 : 0.45));
        ctx.lineWidth = lit && half ? 1.8 : 1;
        ctx.beginPath();
        ctx.ellipse(p.x, p.y, r, r * 0.34, ang, half ? 0 : Math.PI, half ? Math.PI : Math.PI * 2);
        ctx.stroke();
      };
      const ks: number[] = [];
      for (let i = 0; i <= RINGS; i++) {
        const k = i / RINGS + (tn.state === "up" ? flow : 0);
        if (k >= 0.04 && k <= 0.96) ks.push(k);
      }
      for (const k of ks) ring(k, 0);

      // the light inside: a core line, then the traffic
      if (reach > 0) {
        const a = at(0);
        const b = at(1);
        const g = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
        g.addColorStop(0, CYAN);
        g.addColorStop(0.5, tn.state === "up" ? VIOLET : P.warn);
        g.addColorStop(1, tn.state === "up" ? P.water : P.danger);
        for (const [w, alpha] of [
          [10, 0.12],
          [3, 0.9],
        ] as const) {
          ctx.strokeStyle = g;
          ctx.globalAlpha = alpha;
          ctx.lineWidth = w;
          ctx.beginPath();
          for (let i = 0; i <= 60; i++) {
            const k = (i / 60) * reach;
            const p = at(k);
            if (i) ctx.lineTo(p.x, p.y);
            else ctx.moveTo(p.x, p.y);
          }
          ctx.stroke();
        }
        ctx.globalAlpha = 1;
        // the head of a beam still on its way
        if (tn.state === "up" && reach < 1) {
          const p = at(reach);
          const hg = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, 26);
          hg.addColorStop(0, "rgba(255,255,255,0.95)");
          hg.addColorStop(0.3, rgba(CYAN, 0.6));
          hg.addColorStop(1, rgba(CYAN, 0));
          ctx.fillStyle = hg;
          ctx.fillRect(p.x - 26, p.y - 26, 52, 52);
        }
      }
      if (tn.state === "up" && reach >= 1 && !low) {
        const want = Math.round(clamp(14 + tn.rate / 5, 14, 110));
        while (parts.length < want) parts.push({ k: Math.random(), dir: Math.random() < 0.8 ? -1 : 1, s: 0.5 + Math.random() * 0.8, a: Math.random() * Math.PI * 2 });
        parts.length = want;
        const v = clamp(0.14 + tn.rate / 2400, 0.14, 0.55);
        for (const q of parts) {
          q.k = (q.k + q.dir * v * dt * q.s + 1) % 1;
          q.a += dt * 2.4 * q.s;
          const p = at(q.k);
          const r = radius(q.k) * 0.55;
          const ang = tangent(q.k) + Math.PI / 2;
          // spiralling round the inside of the throat
          const ox = Math.cos(q.a) * r;
          const oy = Math.sin(q.a) * r * 0.34;
          const x = p.x + ox * Math.cos(ang) - oy * Math.sin(ang);
          const y = p.y + ox * Math.sin(ang) + oy * Math.cos(ang);
          const size = (q.dir < 0 ? 6 : 4.5) * q.s;
          ctx.globalAlpha = q.dir < 0 ? 0.95 : 0.6;
          ctx.drawImage(P.sprite, x - size, y - size, size * 2, size * 2);
        }
        ctx.globalAlpha = 1;
      }
      for (const k of ks) ring(k, 1);

      // the break
      if (tn.state === "down") {
        const p = at(0.5);
        const k = low ? 0.5 : (time * 0.8) % 1;
        ctx.strokeStyle = rgba(P.danger, 1 - k);
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 6 + k * 22, 0, Math.PI * 2);
        ctx.stroke();
        ctx.drawImage(P.redSprite, p.x - 10, p.y - 10, 20, 20);
      }

      // the two worlds
      ctx.globalCompositeOperation = "source-over";
      const up = tn.state === "up";
      world(ctx, x0, y0, wr, CYAN, time, tn.state !== "off");
      world(ctx, x1, y0, wr, up && reach >= 1 ? P.water : tn.state === "down" ? P.danger : VIOLET, time * 0.8, up);

      // names
      ctx.textAlign = "center";
      ctx.direction = rtl ? "rtl" : "ltr";
      const label = (x: number, name: string, role: string, note: string) => {
        ctx.font = uiFont(600, narrow ? 12 : 14);
        ctx.fillStyle = "#f1efff";
        ctx.fillText(name, x, y0 + wr + 26);
        ctx.font = uiFont(400, 11);
        ctx.fillStyle = "#a9a4d6";
        ctx.fillText(`${role} · ${note}`, x, y0 + wr + 42);
      };
      label(x0, tn.entry?.server.name ?? "?", t("tun.side.entry"), t("td.users"));
      label(x1, tn.exit?.server.name ?? "?", t("tun.side.exit"), t("td.targets"));
      if (up) {
        const r = rateParts(tn.rate);
        const p = at(0.5);
        const text = `${num(r.value, r.decimals)} ${r.unit}`;
        ctx.direction = "ltr";
        ctx.font = uiFont(700, narrow ? 13 : 15);
        const w = ctx.measureText(text).width + 26;
        ctx.fillStyle = "rgba(7,4,26,0.8)";
        ctx.strokeStyle = rgba(P.water, 0.7);
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.roundRect(p.x - w / 2, p.y - radius(0.5) - 34, w, 24, 12);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = P.water;
        ctx.fillText(text, p.x, p.y - radius(0.5) - 17);
      }
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      io.disconnect();
    };
  }, [low]);

  return <canvas ref={canvas} aria-hidden="true" />;
}
