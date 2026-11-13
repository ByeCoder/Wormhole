// The 3D feel of the panel: a card leans toward the pointer and a light follows it.
// One listener for the whole page (cards come and go with the pages). Off in the panel's
// light mode, for reduced motion and on touch screens.

const MAX = 5; // degrees at the card's edge
const TALL = 560; // big cards (tables, logs) only get the light, not the lean

function off(): boolean {
  return (
    document.documentElement.dataset.low === "1" ||
    matchMedia("(prefers-reduced-motion: reduce)").matches ||
    matchMedia("(pointer: coarse)").matches
  );
}

export function startTilt(): () => void {
  let current: HTMLElement | null = null;
  let raf = 0;
  let last: PointerEvent | null = null;

  const reset = (el: HTMLElement) => {
    el.classList.remove("is-tilting");
    el.style.removeProperty("--rx");
    el.style.removeProperty("--ry");
    el.style.removeProperty("--lift");
  };

  const apply = () => {
    raf = 0;
    const e = last;
    if (!e) return;
    const target = (e.target as Element | null)?.closest?.<HTMLElement>(".card, .login-form") ?? null;
    if (current && current !== target) reset(current);
    current = target;
    if (!target || off()) return;
    // A card with an open menu or a focused field holds still.
    if (target.querySelector('[aria-expanded="true"]')) return reset(target);
    const r = target.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width;
    const y = (e.clientY - r.top) / r.height;
    target.style.setProperty("--mx", `${(x * 100).toFixed(1)}%`);
    target.style.setProperty("--my", `${(y * 100).toFixed(1)}%`);
    if (r.height > TALL || r.width > 1100) return;
    const k = target.classList.contains("login-form") ? 1.6 : 1;
    target.classList.add("is-tilting");
    target.style.setProperty("--ry", `${((x - 0.5) * 2 * MAX * k).toFixed(2)}deg`);
    target.style.setProperty("--rx", `${((0.5 - y) * 2 * MAX * k).toFixed(2)}deg`);
    target.style.setProperty("--lift", "8px");
  };

  const move = (e: PointerEvent) => {
    if (e.pointerType === "touch") return;
    last = e;
    if (!raf) raf = requestAnimationFrame(apply);
  };
  const leave = () => {
    if (current) reset(current);
    current = null;
  };

  addEventListener("pointermove", move, { passive: true });
  document.addEventListener("pointerleave", leave);
  addEventListener("blur", leave);
  return () => {
    removeEventListener("pointermove", move);
    document.removeEventListener("pointerleave", leave);
    removeEventListener("blur", leave);
    if (raf) cancelAnimationFrame(raf);
  };
}
