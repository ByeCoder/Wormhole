import type { SpoofPair, SpoofSpec } from "./api";
import { useApp } from "./store";

/** The spoof addresses as the form holds them, per side, as text. */
export interface SpoofForm {
  /** The entry side's forged source addresses, one per line or comma-separated. */
  entrySources: string;
  /** The exit side's forged source addresses. */
  exitSources: string;
  /** The entry side's real address (where the exit sends replies). */
  entryReal: string;
  /** The exit side's real address (where the entry sends replies). */
  exitReal: string;
  /** Forged TCP source port (both sides); empty: the tunnel's real port. */
  port: string;
}

export const emptySpoof = (): SpoofForm => ({
  entrySources: "",
  exitSources: "",
  entryReal: "",
  exitReal: "",
  port: "",
});

export function spoofFromPair(p?: SpoofPair | null): SpoofForm {
  const sources = (s?: SpoofSpec) =>
    s?.spoof_ips?.length ? s.spoof_ips.join("\n") : s?.spoof_ip ?? "";
  // Each side stores the PEER's real address: the entry side's `peer_ip` is the exit's
  // real address, so the entry's own real address comes from the exit side's `peer_ip`.
  return {
    entrySources: sources(p?.entry),
    exitSources: sources(p?.exit),
    entryReal: p?.exit.peer_ip ?? "",
    exitReal: p?.entry.peer_ip ?? "",
    port: p?.entry.port ? String(p.entry.port) : p?.exit.port ? String(p.exit.port) : "",
  };
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const okIp = (s: string) => {
  const m = IPV4.exec(s.trim());
  return !!m && m.slice(1).every((o) => +o <= 255);
};
const list = (text: string) =>
  text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);

/** A side's SpoofSpec: its own sources, and the OTHER side's real address as peer_ip. */
function sideSpec(sources: string[], peerReal: string, port: string): SpoofSpec {
  const spec: SpoofSpec = {};
  if (sources.length === 1) spec.spoof_ip = sources[0];
  else if (sources.length > 1) spec.spoof_ips = sources;
  if (peerReal.trim()) spec.peer_ip = peerReal.trim();
  if (port.trim()) spec.port = +port.trim();
  return spec;
}

/** The form as the `spoof` request field, or the key of the first field that is wrong. */
export function spoofToPair(f: SpoofForm): { spoof?: SpoofPair; bad?: keyof SpoofForm } {
  const entry = list(f.entrySources);
  const exit = list(f.exitSources);
  if (entry.length === 0) return { bad: "entrySources" };
  if (exit.length === 0) return { bad: "exitSources" };
  if (![...entry, ...exit].every(okIp)) return { bad: entry.every(okIp) ? "exitSources" : "entrySources" };
  if (f.entryReal.trim() && !okIp(f.entryReal)) return { bad: "entryReal" };
  if (f.exitReal.trim() && !okIp(f.exitReal)) return { bad: "exitReal" };
  if (f.port.trim() && !/^\d{1,5}$/.test(f.port.trim())) return { bad: "port" };
  // The entry side's peer is the exit (its real address is exitReal), and vice versa.
  return {
    spoof: {
      entry: sideSpec(entry, f.exitReal, f.port),
      exit: sideSpec(exit, f.entryReal, f.port),
    },
  };
}

/** Collects a spoof tunnel's forged addresses: each side's whitelisted source(s), and
 * each side's real address (so the other side knows where to send replies). */
export function SpoofFields({
  value,
  onChange,
  entryName,
  exitName,
}: {
  value: SpoofForm;
  onChange: (v: SpoofForm) => void;
  entryName: string;
  exitName: string;
}) {
  const { t } = useApp();
  const bad = spoofToPair(value).bad;
  const area = (key: "entrySources" | "exitSources", server: string) => (
    <div className="field">
      <label htmlFor={`spoof-${key}`}>{t("spoof.sources", { server })}</label>
      <textarea
        className={`text mono ${bad === key ? "is-bad" : ""}`}
        id={`spoof-${key}`}
        dir="ltr"
        rows={2}
        value={value[key]}
        placeholder="5.6.7.8"
        aria-invalid={bad === key}
        onChange={(e) => onChange({ ...value, [key]: e.target.value })}
      />
      <span className="help">{t("spoof.sources.d")}</span>
    </div>
  );
  const ip = (key: "entryReal" | "exitReal", server: string) => (
    <div className="field">
      <label htmlFor={`spoof-${key}`}>{t("spoof.real", { server })}</label>
      <input
        className={`text mono ${bad === key ? "is-bad" : ""}`}
        id={`spoof-${key}`}
        dir="ltr"
        value={value[key]}
        placeholder="203.0.113.5"
        aria-invalid={bad === key}
        onChange={(e) => onChange({ ...value, [key]: e.target.value.trim() })}
      />
      <span className="help">{t("spoof.real.d")}</span>
    </div>
  );
  return (
    <div className="spoof-fields">
      <p className="muted small">{t("spoof.lead")}</p>
      <div className="grid-2">
        {area("entrySources", entryName)}
        {area("exitSources", exitName)}
        {ip("entryReal", entryName)}
        {ip("exitReal", exitName)}
        <div className="field">
          <label htmlFor="spoof-port">{t("spoof.port")}</label>
          <input
            className={`text mono ${bad === "port" ? "is-bad" : ""}`}
            id="spoof-port"
            dir="ltr"
            inputMode="numeric"
            value={value.port}
            placeholder={t("spoof.port.ph")}
            aria-invalid={bad === "port"}
            onChange={(e) => onChange({ ...value, port: e.target.value.trim() })}
          />
          <span className="help">{t("spoof.port.d")}</span>
        </div>
      </div>
    </div>
  );
}
