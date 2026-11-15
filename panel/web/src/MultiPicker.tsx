// The transports a `multi` tunnel runs at once (`[tunnel.multi] transports`): each on a
// port of its own, from the tunnel's port up, and new streams spread over all of them.
import { MULTI_MEMBERS } from "./transport";
import { useApp } from "./store";

/** The members a new multi tunnel starts with. */
export const DEFAULT_MEMBERS = ["tcp", "ws", "xhttp"];

/** Whether the members can be sent: two to eight, none twice. */
export const membersReady = (members: readonly string[]) => members.length >= 2 && members.length <= 8 && new Set(members).size === members.length;

/** A spec's `multi` list as the form shows it (`tcpmux` is tcp). */
export const readMembers = (multi: readonly string[] | undefined): string[] => (multi?.length ? multi.map((m) => (m === "tcpmux" ? "tcp" : m)) : [...DEFAULT_MEMBERS]);

export function MultiPicker({ value, onChange, port }: { value: string[]; onChange: (v: string[]) => void; port?: string }) {
  const { t } = useApp();
  // Members keep the order they were picked in: that is the order of their ports.
  const toggle = (m: string) => onChange(value.includes(m) ? value.filter((x) => x !== m) : [...value, m]);
  const base = port && /^\d{1,5}$/.test(port) ? +port : undefined;
  return (
    <div className="field">
      <span className="label" id="wz-multi">
        {t("wz.multi.pick")}
      </span>
      <span className="addr-chips" role="group" aria-labelledby="wz-multi">
        {MULTI_MEMBERS.map((m) => {
          const at = value.indexOf(m);
          return (
            <button key={m} type="button" className={`pchip as-btn mono ${at >= 0 ? "on" : ""}`} aria-pressed={at >= 0} dir="ltr" onClick={() => toggle(m)}>
              {m}
              {at >= 0 && base !== undefined && ` :${base + at}`}
            </button>
          );
        })}
      </span>
      <span className={value.length < 2 ? "help err" : "help"}>{value.length < 2 ? t("wz.multi.need2") : t("wz.multi.pickHelp")}</span>
    </div>
  );
}
