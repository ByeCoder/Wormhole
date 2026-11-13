// How a ws or wss tunnel carries its bytes (`tunnel.ws.mode`): WebSocket frames, the bare
// bytes after the same HTTP upgrade (httpupgrade), or for wss the bare bytes right after TLS.
import { Choice } from "./Choice";
import { useApp } from "./store";

export type WsMode = "websocket" | "httpupgrade" | "tls";

/** The modes a transport offers: `tls` only over TLS. */
export const wsModes = (transport: string): WsMode[] => (transport === "wss" ? ["websocket", "httpupgrade", "tls"] : ["websocket", "httpupgrade"]);

/** The mode that applies (a `tls` left over from wss falls back to frames on ws). */
export const wsModeOf = (transport: string, mode: WsMode): WsMode => (wsModes(transport).includes(mode) ? mode : "websocket");

/** What the request carries: nothing for frames (the default) or for other transports. */
export const wsModeField = (transport: string, mode: WsMode): string | undefined => {
  if (transport !== "ws" && transport !== "wss") return undefined;
  const m = wsModeOf(transport, mode);
  return m === "websocket" ? undefined : m;
};

/** A spec's `ws_mode` as a mode ("raw" is the core's other name for tls). */
export const readWsMode = (value: string | undefined): WsMode => (value === "httpupgrade" ? "httpupgrade" : value === "tls" || value === "raw" ? "tls" : "websocket");

export function WsModeChoice({ transport, value, onChange }: { transport: string; value: WsMode; onChange: (m: WsMode) => void }) {
  const { t } = useApp();
  if (transport !== "ws" && transport !== "wss") return null;
  const now = wsModeOf(transport, value);
  return <Choice label={t("wsm.title")} mono value={now} options={wsModes(transport).map((m) => [m, m])} onChange={onChange} hint={t(`wsm.${now}.d`)} />;
}
