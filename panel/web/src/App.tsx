import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";
import { ApiError, api, setCsrf } from "./api";
import type { ServerInfo, SessionInfo } from "./api";
import { Login, loginError, tokenIn } from "./Login";
import { MapPage, ServersPage, SettingsPage } from "./pages";
import { LogsPage } from "./Logs";
import { NetworksPage } from "./Networks";
import { PAGES, Shell } from "./Shell";
import type { Live, PageId } from "./Shell";
import { TunnelsPage } from "./Tunnels";
import { ServersDialog, UpdateDialog, UpdatePill, UpdatesSection, useUpdate } from "./Update";
import { pairTunnels, withMeta } from "./derive";
import { useApp } from "./store";

type Screen = "boot" | "login" | "app";

// A login link in the address (`#t=...`) is read once, when the page loads, and taken out of
// the address at once: it must not stay in the history, and it works only once anyway.
const bootLink = tokenIn(location.hash);
if (bootLink) history.replaceState(null, "", location.pathname + location.search);

export interface Route {
  page: PageId;
  /** A tunnel's own page, under Tunnels. */
  tunnel?: string;
}

/** `#/tunnels/main` as a route; anything else is the map. */
function readRoute(): Route {
  const [, page, tunnel] = location.hash.split("/");
  if (!(PAGES as string[]).includes(page)) return { page: "map" };
  return { page: page as PageId, tunnel: page === "tunnels" && tunnel ? decodeURIComponent(tunnel) : undefined };
}

function Boot({ note }: { note: string }) {
  const { t } = useApp();
  return (
    <section id="boot" className="screen is-on" aria-label={t("a11y.loading")} aria-busy="true">
      <div className="boot-inner">
        <div className="wh-boot" aria-hidden="true">
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <i key={i} style={{ "--i": i } as CSSProperties} />
          ))}
          <b />
        </div>
        <div className="boot-word">
          {t("brand")}
          <small>{t("brand.alt")} · {t("boot.sub")}</small>
        </div>
        <p className="boot-note" aria-live="polite">
          {note}
        </p>
      </div>
    </section>
  );
}

export function App() {
  const { t, num, low, toast } = useApp();
  const [screen, setScreen] = useState<Screen>("boot");
  const [bootNote, setBootNote] = useState("");
  const [info, setInfo] = useState<SessionInfo | null>(null);
  const [loginError0, setLoginError0] = useState("");
  const [route, setRoute] = useState<Route>(readRoute);
  const [servers, setServers] = useState<ServerInfo[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [live, setLive] = useState<Live>({ state: "ok", at: 0 });
  const [agentsOn, setAgentsOn] = useState(false);
  const [reload, setReload] = useState(0);
  const [updating, setUpdating] = useState(false);
  const [updatingServers, setUpdatingServers] = useState(false);
  const update = useUpdate(screen === "app");
  const [rising, setRising] = useState(false);
  const [loginKey, setLoginKey] = useState(0);
  const lowRef = useRef(low);
  lowRef.current = low;

  // The address follows the page, so Back works and a reload keeps it.
  const navigate = useCallback((to: Route, replace = false) => {
    const hash = `#/${to.page}${to.tunnel ? `/${encodeURIComponent(to.tunnel)}` : ""}`;
    if (location.hash !== hash) history[replace ? "replaceState" : "pushState"](null, "", hash);
    setRoute(to);
  }, []);

  useEffect(() => {
    const onPop = () => setRoute(readRoute());
    addEventListener("popstate", onPop);
    return () => removeEventListener("popstate", onPop);
  }, []);

  const enter = useCallback((csrf: string | undefined) => {
    setCsrf(csrf);
    setRising(true);
    setScreen("app");
  }, []);

  // The logo draws itself while the session is looked up. A link in the address signs in
  // right here, without showing the sign-in form at all; only if it fails does the form come,
  // with the reason.
  useEffect(() => {
    let cancelled = false;
    const wait = new Promise((r) => setTimeout(r, lowRef.current ? 350 : 1500));
    void (async () => {
      const s = await api.session().catch(() => ({ authenticated: false, has_password: false }) as SessionInfo);
      if (cancelled) return;
      setInfo(s);
      if (bootLink) {
        setBootNote(t("login.checking"));
        try {
          const { csrf } = await api.loginWithLink(bootLink);
          const kept = await api.session().then((x) => x.authenticated, () => false);
          await wait;
          if (cancelled) return;
          if (!kept) {
            setLoginError0(t("login.noCookie"));
            setScreen("login");
            return;
          }
          void api.session().then(setInfo).catch(() => {});
          enter(csrf);
          setTimeout(() => toast(t("welcome"), "ok"), 900);
        } catch (e) {
          await wait;
          if (cancelled) return;
          setLoginError0(loginError(e, true, t, num));
          setScreen("login");
        }
        return;
      }
      await wait;
      if (cancelled) return;
      if (s.authenticated) enter(s.csrf);
      else setScreen("login");
    })();
    return () => {
      cancelled = true;
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const signOut = useCallback(() => {
    setCsrf(undefined);
    setServers([]);
    setLoaded(false);
    setLoginError0("");
    void api.session().then(setInfo).catch(() => {});
    setLoginKey((k) => k + 1);
    setScreen("login");
  }, []);

  // The servers, kept fresh while the dashboard is open. A session that ended (a revoked
  // one, a new password elsewhere) takes the panel back to the sign-in page; a panel that
  // does not answer is said so at the top, and the page keeps the last numbers it had.
  useEffect(() => {
    if (screen !== "app") return;
    let alive = true;
    let misses = 0;
    const load = () =>
      api
        .servers()
        .then((r) => {
          if (!alive) return;
          misses = 0;
          setServers(withMeta(r.servers, r.tunnel_meta));
          setAgentsOn(r.agents);
          setLoaded(true);
          setLive({ state: "ok", at: Date.now() });
        })
        .catch((e) => {
          if (!alive) return;
          if (e instanceof ApiError && e.status === 401) return signOut();
          misses++;
          if (misses >= 2) setLive((l) => ({ ...l, state: "lost" }));
        });
    void load();
    const id = setInterval(load, 2500);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [screen, signOut, reload]);

  const tunnelTitles = useMemo(() => pairTunnels(servers).map((x) => [x.name, x.title] as const), [servers]);
  const tunnelCount = tunnelTitles.length;
  const items = useMemo(
    () => tunnelTitles.map(([name, title]) => ({ label: t("pal.openTunnel", { name: title }), icon: "tunnels", run: () => navigate({ page: "tunnels", tunnel: name }) })),
    [tunnelTitles.join(), t, navigate], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const tunnelTitle = tunnelTitles.find(([name]) => name === route.tunnel)?.[1];
  const subtitle =
    route.page === "map"
      ? t("page.mapSub", { s: num(servers.length), t: num(tunnelCount) })
      : route.page === "servers"
        ? t("srv.sub", { n: num(servers.length) })
        : route.page === "tunnels"
          ? t("tun.sub", { n: num(tunnelCount) })
          : route.page === "networks"
            ? t("net.sub")
            : route.page === "logs"
              ? t("logs.sub")
              : t("set.sub");
  const changed = () => setReload((n) => n + 1);

  return (
    <>
      {screen === "boot" && <Boot note={bootNote} />}
      {screen === "login" && info && (
        <Login
          key={loginKey}
          hasPassword={info.has_password}
          initialError={loginError0}
          onSignedIn={(csrf) => {
            void api.session().then(setInfo).catch(() => {});
            enter(csrf);
          }}
        />
      )}
      {screen === "app" && (
        <Shell
          route={route}
          tunnelTitle={tunnelTitle}
          navigate={navigate}
          subtitle={subtitle}
          rising={rising}
          live={live}
          items={items}
          onLogout={() => {
            void api.logout().finally(signOut);
          }}
          notice={<UpdatePill status={update.status} onOpen={() => setUpdating(true)} onServers={() => setUpdatingServers(true)} />}
        >
          {route.page === "map" && <MapPage servers={servers} loaded={loaded} navigate={navigate} outdated={update.status?.outdated.length ?? 0} onUpdateServers={() => setUpdatingServers(true)} />}
          {route.page === "servers" && <ServersPage servers={servers} loaded={loaded} agentsOn={agentsOn} onChanged={changed} />}
          {route.page === "tunnels" && (
            <TunnelsPage
              servers={servers}
              loaded={loaded}
              open={route.tunnel ?? null}
              setOpen={(name) => navigate({ page: "tunnels", tunnel: name ?? undefined })}
              onChanged={changed}
            />
          )}
          {route.page === "networks" && <NetworksPage servers={servers} onChanged={changed} onOpenTunnel={(name) => navigate({ page: "tunnels", tunnel: name })} />}
          {route.page === "logs" && <LogsPage servers={servers} />}
          {route.page === "settings" && (
            <SettingsPage
              hasPassword={info?.has_password ?? false}
              onPasswordSet={() => setInfo((i) => (i ? { ...i, has_password: true } : i))}
              updates={<UpdatesSection status={update.status} reload={update.reload} />}
            />
          )}
          {updating && update.status && <UpdateDialog status={update.status} onClose={() => setUpdating(false)} />}
          {updatingServers && update.status && (
            <ServersDialog
              status={update.status}
              onClose={() => {
                setUpdatingServers(false);
                update.reload();
              }}
            />
          )}
        </Shell>
      )}
    </>
  );
}
