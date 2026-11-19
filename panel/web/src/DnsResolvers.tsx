// `dns` through real DNS resolvers (`[tunnel.dns]`): the dialing side sends its queries to
// resolvers, which pass them on to the listening side as the authoritative server of a
// domain delegated to it. For a shutdown where only DNS still gets out.
import { useApp } from "./store";

export interface DnsPath {
  on: boolean;
  domain: string;
  /** The resolvers as typed: IPs or IP:port, separated by commas, spaces or lines. */
  resolvers: string;
  duplicate: number;
}

/** Public resolvers to start from; for a shutdown, the country's own (the ISP's) belong here. */
export const DEFAULT_RESOLVERS = "8.8.8.8, 1.1.1.1, 9.9.9.9";

export const NO_DNS_PATH: DnsPath = { on: false, domain: "", resolvers: DEFAULT_RESOLVERS, duplicate: 2 };

const DOMAIN = /^(?=.{1,200}$)([a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$/;
const IP4 = /^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/;
const IP6 = /^(\[[0-9a-f:]+\](:\d{1,5})?|[0-9a-f:]*:[0-9a-f:]*)$/i;

export const resolverList = (text: string) =>
  text
    .split(/[\s,]+/)
    .map((r) => r.trim())
    .filter(Boolean);

const cleanDomain = (d: string) => d.trim().toLowerCase().replace(/\.$/, "");

/** What is wrong with the fields, as an i18n key; `null` when they can be sent. */
export function dnsProblem(v: DnsPath): string | null {
  if (!v.on) return null;
  if (!DOMAIN.test(cleanDomain(v.domain))) return "wz.dns.badDomain";
  const list = resolverList(v.resolvers);
  if (!list.length) return "wz.dns.needResolvers";
  if (!list.every((r) => IP4.test(r) || IP6.test(r))) return "wz.dns.badResolver";
  return null;
}

/** The request's fields for it (none when it is off). */
export function dnsFields(v: DnsPath) {
  if (!v.on) return {};
  return { dns_domain: cleanDomain(v.domain), dns_resolvers: resolverList(v.resolvers), dns_duplicate: v.duplicate };
}

/** The form's value from the specs of a tunnel's two sides. */
export function readDnsPath(specs: ({ dns?: { domain: string; resolvers?: string[]; duplicate?: number } } | undefined)[]): DnsPath {
  const sides = specs.map((s) => s?.dns).filter((d): d is NonNullable<typeof d> => !!d);
  if (!sides.length) return NO_DNS_PATH;
  const dialer = sides.find((d) => d.resolvers?.length) ?? sides[0];
  return {
    on: true,
    domain: dialer.domain,
    resolvers: (dialer.resolvers ?? []).join(", ") || DEFAULT_RESOLVERS,
    duplicate: dialer.duplicate ?? 2,
  };
}

export function DnsResolvers({ value, onChange, listener, dialer }: { value: DnsPath; onChange: (v: DnsPath) => void; listener: string; dialer: string }) {
  const { t } = useApp();
  const set = (patch: Partial<DnsPath>) => onChange({ ...value, ...patch });
  const problem = dnsProblem(value);
  return (
    <div className="field">
      <label className="check">
        <input type="checkbox" checked={value.on} onChange={(e) => set({ on: e.target.checked })} />
        <span>{t("wz.dns.on")}</span>
      </label>
      <span className="help">{t("wz.dns.onHelp")}</span>
      {value.on && (
        <>
          <div className="field">
            <label htmlFor="wz-dns-domain">{t("wz.dns.domain")}</label>
            <input className="text mono" id="wz-dns-domain" dir="ltr" value={value.domain} placeholder="t.example.com" onChange={(e) => set({ domain: e.target.value.trim() })} />
            <span className="help">{t("wz.dns.domainHelp", { server: listener })}</span>
          </div>
          <div className="field">
            <label htmlFor="wz-dns-resolvers">{t("wz.dns.resolvers")}</label>
            <textarea className="text mono" id="wz-dns-resolvers" dir="ltr" rows={2} value={value.resolvers} placeholder={DEFAULT_RESOLVERS} onChange={(e) => set({ resolvers: e.target.value })} />
            <span className="help">{t("wz.dns.resolversHelp", { server: dialer })}</span>
          </div>
          <div className="field">
            <label htmlFor="wz-dns-dup">{t("wz.dns.duplicate")}</label>
            <select className="text" id="wz-dns-dup" value={value.duplicate} onChange={(e) => set({ duplicate: +e.target.value })}>
              {[1, 2, 3, 4].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
            <span className="help">{t("wz.dns.duplicateHelp")}</span>
          </div>
          {problem && <span className="help err">{t(problem)}</span>}
        </>
      )}
    </div>
  );
}
