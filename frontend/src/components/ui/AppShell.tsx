import { useEffect, useState, type ReactNode } from "react";
import { Link, NavLink, Outlet, useLocation, useParams } from "react-router-dom";
import { api, type Overview, type Policy, type Scan } from "../../api";
import { MODE_LABEL, SCAN_STATUS_LABEL, SCAN_STATUS_TONE, scanLabel } from "../../lib/labels";
import s from "./AppShell.module.css";
import { Icon, type IconName } from "./Icon";
import { Banner, SeverityBadge } from "./primitives";
import { cx } from "./tone";

// The frame around every screen (TOKENS.md §6): a dark sidebar holding the
// current scan and the six screens, a top bar naming the scan and its state,
// and the policy staleness banner (§6) — an air-gapped install cannot fetch a
// newer pack, so the UI has to say when the loaded one is old.
//
// It reads only existing endpoints: the policy, the scan (re-read on every
// route change, since the flow advances a scan between screens), and the
// overview once a scan has finished, for the nav counts.

const SIDEBAR_DOT = {
  info: "var(--sb-dot-info)",
  high: "var(--sb-dot-high)",
  safe: "var(--sb-dot-safe)",
  critical: "var(--sb-dot-critical)",
} as const;

// The UUID's first block. The full id is on hover.
export const shortId = (id: string) => id.slice(0, 8);

function clock(iso: string): string {
  const at = new Date(iso);
  const parts = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZoneName: "short",
  }).formatToParts(at);
  const part = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  const sameDay = at.toDateString() === new Date().toDateString();
  const day = sameDay
    ? ""
    : `${String(at.getMonth() + 1).padStart(2, "0")}-${String(at.getDate()).padStart(2, "0")} `;
  return `${day}${part("hour")}:${part("minute")} ${part("timeZoneName")}`.trim();
}

function duration(fromIso: string, toIso: string): string {
  const total = Math.max(0, Math.round((Date.parse(toIso) - Date.parse(fromIso)) / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const sec = total % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}

function timing(scan: Scan): string | null {
  if (scan.completed_at) {
    const verb = scan.status === "failed" ? "failed" : "finished";
    const took = scan.created_at ? ` · ${duration(scan.created_at, scan.completed_at)}` : "";
    return `${verb} ${clock(scan.completed_at)}${took}`;
  }
  return scan.created_at ? `started ${clock(scan.created_at)}` : null;
}

interface NavEntry {
  label: string;
  icon: IconName;
  to: (id: string) => string;
  count?: (scan: Scan, overview: Overview | null) => number | null;
}

const NAV: NavEntry[] = [
  { label: "File Selection", icon: "fileSelection", to: (id) => `/scans/${id}/files`,
    count: (scan) => (scan.status === "awaiting_approval" ? scan.file_count : scan.approved_count || null) },
  { label: "Overview", icon: "overview", to: (id) => `/scans/${id}` },
  { label: "Findings", icon: "findings", to: (id) => `/scans/${id}/findings`,
    count: (_, o) => o?.finding_count ?? null },
  { label: "Drift", icon: "drift", to: (id) => `/scans/${id}/drift`,
    count: (_, o) => (o?.alignment.status === "compared" ? o.alignment.note_count : null) },
  { label: "Roadmap", icon: "roadmap", to: (id) => `/scans/${id}/roadmap`,
    count: (_, o) => (o ? Object.values(o.wave_counts).reduce((a, b) => a + b, 0) : null) },
];

export default function AppShell() {
  const { scanId } = useParams();
  const { pathname } = useLocation();
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);

  useEffect(() => {
    api.policy().then(setPolicy).catch(() => setPolicy(null));
  }, []);

  useEffect(() => {
    if (!scanId) {
      setScan(null);
      return;
    }
    let live = true;
    api
      .scan(scanId)
      .then((loaded) => live && setScan(loaded))
      .catch(() => live && setScan(null));
    return () => {
      live = false;
    };
  }, [scanId, pathname]);

  const finished =
    scan && (scan.status === "complete" || scan.status === "partial" || scan.status === "failed") ? scan.id : null;
  useEffect(() => {
    setOverview(null);
    if (!finished) return;
    let live = true;
    api
      .overview(finished)
      .then((loaded) => live && setOverview(loaded))
      .catch(() => live && setOverview(null));
    return () => {
      live = false;
    };
  }, [finished]);

  const current = scan && scan.id === scanId ? scan : null;
  const tone = current ? SCAN_STATUS_TONE[current.status] : null;

  const navClass = ({ isActive }: { isActive: boolean }) => cx(s.navItem, isActive && s.navActive);

  return (
    <div className={s.shell}>
      <aside className={s.sidebar}>
        <div className={s.brand}>
          <Link to="/" className={s.brandName}>
            ECDAT
          </Link>
          {__APP_VERSION__ && <span className={s.version}>v{__APP_VERSION__}</span>}
        </div>

        <div className={s.current}>
          <span className={s.sbCaps}>Current scan</span>
          {current && tone ? (
            <>
              <div className={s.currentId} title={current.id}>
                {shortId(current.id)}
              </div>
              <div className={s.currentTarget} title={scanLabel(current)}>
                {scanLabel(current)}
              </div>
              <div className={s.currentMode}>{MODE_LABEL[current.mode]}</div>
              <div className={s.currentStatus}>
                <span
                  className={s.statusSquare}
                  style={{ background: SIDEBAR_DOT[tone as keyof typeof SIDEBAR_DOT] ?? "var(--sb-dot-unknown)" }}
                  aria-hidden="true"
                />
                {SCAN_STATUS_LABEL[current.status]}
              </div>
            </>
          ) : (
            <div className={s.none}>None loaded. Start a scan or open one from history.</div>
          )}
        </div>

        <nav className={s.nav}>
          <NavLink to="/" end className={navClass}>
            <Icon name="newScan" />
            New Scan
          </NavLink>
          {NAV.map((entry) => {
            if (!scanId) {
              return (
                <span key={entry.label} className={cx(s.navItem, s.navDisabled)} aria-disabled="true">
                  <Icon name={entry.icon} />
                  {entry.label}
                </span>
              );
            }
            const count = current && entry.count ? entry.count(current, overview) : null;
            return (
              <NavLink key={entry.label} to={entry.to(scanId)} end className={navClass}>
                <Icon name={entry.icon} />
                {entry.label}
                {count !== null && <span className={s.navCount}>{count.toLocaleString("en-US")}</span>}
              </NavLink>
            );
          })}
        </nav>

        {policy && (
          <dl className={s.footer}>
            <dt className={s.footerLabel}>Policy</dt>
            <dd className={s.footerValue} title={policy.version}>
              {policy.version}
            </dd>
          </dl>
        )}
      </aside>

      <div className={s.main}>
        <header className={s.topbar}>
          {current && tone ? (
            <>
              <span className={s.topId} title={current.id}>
                {shortId(current.id)}
              </span>
              <span className={s.topTarget}>{scanLabel(current)}</span>
              <SeverityBadge tone={tone} marker={false}>
                {SCAN_STATUS_LABEL[current.status]}
              </SeverityBadge>
              {timing(current) && <span className={s.topMeta}>{timing(current)}</span>}
            </>
          ) : (
            <>
              <span className={s.topId}>–</span>
              <span className={s.topTarget}>No scan loaded</span>
              <SeverityBadge tone="unknown" marker={false}>
                Idle
              </SeverityBadge>
            </>
          )}
        </header>

        {policy?.stale && (
          <div className={s.stale}>
            <Banner tone="warn" title={`Policy pack ${policy.version} is ${policy.age_days} days old`}>
              Published {policy.published}; warning threshold {policy.staleness_warning_days} days. An
              air-gapped install cannot fetch updates — a newer pack has to be carried in.
            </Banner>
          </div>
        )}

        <div className={s.outlet}>
          <Outlet />
        </div>
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className={s.pageHead}>
      <h1 className={s.pageTitle}>{title}</h1>
      {subtitle && <span className={s.pageSubtitle}>{subtitle}</span>}
      {actions && <div className={s.pageActions}>{actions}</div>}
    </div>
  );
}

// The scrolling area under the page header. `flush` drops the padding for
// screens whose table runs edge to edge (Findings).
export function PageBody({ children, flush, className }: { children: ReactNode; flush?: boolean; className?: string }) {
  return <div className={cx(s.pageBody, flush && s.pageBodyFlush, className)}>{children}</div>;
}
