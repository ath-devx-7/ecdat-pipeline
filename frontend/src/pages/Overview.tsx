import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, zStorageKey, type Overview as OverviewData, type Scan } from "../api";
import { PageBody, PageHeader, shortId } from "../components/ui/AppShell";
import { BarList, StackedBar } from "../components/ui/Bars";
import { DataTable } from "../components/ui/DataTable";
import { Icon } from "../components/ui/Icon";
import { Banner, buttonClass, Caps, KpiTile, Panel, SeverityBadge } from "../components/ui/primitives";
import { StatePanel } from "../components/ui/StatePanel";
import {
  SCAN_STATUS_LABEL,
  STATUS_DESCRIPTION,
  STATUS_LABEL,
  STATUS_TONE,
  STATUSES,
  titleCase,
  VERDICT_LABEL,
  VERDICT_TONE,
  VERDICTS,
  WAVE_LABEL,
  WAVE_TONE,
  WAVES,
  scanLabel,
} from "../lib/labels";
import s from "./Overview.module.css";

// §13 screen 3. The readiness number is shown with its denominator and the
// unassessed count beside it; the four recommendation statuses are always four
// rows; and the Z slider re-scores the scan live, because Z is an assumption.

// Z is an assumption about the world rather than a fact about this scan, so it
// is answered here, beside the waves it moves and the report that carries them
// out of the room — not on the intake form, where it would look like a property
// of the source. It starts lower than the pack's own figure deliberately: a plan
// that only holds if the machine is late is not a plan.
const DEFAULT_Z = 5;

const pct = (part: number, whole: number) => (whole ? Math.round((part / whole) * 100) : 0);

function duration(fromIso: string | null, toIso: string | null): string | null {
  if (!fromIso || !toIso) return null;
  const total = Math.max(0, Math.round((Date.parse(toIso) - Date.parse(fromIso)) / 1000));
  const m = Math.floor(total / 60);
  return m ? `${m}m ${total % 60}s` : `${total}s`;
}

export default function Overview() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState<OverviewData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const [recent, setRecent] = useState<Scan[] | null>(null);
  const [z, setZ] = useState<number | null>(null);
  const [rescoring, setRescoring] = useState(false);
  const [importing, setImporting] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  const load = useCallback(async () => {
    const loaded = await api.overview(scanId);
    setData(loaded);
    return loaded;
  }, [scanId]);

  useEffect(() => {
    load()
      .then(async (loaded) => {
        // Z opens at DEFAULT_Z unless this scan has already been moved, in
        // which case that choice stands — the slider must not reset the answer
        // out from under someone every time they come back to the page.
        const remembered = localStorage.getItem(zStorageKey(scanId));
        const wanted = remembered ? Number(remembered) : DEFAULT_Z;
        if (loaded.z_years_used !== null && wanted !== loaded.z_years_used) {
          // The stored rows were scored at a different Z, so the wave chart on
          // screen would not be the chart this slider position describes.
          await api.rescore(scanId, wanted);
          await load();
        }
        setZ(wanted);
      })
      .catch((err) => {
        // No such scan is the "nothing loaded" screen, not an error: offer
        // the scans that do exist.
        if (err instanceof ApiError && err.status === 404) {
          setMissing(true);
          api.scans().then(setRecent).catch(() => setRecent([]));
        } else setError(err.message);
      });
  }, [scanId, load]);

  function onZ(value: number) {
    setZ(value);
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(async () => {
      setRescoring(true);
      try {
        await api.rescore(scanId, value);
        // Remembered per scan, so reopening the page does not throw the answer
        // away and re-score at the default behind the user's back.
        localStorage.setItem(zStorageKey(scanId), String(value));
        await load();
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setRescoring(false);
      }
    }, 300);
  }

  async function onImport(file: File | undefined) {
    if (!file) return;
    setImporting(`Importing ${file.name}…`);
    try {
      const outcome = await api.importCbom(scanId, file);
      setImporting(
        `${file.name}: ${outcome.component_count} components → ${outcome.finding_count} findings` +
          (outcome.tool ? ` (from ${outcome.tool})` : "") +
          (outcome.skipped.length ? `; skipped ${outcome.skipped.length}` : ""),
      );
      await load();
    } catch (err) {
      setImporting(err instanceof Error ? err.message : String(err));
    }
  }

  // ---- empty: no such scan ----
  if (missing) {
    const finished = (recent ?? []).filter(
      (scan) => scan.status === "complete" || scan.status === "partial" || scan.status === "failed",
    );
    return (
      <>
        <PageHeader title="Overview" subtitle="Summary of a completed scan." />
        <PageBody>
          <StatePanel
            variant="empty"
            title="No scan loaded"
            actions={
              <Link to="/" className={buttonClass("primary")}>
                New scan
              </Link>
            }
          >
            <p>
              The overview summarises one completed scan: finding counts, verdict mix, Mosca risk and exports. Open a
              recent scan or configure a new one.
            </p>
            {finished.length > 0 && (
              <div style={{ border: "var(--bw) solid var(--border)", borderRadius: "var(--radius-sm)" }}>
                <DataTable
                  rowKey={(scan) => scan.id}
                  rows={finished.slice(0, 8)}
                  onRowClick={(scan) => navigate(`/scans/${scan.id}`)}
                  columns={[
                    { key: "id", header: "ID", width: 90, mono: true, render: (scan) => shortId(scan.id) },
                    { key: "target", header: "Target", render: (scan) => scanLabel(scan) },
                    {
                      key: "finished",
                      header: "Finished",
                      width: 120,
                      mono: true,
                      render: (scan) => scan.completed_at?.slice(5, 16).replace("T", " ") ?? "–",
                    },
                  ]}
                />
              </div>
            )}
          </StatePanel>
        </PageBody>
      </>
    );
  }

  if (error && !data) {
    return (
      <>
        <PageHeader title="Overview" subtitle="Summary of a completed scan." />
        <PageBody>
          <StatePanel variant="error" tag="Overview unavailable" meta={shortId(scanId)} title="The overview could not be loaded" log={[error]} />
        </PageBody>
      </>
    );
  }

  if (!data) {
    return (
      <>
        <PageHeader title="Overview" subtitle="Loading…" />
        <PageBody>
          <StatePanel variant="loading" appearance="panel" title="Loading overview" meta={shortId(scanId)} />
        </PageBody>
      </>
    );
  }

  const { scan, readiness, policy } = data;

  // ---- not analysed yet ----
  if (scan.status === "staging" || scan.status === "awaiting_approval") {
    return (
      <>
        <PageHeader title="Overview" subtitle="Analysis has not started." />
        <PageBody>
          <StatePanel
            variant="empty"
            tag={SCAN_STATUS_LABEL[scan.status]}
            tagTone="high"
            meta={shortId(scan.id)}
            title="Nothing has been analysed yet"
            actions={
              <Link to={`/scans/${scan.id}/files`} className={buttonClass("primary")}>
                Review files
              </Link>
            }
          >
            Collectors run only over files you approve. Charts, the risk picture and exports appear once analysis has
            finished.
          </StatePanel>
        </PageBody>
      </>
    );
  }

  // ---- analysis running ----
  if (scan.status === "running") {
    return (
      <>
        <PageHeader title="Overview" subtitle={`Analysis in progress — ${scan.approved_count.toLocaleString("en-US")} approved files.`} />
        <PageBody>
          <StatePanel variant="loading" appearance="panel" title="Analysis running" meta={shortId(scan.id)}>
            Collectors are running over the approved paths only. Charts and the risk picture appear when every collector
            has finished; reload this page then.
          </StatePanel>
        </PageBody>
      </>
    );
  }

  // ---- populated / completed with errors ----
  const total = data.finding_count;
  const targets = scan.probe_targets?.length ?? 0;
  const counts = data.verdict_counts;
  const zUsed = data.z_years_used ?? z ?? policy.z_years_default;
  const x = scan.data_lifetime_years;
  const y = policy.y_years_default;
  const recTotal = STATUSES.reduce((sum, status) => sum + (data.recommendation_counts[status] ?? 0), 0);
  const ran = new Set(scan.diagnostics?.collectors.filter((run) => run.ran).map((run) => run.name) ?? []);
  const notRun = scan.diagnostics?.collectors.filter((run) => !run.ran).map((run) => run.name) ?? [];
  const took = duration(scan.created_at, scan.completed_at);

  const subtitle = [
    scan.mode !== "probe_only" && `${scan.approved_count.toLocaleString("en-US")} files analysed`,
    targets > 0 && `${targets} endpoint${targets === 1 ? "" : "s"} probed`,
    `policy ${scan.policy_version ?? policy.version}`,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle={subtitle}
        actions={
          <>
            <a className={buttonClass("primary")} href={api.cbomUrl(scanId)}>
              <Icon name="download" size={14} />
              CycloneDX 1.6 CBOM
            </a>
            <a className={buttonClass("secondary")} href={api.reportUrl(scanId)}>
              PDF report
            </a>
            <a className={buttonClass("secondary")} href={api.reportHtmlUrl(scanId)} target="_blank" rel="noreferrer">
              HTML report
            </a>
          </>
        }
      />
      <PageBody>
        {scan.policy_version && scan.policy_version !== policy.version && (
          <Banner tone="warn" title={`Scanned under pack ${scan.policy_version}`}>
            Verdicts were re-computed under {policy.version}.
          </Banner>
        )}
        {error && <Banner tone="error" title="Re-scoring failed">{error}</Banner>}

        <div className={s.kpis}>
          <KpiTile label="Total findings" value={total} sub={`${readiness.assessed} assessed · ${readiness.unassessed} unassessed`} />
          <KpiTile
            label="Quantum-vulnerable"
            tone="high"
            value={counts.quantum_vulnerable ?? 0}
            sub={`${pct(counts.quantum_vulnerable ?? 0, total)}% · breakable by a quantum computer`}
          />
          <KpiTile label="Classically weak" tone="critical" value={counts.broken_now ?? 0} sub="fix now — no PQC dependency" />
          <KpiTile
            label="PQC-ready"
            tone="safe"
            value={readiness.quantum_safe}
            sub={readiness.percent === null ? "readiness not assessed" : `${readiness.percent}% PQC readiness`}
          />
          <KpiTile label="Unknown" tone="unknown" value={counts.unknown ?? 0} sub="not assessed — neither safe nor vulnerable" />
          <KpiTile label="Blocked recs" tone="blocked" value={data.recommendation_counts.blocked ?? 0} sub={`of ${recTotal} recommendations`} />
        </div>

        <div className={s.grid}>
          <div className={s.col}>
            <Panel title="Findings by verdict" meta={<span className={s.metaMono}>n = {total}</span>}>
              <StackedBar
                parts={VERDICTS.filter((verdict) => verdict in counts).map((verdict) => ({
                  key: verdict,
                  label: VERDICT_LABEL[verdict],
                  count: counts[verdict] ?? 0,
                  tone: VERDICT_TONE[verdict],
                }))}
              />
              <p className={s.note}>
                Broken-now and quantum-vulnerable are independent classifications, not two points on one scale.
              </p>
            </Panel>

            <div className={s.pair}>
              <Panel title="By primitive" meta="findings per use">
                <BarList
                  labelWidth={120}
                  rows={Object.entries(data.primitive_counts)
                    .sort((a, b) => b[1] - a[1])
                    .map(([name, count]) => ({ key: name, label: titleCase(name), value: count }))}
                />
              </Panel>

              <Panel title="By source collector">
                <BarList
                  labelWidth={110}
                  rows={[
                    ...Object.entries(data.collector_counts)
                      .sort((a, b) => b[1] - a[1])
                      .map(([name, count]) => ({ key: name, label: titleCase(name), value: count })),
                    ...notRun
                      .filter((name) => !(name in data.collector_counts) && !ran.has(name))
                      .map((name) => ({ key: name, label: titleCase(name), value: null, valueText: "off" })),
                  ]}
                />
                <dl className={s.kv}>
                  {scan.mode !== "probe_only" && (
                    <>
                      <dt>Files analysed</dt>
                      <dd>{scan.approved_count.toLocaleString("en-US")}</dd>
                    </>
                  )}
                  {targets > 0 && (
                    <>
                      <dt>Endpoints probed</dt>
                      <dd>{targets}</dd>
                    </>
                  )}
                  <dt>
                    <Link to={`/scans/${scanId}/drift`} className={s.link}>
                      Drift notes
                    </Link>
                  </dt>
                  <dd>
                    {data.alignment.status === "skipped"
                      ? "skipped"
                      : `${data.alignment.note_count} / ${data.alignment.compared_services.length} services`}
                  </dd>
                  {Object.entries(data.source_layer_counts).map(([layer, count]) => (
                    <FragmentKv key={layer} label={`${titleCase(layer)} layer`} value={count} />
                  ))}
                  {took && (
                    <>
                      <dt>Analysis time</dt>
                      <dd>{took}</dd>
                    </>
                  )}
                </dl>
              </Panel>
            </div>

            <div className={s.pair}>
              <Panel
                title="Migration waves"
                meta={
                  <Link to={`/scans/${scanId}/roadmap`} className={s.link}>
                    Open roadmap
                  </Link>
                }
              >
                <BarList
                  labelWidth={190}
                  rows={WAVES.map((wave) => ({
                    key: wave,
                    label: WAVE_LABEL[wave],
                    value: data.wave_counts[wave] ?? 0,
                    tone: WAVE_TONE[wave],
                  }))}
                />
              </Panel>

              <Panel title="Recommendations" meta={`${recTotal} total`} flush>
                <ul className={s.statuses}>
                  {STATUSES.map((status) => (
                    <li key={status} className={s.status}>
                      <SeverityBadge tone={STATUS_TONE[status]}>{STATUS_LABEL[status]}</SeverityBadge>
                      <span className={s.statusCount}>{data.recommendation_counts[status] ?? 0}</span>
                      <span className={s.statusText}>{STATUS_DESCRIPTION[status]}</span>
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>
          </div>

          <div className={s.col}>
            <Panel title="Mosca risk · X + Y vs Z" meta={rescoring ? "re-scoring…" : undefined}>
              <MoscaPanel
                x={x}
                y={y}
                z={z ?? zUsed}
                onZ={onZ}
                packZ={policy.z_years_default}
                subject={data.mosca.subject}
                overdue={data.mosca.overdue}
                unknownPrimitive={data.mosca.unknown_primitive}
                zUsed={zUsed}
              />
            </Panel>

            <Panel title="Exports" flush>
              <ul className={s.exports}>
                <li className={s.export}>
                  <span className={s.exportName}>CycloneDX 1.6 CBOM</span>
                  <a className={s.exportAction} href={api.cbomUrl(scanId)}>
                    Download
                  </a>
                  <span className={s.exportDetail}>{api.cbomUrl(scanId)}</span>
                </li>
                <li className={s.export}>
                  <span className={s.exportName}>PDF report</span>
                  <a className={s.exportAction} href={api.reportUrl(scanId)}>
                    Download
                  </a>
                  <span className={s.exportDetail}>{api.reportUrl(scanId)}</span>
                </li>
                <li className={s.export}>
                  <span className={s.exportName}>HTML report</span>
                  <a className={s.exportAction} href={api.reportHtmlUrl(scanId)} target="_blank" rel="noreferrer">
                    Open
                  </a>
                  <span className={s.exportDetail}>{api.reportHtmlUrl(scanId)} · single file</span>
                </li>
                <li className={s.export}>
                  <span className={s.exportName}>Import CycloneDX CBOM</span>
                  <label className={s.exportAction}>
                    Choose file…
                    <input
                      type="file"
                      accept=".json,application/json"
                      className={s.hiddenInput}
                      onChange={(e) => onImport(e.target.files?.[0])}
                    />
                  </label>
                  <span className={s.exportNote}>
                    {importing ??
                      "Another tool's CycloneDX 1.6 inventory becomes findings here, classified like the native ones."}
                    {data.provenance_count > 0 &&
                      ` ${data.provenance_count} imported CBOM${data.provenance_count === 1 ? "" : "s"} kept as provenance.`}
                  </span>
                </li>
              </ul>
            </Panel>
          </div>
        </div>
      </PageBody>
    </>
  );
}

function FragmentKv({ label, value }: { label: string; value: number }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </>
  );
}

// X + Y against Z, at the scan-wide defaults. Each finding crosses at its own
// X + Y, so the overdue count — from the backend — is what decides; the bars
// only show what the defaults imply.
function MoscaPanel({
  x,
  y,
  z,
  onZ,
  packZ,
  subject,
  overdue,
  unknownPrimitive,
  zUsed,
}: {
  x: number | null;
  y: number;
  z: number;
  onZ: (value: number) => void;
  packZ: number;
  subject: number;
  overdue: number;
  unknownPrimitive: number;
  zUsed: number;
}) {
  const year = new Date().getFullYear();
  const need = (x ?? 0) + y;
  const span = Math.max(10, Math.ceil((Math.max(need, z) * 1.2) / 5) * 5);
  const at = (years: number) => `${(years / span) * 100}%`;
  const ticks = Array.from({ length: 6 }, (_, i) => year + Math.round((span / 5) * i));

  return (
    <>
      <div className={s.moscaRows}>
        <span className={s.moscaLetter}>X</span>
        <span>
          <span className={s.moscaLabel}>Data shelf life</span>
          <span className={s.moscaSub}> · scan default, per file on approval</span>
        </span>
        <span className={s.moscaValue}>{x === null ? "per file" : `${x} y`}</span>

        <span className={s.moscaLetter}>Y</span>
        <span>
          <span className={s.moscaLabel}>Migration time</span>
          <span className={s.moscaSub}> · policy default, per finding</span>
        </span>
        <span className={s.moscaValue}>{y} y</span>

        <span className={s.moscaLetter}>Z</span>
        <span>
          <span className={s.moscaLabel}>Time to CRQC</span>
          <span className={s.moscaSub}> · assumption, pack says {packZ}</span>
        </span>
        <span className={s.moscaValue}>{z} y</span>
      </div>
      <input
        type="range"
        className={s.slider}
        min={1}
        max={40}
        value={z}
        onChange={(e) => onZ(Number(e.target.value))}
        aria-label="Z — years until a quantum computer"
      />

      {x !== null && (
        <div className={s.timeline} aria-hidden="true">
          <div className={s.lane}>
            <span className={`${s.seg} ${s.segY}`} style={{ left: 0, width: at(y) }}>
              Y {y}
            </span>
            <span className={`${s.seg} ${s.segX}`} style={{ left: at(y), width: at(x) }}>
              X {x}
            </span>
          </div>
          <div className={s.lane}>
            <span className={`${s.seg} ${s.segZ}`} style={{ left: 0, width: at(z) }}>
              Z {z}
            </span>
            {need > z && (
              <span className={`${s.seg} ${s.segExposed}`} style={{ left: at(z), width: at(need - z) }}>
                Exposed {need - z} y
              </span>
            )}
          </div>
          <div className={s.axis}>
            {ticks.map((tick) => (
              <span key={tick}>{tick}</span>
            ))}
          </div>
        </div>
      )}

      <div className={s.risk}>
        <div>
          <Caps>Overdue</Caps>
          <div className={s.riskNumber}>{subject > 0 ? overdue : "—"}</div>
        </div>
        <div className={s.riskText}>
          {subject > 0 ? (
            <>
              <span>
                <SeverityBadge tone={overdue > 0 ? "critical" : "safe"} marker={false}>
                  {overdue > 0 ? "Overdue · X + Y > Z" : "Not overdue · X + Y ≤ Z"}
                </SeverityBadge>
              </span>
              <span>
                {overdue} of {subject} finding{subject === 1 ? "" : "s"} subject to Mosca at Z = {zUsed}. Only
                quantum-vulnerable key exchanges and ciphers move with Z.
              </span>
            </>
          ) : (
            <span>
              Nothing in this scan moves with Z: it has no quantum-vulnerable key exchange or cipher findings.
              {unknownPrimitive > 0 &&
                ` ${unknownPrimitive} quantum-vulnerable finding${unknownPrimitive === 1 ? "" : "s"} of unknown use sit in Verify.`}
            </span>
          )}
        </div>
      </div>
    </>
  );
}
