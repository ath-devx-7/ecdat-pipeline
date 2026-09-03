import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, zStorageKey, type Overview as OverviewData } from "../api";
import { VerdictChart, WaveChart } from "../components/Charts";
import {
  STATUS_BADGE,
  STATUS_DESCRIPTION,
  STATUS_LABEL,
  STATUSES,
  titleCase,
} from "../lib/labels";

// §13 screen 3. The readiness number is shown with its denominator and the
// unassessed count beside it; the four recommendation statuses are always four
// tiles; and the Z slider re-scores the scan live, because Z is an assumption.

export default function Overview() {
  const { scanId = "" } = useParams();
  const [data, setData] = useState<OverviewData | null>(null);
  const [error, setError] = useState<string | null>(null);
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
        // The New-scan screen remembered a Z for this scan; apply it once.
        const remembered = localStorage.getItem(zStorageKey(scanId));
        const wanted = remembered ? Number(remembered) : null;
        if (wanted !== null && loaded.z_years_used !== null && wanted !== loaded.z_years_used) {
          await api.rescore(scanId, wanted);
          localStorage.removeItem(zStorageKey(scanId));
          await load();
          setZ(wanted);
        } else {
          setZ(loaded.z_years_used ?? loaded.policy.z_years_default);
        }
      })
      .catch((err) => setError(err.message));
  }, [scanId, load]);

  function onZ(value: number) {
    setZ(value);
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(async () => {
      setRescoring(true);
      try {
        await api.rescore(scanId, value);
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

  if (error) return <div className="card text-sm text-red-800">{error}</div>;
  if (!data) return <div className="text-sm text-slate-500">Loading…</div>;

  const { scan, readiness, policy } = data;

  return (
    <div className="space-y-4">
      <div className="card flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h1 className="text-xl font-semibold">
          {scan.source_ref ?? scan.probe_targets?.map((t) => `${t.host}:${t.port}`).join(", ")}
        </h1>
        <span className="text-sm text-slate-600">
          {titleCase(scan.mode)} · <StatusWord status={scan.status} /> · {data.finding_count} findings
          {scan.data_lifetime_years !== null && <> · X = {scan.data_lifetime_years} years</>}
        </span>
        <div className="ml-auto flex items-center gap-2 text-sm">
          <a className="btn" href={api.reportUrl(scanId)}>
            PDF report
          </a>
          <a className="btn-secondary" href={api.reportHtmlUrl(scanId)} target="_blank" rel="noreferrer">
            HTML
          </a>
          <a className="btn-secondary" href={api.cbomUrl(scanId)}>
            Export CycloneDX
          </a>
          <label className="btn-secondary cursor-pointer">
            Import CBOM
            <input
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={(e) => onImport(e.target.files?.[0])}
            />
          </label>
        </div>
        {importing && <div className="w-full text-xs text-slate-600">{importing}</div>}
        {scan.status === "partial" && (
          <div className="w-full rounded-md bg-amber-50 p-2 text-xs text-amber-900">
            This scan is <strong>partial</strong>: at least one collector failed or ran out of
            budget. The findings below are incomplete, not wrong.
          </div>
        )}
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <div className="card md:col-span-1">
          <div className="label">PQC readiness</div>
          <div className="text-4xl font-bold">
            {readiness.percent === null ? "—" : `${readiness.percent}%`}
          </div>
          <div className="mt-1 text-xs text-slate-600">
            {readiness.assessed} findings assessed
            <br />
            {readiness.quantum_vulnerable} quantum-vulnerable · {readiness.broken_now} broken now
          </div>
          <div className="mt-2 text-xs text-slate-500">
            <strong>{readiness.unassessed} unassessed</strong> findings are not in this number. Not
            assessed is neither safe nor vulnerable.
          </div>
        </div>
        <div className="card md:col-span-3">
          <div className="label">Recommendations — all four statuses</div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {STATUSES.map((status) => (
              <div key={status} className="rounded-md border border-slate-200 p-2">
                <span className={`badge ${STATUS_BADGE[status]}`}>{STATUS_LABEL[status]}</span>
                <div className="mt-1 text-2xl font-semibold">{data.recommendation_counts[status] ?? 0}</div>
                <div className="text-xs text-slate-500">{STATUS_DESCRIPTION[status]}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="card">
          <div className="label">Verdicts</div>
          <VerdictChart counts={data.verdict_counts} />
          <p className="text-xs text-slate-500">
            Broken-now and quantum-vulnerable are independent classifications, not two points on one
            scale. RSA-4096 is secure today and vulnerable tomorrow; MD5 is broken today and irrelevant
            to quantum.
          </p>
        </div>
        <div className="card">
          <div className="flex items-baseline justify-between">
            <div className="label">Migration waves</div>
            <Link to={`/scans/${scanId}/roadmap`} className="text-xs underline">
              Roadmap
            </Link>
          </div>
          <WaveChart counts={data.wave_counts} />
          <div className="mt-2">
            <label className="label" htmlFor="z">
              Z — years until a quantum computer: <span className="text-slate-900">{z ?? "…"}</span>
              {rescoring && <span className="ml-2 font-normal normal-case text-slate-500">re-scoring…</span>}
            </label>
            <input
              id="z"
              type="range"
              min={1}
              max={40}
              value={z ?? policy.z_years_default}
              onChange={(e) => onZ(Number(e.target.value))}
              className="w-full"
            />
            <p className="text-xs text-slate-500">
              Mosca: (X + Y) − Z &gt; 0 means overdue. Y = {policy.y_years_default} (migration
              duration, from the pack). Move Z and the waves move with it; wave 0 does not, because
              broken today is not a quantum deadline.
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="card">
          <div className="flex items-baseline justify-between">
            <div className="label">Drift</div>
            <Link to={`/scans/${scanId}/drift`} className="text-xs underline">
              Details
            </Link>
          </div>
          {data.alignment.status === "skipped" ? (
            <p className="text-sm">
              <span className="badge bg-slate-200 text-slate-700">Skipped</span>{" "}
              <span className="text-slate-600">{data.alignment.reason}</span>
            </p>
          ) : (
            <p className="text-sm">
              <span className={`badge ${data.alignment.note_count ? "bg-amber-100 text-amber-800" : "bg-green-100 text-green-800"}`}>
                {data.alignment.note_count} note{data.alignment.note_count === 1 ? "" : "s"}
              </span>{" "}
              <span className="text-slate-600">
                over {data.alignment.compared_services.length} probed service
                {data.alignment.compared_services.length === 1 ? "" : "s"}
              </span>
            </p>
          )}
        </div>
        <div className="card">
          <div className="label">Where findings came from</div>
          <CountList counts={data.collector_counts} />
          <div className="label mt-3">Source layers</div>
          <CountList counts={data.source_layer_counts} />
        </div>
        <div className="card">
          <div className="label">Policy pack</div>
          <div className="text-sm">
            <div>
              <strong>{policy.version}</strong> · published {policy.published} · {policy.age_days} days old
            </div>
            <div className="text-slate-600">
              {policy.algorithm_rule_count} verdict rules · {policy.pqc_target_count} migration targets ·
              hybrid {policy.prefer_hybrid ? "preferred" : "not preferred"}
            </div>
            {policy.stale ? (
              <div className="mt-1 rounded bg-amber-50 p-1 text-xs text-amber-900">
                Older than {policy.staleness_warning_days} days — carry in a newer pack.
              </div>
            ) : (
              <div className="mt-1 text-xs text-slate-500">
                Within the {policy.staleness_warning_days}-day staleness window.
              </div>
            )}
            {scan.policy_version && scan.policy_version !== policy.version && (
              <div className="mt-1 text-xs text-amber-900">
                Scanned under pack {scan.policy_version}; verdicts were re-computed under {policy.version}.
              </div>
            )}
            {data.provenance_count > 0 && (
              <div className="mt-1 text-xs text-slate-500">
                {data.provenance_count} imported CBOM{data.provenance_count === 1 ? "" : "s"} kept as provenance.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function CountList({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return <p className="text-xs text-slate-500">none</p>;
  return (
    <ul className="text-sm">
      {entries.map(([name, count]) => (
        <li key={name} className="flex justify-between">
          <span>{titleCase(name)}</span>
          <span className="font-mono text-xs">{count}</span>
        </li>
      ))}
    </ul>
  );
}

export function StatusWord({ status }: { status: string }) {
  const tone =
    status === "complete"
      ? "text-green-700"
      : status === "partial"
        ? "text-amber-700"
        : status === "failed"
          ? "text-red-700"
          : "text-slate-700";
  return <span className={`font-medium ${tone}`}>{titleCase(status)}</span>;
}
