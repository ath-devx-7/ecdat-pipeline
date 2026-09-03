import { useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { api, type FindingDetail, type FindingPage, type RecommendationStatus, type Verdict, type Wave } from "../api";
import {
  STATUS_BADGE,
  STATUS_LABEL,
  VERDICT_BADGE,
  VERDICT_LABEL,
  WAVE_SHORT,
  describeAlgorithm,
  titleCase,
} from "../lib/labels";

// §13 screen 4. Filters are the URL, so a filtered view can be linked to; the
// facets come from the scan itself, so a filter never offers a value that
// selects nothing. Clicking a row opens the whole rationale and the raw
// evidence — a verdict without its citation is an opinion.

const FILTERS = ["verdict", "wave", "collector", "confidence", "source_layer"] as const;

export default function Findings() {
  const { scanId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const [page, setPage] = useState<FindingPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<FindingDetail | null>(null);
  const query = params.toString();

  useEffect(() => {
    api
      .findings(scanId, new URLSearchParams(query))
      .then(setPage)
      .catch((err) => setError(err.message));
  }, [scanId, query]);

  const active = useMemo(() => {
    const chosen: Record<string, Set<string>> = {};
    for (const key of FILTERS) chosen[key] = new Set(params.getAll(key));
    return chosen;
  }, [params]);

  function toggle(key: string, value: string) {
    const next = new URLSearchParams(params);
    const values = new Set(next.getAll(key));
    next.delete(key);
    if (values.has(value)) values.delete(value);
    else values.add(value);
    for (const item of values) next.append(key, item);
    next.delete("offset");
    setParams(next);
  }

  function search(text: string) {
    const next = new URLSearchParams(params);
    if (text) next.set("q", text);
    else next.delete("q");
    setParams(next);
  }

  if (error) return <div className="card text-sm text-red-800">{error}</div>;
  if (!page) return <div className="text-sm text-slate-500">Loading…</div>;

  return (
    <div className="space-y-4">
      <div className="card space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-xl font-semibold">Findings</h1>
          <span className="text-sm text-slate-600">
            {page.total} shown
            {query && (
              <button className="ml-2 text-xs underline" onClick={() => setParams(new URLSearchParams())}>
                clear filters
              </button>
            )}
          </span>
          <input
            className="input ml-auto max-w-xs"
            placeholder="Search name, family or location"
            defaultValue={params.get("q") ?? ""}
            onKeyDown={(e) => {
              if (e.key === "Enter") search((e.target as HTMLInputElement).value.trim());
            }}
          />
        </div>
        <div className="grid gap-3 md:grid-cols-5">
          {FILTERS.map((key) => (
            <div key={key}>
              <div className="label">{titleCase(key)}</div>
              <div className="flex flex-wrap gap-1">
                {(page.facets[key] ?? []).map((value) => {
                  const on = active[key].has(value);
                  return (
                    <button
                      key={value}
                      type="button"
                      onClick={() => toggle(key, value)}
                      className={`rounded border px-2 py-0.5 text-xs ${
                        on ? "border-slate-900 bg-slate-900 text-white" : "border-slate-300 bg-white text-slate-700"
                      }`}
                    >
                      {key === "verdict"
                        ? VERDICT_LABEL[value as Verdict]
                        : key === "wave"
                          ? WAVE_SHORT[value as Wave]
                          : titleCase(value)}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className={`card overflow-x-auto ${open ? "lg:col-span-2" : "lg:col-span-3"}`}>
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-1 pr-3">Algorithm</th>
                <th className="py-1 pr-3">Primitive</th>
                <th className="py-1 pr-3">Verdict</th>
                <th className="py-1 pr-3">Wave</th>
                <th className="py-1 pr-3">Advice</th>
                <th className="py-1 pr-3">Collector</th>
                <th className="py-1 pr-3">Layer</th>
                <th className="py-1 pr-3">Conf.</th>
                <th className="py-1 pr-3">Location</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => setOpen(open?.id === finding.id ? null : finding)}
                  className={`cursor-pointer border-t border-slate-100 hover:bg-slate-50 ${
                    open?.id === finding.id ? "bg-slate-100" : ""
                  }`}
                >
                  <td className="py-1 pr-3 font-medium">
                    {describeAlgorithm(finding)}
                    {finding.algorithm_family && finding.algorithm_family !== finding.algorithm_name && (
                      <div className="text-xs font-normal text-slate-500">as {finding.algorithm_name}</div>
                    )}
                  </td>
                  <td className="py-1 pr-3">{titleCase(finding.primitive)}</td>
                  <td className="py-1 pr-3">
                    {finding.verdict && (
                      <span className={`badge ${VERDICT_BADGE[finding.verdict.verdict]}`}>
                        {VERDICT_LABEL[finding.verdict.verdict]}
                      </span>
                    )}
                  </td>
                  <td className="py-1 pr-3">{finding.risk ? WAVE_SHORT[finding.risk.wave] : "—"}</td>
                  <td className="py-1 pr-3">
                    {finding.recommendations.map((rec) => (
                      <span key={rec.id} className={`badge mr-1 ${STATUS_BADGE[rec.status as RecommendationStatus]}`}>
                        {rec.target ?? STATUS_LABEL[rec.status]}
                      </span>
                    ))}
                  </td>
                  <td className="py-1 pr-3">{finding.collector}</td>
                  <td className="py-1 pr-3">{finding.source_layer}</td>
                  <td className="py-1 pr-3">{finding.confidence}</td>
                  <td className="py-1 pr-3 font-mono text-xs">{finding.evidence_location}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {page.items.length === 0 && <p className="py-4 text-sm text-slate-500">Nothing matches these filters.</p>}
        </div>
        {open && <Detail finding={open} onClose={() => setOpen(null)} />}
      </div>
    </div>
  );
}

function Detail({ finding, onClose }: { finding: FindingDetail; onClose: () => void }) {
  return (
    <div className="card space-y-3 text-sm lg:col-span-1">
      <div className="flex items-start justify-between">
        <h2 className="font-semibold">{describeAlgorithm(finding)}</h2>
        <button className="text-xs underline" onClick={onClose}>
          close
        </button>
      </div>
      <dl className="grid grid-cols-3 gap-x-2 gap-y-1 text-xs">
        <dt className="text-slate-500">Observed as</dt>
        <dd className="col-span-2 font-mono">{finding.algorithm_name}</dd>
        <dt className="text-slate-500">OID</dt>
        <dd className="col-span-2 font-mono">{finding.algorithm_oid ?? "—"}</dd>
        <dt className="text-slate-500">Location</dt>
        <dd className="col-span-2 font-mono">{finding.evidence_location}</dd>
        <dt className="text-slate-500">Collector</dt>
        <dd className="col-span-2">
          {finding.collector} · {finding.source_layer} · {finding.confidence} confidence
        </dd>
      </dl>

      <section>
        <div className="label">Verdict</div>
        {finding.verdict ? (
          <div>
            <span className={`badge ${VERDICT_BADGE[finding.verdict.verdict]}`}>
              {VERDICT_LABEL[finding.verdict.verdict]}
            </span>
            <div className="mt-1 text-xs">
              rule <code>{finding.verdict.rule_id ?? "—"}</code> · pack {finding.verdict.policy_version}
            </div>
            <div className="mt-1 text-xs text-slate-700">{finding.verdict.source_citation}</div>
          </div>
        ) : (
          <p className="text-xs text-slate-500">not classified</p>
        )}
      </section>

      <section>
        <div className="label">Risk</div>
        {finding.risk ? (
          <div className="text-xs">
            <div>
              <strong>{WAVE_SHORT[finding.risk.wave]}</strong>
              {finding.risk.urgency_years !== null && <> · overdue by {finding.risk.urgency_years} years</>}
            </div>
            <div className="text-slate-600">
              X = {finding.risk.x_years ?? "—"}, Y = {finding.risk.y_years}, Z = {finding.risk.z_years}
              {finding.risk.urgency_years === null && " · Mosca not applied"}
            </div>
            {finding.risk.rationale && typeof finding.risk.rationale.because === "string" && (
              <div className="mt-1 text-slate-700">{finding.risk.rationale.because}</div>
            )}
          </div>
        ) : (
          <p className="text-xs text-slate-500">no wave — needs no migration</p>
        )}
      </section>

      <section>
        <div className="label">Recommendations</div>
        {finding.recommendations.length === 0 && <p className="text-xs text-slate-500">none</p>}
        {finding.recommendations.map((rec) => (
          <div key={rec.id} className="mb-2 rounded border border-slate-200 p-2 text-xs">
            <span className={`badge ${STATUS_BADGE[rec.status as RecommendationStatus]}`}>{STATUS_LABEL[rec.status]}</span>{" "}
            {rec.target && <strong>{rec.target}</strong>}
            {rec.hybrid_target && rec.hybrid_target !== rec.target && <> (hybrid {rec.hybrid_target})</>}
            {rec.action_class && <div className="text-slate-600">action: {titleCase(rec.action_class)}</div>}
            {rec.prerequisites && rec.prerequisites.length > 0 && (
              <ol className="mt-1 list-decimal pl-4">
                {rec.prerequisites.map((p, index) => (
                  <li key={index}>
                    <code>{p.unmet}</code> — observed {p.observed ?? <em>nothing</em>}
                    {p.observed_at && <span className="text-slate-500"> at {p.observed_at}</span>}
                    {p.note && <div className="text-slate-500">{p.note}</div>}
                  </li>
                ))}
              </ol>
            )}
            {rec.side_effects && <div className="mt-1 text-slate-700">{rec.side_effects}</div>}
            <div className="mt-1 text-slate-500">{rec.source_citation}</div>
          </div>
        ))}
      </section>

      <section>
        <div className="label">Evidence</div>
        <pre className="max-h-80 overflow-auto rounded bg-slate-900 p-2 text-xs text-slate-100">
          {JSON.stringify(finding.evidence_raw, null, 2)}
        </pre>
      </section>
    </div>
  );
}
