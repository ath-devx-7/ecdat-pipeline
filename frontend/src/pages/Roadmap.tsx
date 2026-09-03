import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type RecommendationStatus, type Roadmap as RoadmapData, type RoadmapItem } from "../api";
import {
  STATUS_BADGE,
  STATUS_LABEL,
  VERDICT_BADGE,
  VERDICT_LABEL,
  WAVE_COLOR,
  WAVE_DESCRIPTION,
  WAVE_LABEL,
  WAVES,
  describeAlgorithm,
  titleCase,
} from "../lib/labels";

// §13 screen 6. Waves, not a sorted list: each wave is a block of work that can
// start together. Every item carries its target, its prerequisites in the
// order they have to be cleared, and the action class that sizes the job.

export default function Roadmap() {
  const { scanId = "" } = useParams();
  const [data, setData] = useState<RoadmapData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.roadmap(scanId).then(setData).catch((err) => setError(err.message));
  }, [scanId]);

  if (error) return <div className="card text-sm text-red-800">{error}</div>;
  if (!data) return <div className="text-sm text-slate-500">Loading…</div>;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-semibold">Roadmap</h1>
        <span className="text-sm text-slate-600">
          scored at Z = {data.z_years_used ?? "—"} ·{" "}
          <Link to={`/scans/${scanId}`} className="underline">
            move the slider on the overview
          </Link>{" "}
          · {data.unscored} findings need no migration
        </span>
      </div>

      {WAVES.map((wave) => (
        <section key={wave} className="card">
          <div className="mb-1 flex items-baseline gap-3">
            <span className="inline-block h-3 w-3 rounded-sm" style={{ background: WAVE_COLOR[wave] }} />
            <h2 className="font-semibold">{WAVE_LABEL[wave]}</h2>
            <span className="text-sm text-slate-600">{data.wave_counts[wave]} findings</span>
          </div>
          <p className="mb-3 text-xs text-slate-500">{WAVE_DESCRIPTION[wave]}</p>
          {data.waves[wave].length === 0 ? (
            <p className="text-sm text-slate-500">Empty.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {data.waves[wave].map((item) => (
                <Item key={item.finding.id} item={item} scanId={scanId} />
              ))}
            </ul>
          )}
        </section>
      ))}
    </div>
  );
}

function Item({ item, scanId }: { item: RoadmapItem; scanId: string }) {
  return (
    <li className="grid gap-2 py-2 text-sm md:grid-cols-3">
      <div>
        <div className="font-medium">
          {describeAlgorithm(item.finding)}{" "}
          <span className="text-xs font-normal text-slate-500">{titleCase(item.finding.primitive)}</span>
        </div>
        <div className="font-mono text-xs text-slate-600">{item.finding.evidence_location}</div>
        <div className="mt-1 text-xs">
          {item.verdict && <span className={`badge mr-1 ${VERDICT_BADGE[item.verdict]}`}>{VERDICT_LABEL[item.verdict]}</span>}
          {item.urgency_years !== null ? (
            <span className="text-slate-600">overdue by {item.urgency_years} years</span>
          ) : (
            <span className="text-slate-500">Mosca not applied</span>
          )}
        </div>
      </div>
      <div className="md:col-span-2">
        {item.recommendations.length === 0 && (
          <span className="text-xs text-slate-500">
            No recommendation row — the verdict is not a migration item.
          </span>
        )}
        {item.recommendations.map((rec) => (
          <div key={rec.id} className="mb-1 rounded border border-slate-200 p-2 text-xs">
            <span className={`badge ${STATUS_BADGE[rec.status as RecommendationStatus]}`}>{STATUS_LABEL[rec.status]}</span>{" "}
            {rec.target ? <strong>{rec.target}</strong> : <em>no target</em>}
            {rec.hybrid_target && rec.hybrid_target !== rec.target && (
              <span className="text-slate-600"> · hybrid {rec.hybrid_target}</span>
            )}
            {rec.action_class && <span className="text-slate-600"> · {titleCase(rec.action_class)}</span>}
            {rec.prerequisites && rec.prerequisites.length > 0 && (
              <ol className="mt-1 list-decimal pl-4">
                {rec.prerequisites.map((p, index) => (
                  <li key={index}>
                    <code>{p.unmet}</code> — observed {p.observed ?? <em>nothing</em>}
                    {p.observed_at && <span className="text-slate-500"> at {p.observed_at}</span>}
                    {p.note && <span className="text-slate-500"> · {p.note}</span>}
                  </li>
                ))}
              </ol>
            )}
            {rec.side_effects && <div className="mt-1 text-slate-700">{rec.side_effects}</div>}
            <div className="text-slate-500">{rec.source_citation}</div>
          </div>
        ))}
        <Link to={`/scans/${scanId}/findings?q=${encodeURIComponent(item.finding.evidence_location ?? "")}`} className="text-xs underline">
          open in findings
        </Link>
      </div>
    </li>
  );
}
