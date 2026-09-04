import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  type BlockedChain,
  type RecommendationStatus,
  type Roadmap as RoadmapData,
  type RoadmapItem,
} from "../api";
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
//
// Above them, the same blocked rows counted by work rather than by finding. A
// blocked count scales with how thoroughly the scan searched; forty rows behind
// one "upgrade OpenSSL, then enable TLS 1.3" are one procurement item and one
// config line, and that is the number someone planning the migration needs.
// Beside the per-finding rows, never instead of them.

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

      <Blockers chains={data.blocked_chains} />

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
              {groupItems(data.waves[wave]).map((group) => (
                <Item key={group.item.finding.id} group={group} scanId={scanId} />
              ))}
            </ul>
          )}
        </section>
      ))}
    </div>
  );
}

function Blockers({ chains }: { chains: BlockedChain[] }) {
  if (chains.length === 0) return null;
  const held = chains.reduce((total, chain) => total + chain.finding_count, 0);
  return (
    <section className="card">
      <div className="mb-1 flex items-baseline gap-3">
        <h2 className="font-semibold">What is standing in the way</h2>
        <span className="text-sm text-slate-600">
          {chains.length} distinct {chains.length === 1 ? "chain" : "chains"} holding {held}{" "}
          {held === 1 ? "finding" : "findings"}
        </span>
      </div>
      <p className="mb-3 text-xs text-slate-500">
        The blocked rows below, grouped by the work they are waiting on and ordered with the
        long-lead item first. Clearing one row clears every finding behind it.
      </p>
      <ul className="divide-y divide-slate-100">
        {chains.map((chain, index) => (
          <li key={index} className="grid gap-2 py-2 text-sm md:grid-cols-3">
            <div className="md:col-span-2">
              <ol className="list-decimal pl-4 text-xs">
                {chain.prerequisites.map((p, position) => (
                  <li key={position}>
                    <code>{p.unmet}</code> — observed {p.observed ?? <em>nothing</em>}
                  </li>
                ))}
              </ol>
            </div>
            <div className="text-xs">
              <div className="font-medium">
                {chain.finding_count} {chain.finding_count === 1 ? "finding" : "findings"}
              </div>
              <div className="font-mono text-slate-600">{chain.assets.join(", ")}</div>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}

// One `AES.new(...)` call is not an asset; a file's use of AES is. A library
// that calls it 62 times in one module has one thing to change there, and 62
// identical rows bury every row that is not identical. The grouping is a
// presentation choice only — /roadmap still returns every finding, the findings
// table still lists them, and the count on each row says how many there were.
type ItemGroup = { item: RoadmapItem; occurrences: number; lines: string[] };

function groupItems(items: RoadmapItem[]): ItemGroup[] {
  const groups = new Map<string, ItemGroup>();
  for (const item of items) {
    const location = item.finding.evidence_location ?? "";
    const cut = location.lastIndexOf(":");
    const file = cut > 0 ? location.slice(0, cut) : location;
    const line = cut > 0 ? location.slice(cut + 1) : "";
    // Anything that would read differently keeps its own row.
    const key = [
      describeAlgorithm(item.finding),
      item.finding.algorithm_name,
      item.finding.primitive,
      item.finding.source_layer,
      file,
      item.verdict ?? "",
      item.urgency_years ?? "",
      item.recommendations.map((r) => `${r.status}:${r.target ?? ""}`).join("|"),
    ].join("\u0000");

    const existing = groups.get(key);
    if (existing) {
      existing.occurrences += 1;
      if (line) existing.lines.push(line);
    } else {
      groups.set(key, { item, occurrences: 1, lines: line ? [line] : [] });
    }
  }
  return [...groups.values()];
}

function Item({ group, scanId }: { group: ItemGroup; scanId: string }) {
  const { item, occurrences, lines } = group;
  const location = item.finding.evidence_location ?? "";
  const cut = location.lastIndexOf(":");
  const file = cut > 0 ? location.slice(0, cut) : location;
  return (
    <li className="grid gap-2 py-2 text-sm md:grid-cols-3">
      <div>
        <div className="font-medium">
          {describeAlgorithm(item.finding)}{" "}
          <span className="text-xs font-normal text-slate-500">{titleCase(item.finding.primitive)}</span>
        </div>
        <div className="font-mono text-xs text-slate-600">
          {occurrences > 1 ? file : item.finding.evidence_location}
        </div>
        {occurrences > 1 && (
          <div className="text-xs text-slate-500">
            <strong>{occurrences} uses</strong> · lines {lines.slice(0, 6).join(", ")}
            {lines.length > 6 && ` and ${lines.length - 6} more`}
          </div>
        )}
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
        <Link to={`/scans/${scanId}/findings?q=${encodeURIComponent(occurrences > 1 ? file : item.finding.evidence_location ?? "")}`} className="text-xs underline">
          open in findings
        </Link>
      </div>
    </li>
  );
}
