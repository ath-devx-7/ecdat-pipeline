import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Roadmap as RoadmapData, type RoadmapItem, type Wave } from "../api";
import { PageBody, PageHeader, shortId } from "../components/ui/AppShell";
import { DataTable, type Column, type TableSection } from "../components/ui/DataTable";
import { Icon } from "../components/ui/Icon";
import { Banner, buttonClass, Caps, Panel, SeverityBadge } from "../components/ui/primitives";
import { StatePanel } from "../components/ui/StatePanel";
import { toneVars } from "../components/ui/tone";
import {
  STATUS_LABEL,
  STATUS_TONE,
  WAVE_DESCRIPTION,
  WAVE_LABEL,
  WAVE_SHORT,
  WAVE_TONE,
  WAVES,
  describeAlgorithm,
  titleCase,
} from "../lib/labels";
import s from "./Roadmap.module.css";

// §13 screen 6. Waves, not a sorted list: each wave is a block of work that can
// start together. Every item carries its target, its prerequisites in the
// order they have to be cleared, and the action class that sizes the job.
//
// Above them, the same blocked rows counted by work rather than by finding. A
// blocked count scales with how thoroughly the scan searched; forty rows behind
// one "upgrade OpenSSL, then enable TLS 1.3" are one procurement item and one
// config line, and that is the number someone planning the migration needs.
// Beside the per-finding rows, never instead of them.

// One `AES.new(...)` call is not an asset; a file's use of AES is. A library
// that calls it 62 times in one module has one thing to change there, and 62
// identical rows bury every row that is not identical. The grouping is a
// presentation choice only — /roadmap still returns every finding, the findings
// table still lists them, and the count on each row says how many there were.
type ItemGroup = { item: RoadmapItem; occurrences: number; lines: string[]; file: string; wave: Wave; index: number };

// The scorer stores every Mosca input on the row and the provenance of the two
// that are assumptions. Read as recorded, never relabelled: the rationale is an
// audit trail, and a prettified value is no longer the value that was stored.
function mosca(rationale: Record<string, unknown> | null, key: string): number | null {
  const value = rationale?.[key];
  return typeof value === "number" ? value : null;
}

function source(rationale: Record<string, unknown> | null, key: string): string | null {
  const value = rationale?.[key];
  return typeof value === "string" ? value : null;
}

function groupItems(items: RoadmapItem[], wave: Wave): Omit<ItemGroup, "index">[] {
  const groups = new Map<string, Omit<ItemGroup, "index">>();
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
      // X varies per asset now, so two findings sharing a file but scored at
      // different lifetimes are two rows, not one collapsed row.
      String(mosca(item.rationale, "x_years")),
      item.recommendations.map((r) => `${r.status}:${r.target ?? ""}`).join("|"),
    ].join("\u0000");

    const existing = groups.get(key);
    if (existing) {
      existing.occurrences += 1;
      if (line) existing.lines.push(line);
    } else {
      groups.set(key, { item, occurrences: 1, lines: line ? [line] : [], file, wave });
    }
  }
  return [...groups.values()];
}

// "Wave 0 — broken today" → ["Wave 0", "Broken today"]
function splitLabel(wave: Wave): [string, string] {
  const [head, tail = ""] = WAVE_LABEL[wave].split(" — ");
  return [head, tail.charAt(0).toUpperCase() + tail.slice(1)];
}

export default function Roadmap() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState<RoadmapData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState<Set<Wave>>(new Set());

  useEffect(() => {
    api.roadmap(scanId).then(setData).catch((err) => setError(err.message));
  }, [scanId]);

  // Rows numbered once, in wave order, so "#7" names the same item however
  // the groups are opened and closed.
  const groups = useMemo(() => {
    if (!data) return {} as Record<Wave, ItemGroup[]>;
    let n = 0;
    const out = {} as Record<Wave, ItemGroup[]>;
    for (const wave of WAVES) {
      out[wave] = groupItems(data.waves[wave], wave).map((group) => ({ ...group, index: ++n }));
    }
    return out;
  }, [data]);

  const findingsLink = (group: ItemGroup) =>
    `/scans/${scanId}/findings?q=${encodeURIComponent(group.occurrences > 1 ? group.file : (group.item.finding.evidence_location ?? ""))}`;

  const columns: Column<ItemGroup>[] = [
    { key: "n", header: "#", width: 44, skeletonWidth: 14, render: (g) => <span className={s.num}>{g.index}</span> },
    {
      key: "asset",
      header: "Asset",
      skeletonWidth: 160,
      render: (g) => (
        <span className={s.asset}>
          <span className={s.assetName} title={describeAlgorithm(g.item.finding)}>
            {describeAlgorithm(g.item.finding)}{" "}
            <span className={s.groupMeta}>{titleCase(g.item.finding.primitive)}</span>
          </span>
          <span className={s.assetLoc} title={g.item.finding.evidence_location ?? undefined}>
            {g.occurrences > 1
              ? `${g.file} · ${g.occurrences} uses · lines ${g.lines.slice(0, 6).join(", ")}${g.lines.length > 6 ? ` +${g.lines.length - 6}` : ""}`
              : g.item.finding.evidence_location}
          </span>
        </span>
      ),
    },
    {
      key: "current",
      header: "Current",
      width: 140,
      skeletonWidth: 90,
      render: (g) => (
        <span className={s.stack}>
          <span className={s.mono} title={g.item.finding.algorithm_name}>
            {g.item.finding.algorithm_name}
          </span>
          <span className={s.subSans}>{titleCase(g.item.finding.source_layer)} · {g.item.finding.confidence}</span>
        </span>
      ),
    },
    {
      key: "target",
      header: "Target",
      width: 190,
      skeletonWidth: 130,
      render: (g) => {
        const rec = g.item.recommendations[0];
        if (!rec) return <span className={s.subSans}>No recommendation row</span>;
        return (
          <span className={s.stack}>
            <span className={rec.target ? s.target : s.subSans} title={rec.target ?? undefined}>
              {rec.target ?? "no target"}
            </span>
            {rec.hybrid_target && rec.hybrid_target !== rec.target && (
              <span className={s.sub}>hybrid {rec.hybrid_target}</span>
            )}
          </span>
        );
      },
    },
    {
      key: "mosca",
      header: "Mosca",
      width: 100,
      align: "right",
      skeletonWidth: 40,
      render: (g) => {
        const r = g.item.rationale;
        // The inputs beside the answer. X and Y both vary per finding, so
        // "overdue by 9 years" on its own no longer says which assumption
        // produced it.
        const inputs = `X${mosca(r, "x_years") ?? "—"} Y${mosca(r, "y_years") ?? "—"} Z${mosca(r, "z_years") ?? "—"}`;
        const provenance = [source(r, "x_source") && `X from ${source(r, "x_source")}`, source(r, "y_source") && `Y from ${source(r, "y_source")}`]
          .filter(Boolean)
          .join("\n");
        return (
          <span className={s.mosca} title={provenance || undefined}>
            <span className={s.moscaValue}>{g.item.urgency_years !== null ? `+${g.item.urgency_years} y` : "—"}</span>
            <span className={s.sub}>{g.item.urgency_years !== null ? inputs : "not applied"}</span>
          </span>
        );
      },
    },
    {
      key: "effort",
      header: "Effort",
      width: 116,
      skeletonWidth: 30,
      render: (g) => {
        const action = g.item.recommendations[0]?.action_class;
        return action ? <span className={s.effort}>{titleCase(action)}</span> : <span className={s.subSans}>—</span>;
      },
    },
    {
      key: "status",
      header: "Status",
      width: 230,
      skeletonWidth: 70,
      render: (g) => {
        const rec = g.item.recommendations[0];
        if (!rec) return <span className={s.subSans}>The verdict is not a migration item</span>;
        const first = rec.prerequisites?.[0];
        return (
          <span className={s.status}>
            <SeverityBadge tone={STATUS_TONE[rec.status]}>{STATUS_LABEL[rec.status]}</SeverityBadge>
            <span className={s.subSans} title={rec.side_effects ?? undefined}>
              {first
                ? `${first.unmet} — observed ${first.observed ?? "nothing"}${(rec.prerequisites?.length ?? 0) > 1 ? ` (+${rec.prerequisites!.length - 1})` : ""}`
                : (rec.side_effects ?? (rec.action_class ? titleCase(rec.action_class) : ""))}
            </span>
          </span>
        );
      },
    },
    {
      key: "refs",
      header: "References",
      width: 150,
      skeletonWidth: 80,
      render: (g) => <span className={s.refs}>{g.item.recommendations[0]?.source_citation ?? "—"}</span>,
    },
  ];

  const header = (subtitle: string) => (
    <PageHeader
      title="Roadmap"
      subtitle={subtitle}
      actions={
        <Link to={`/scans/${scanId}`} className={buttonClass("secondary")}>
          Mosca inputs
        </Link>
      }
    />
  );

  if (error) {
    return (
      <>
        {header("PQC migration plan ordered by Mosca urgency.")}
        <PageBody>
          <StatePanel variant="error" tag="Roadmap not generated" meta={shortId(scanId)} title="The migration plan could not be loaded" log={[error]} />
        </PageBody>
      </>
    );
  }

  // ---- scoring / loading ----
  if (!data) {
    return (
      <>
        {header("Loading the migration plan…")}
        <PageBody>
          <div className={s.cards}>
            {WAVES.map((wave) => {
              const [head, title] = splitLabel(wave);
              return (
                <div key={wave} className={s.card} style={toneVars(WAVE_TONE[wave])}>
                  <span className={s.cardHead}>
                    <span className={s.cardSquare} aria-hidden="true" />
                    <Caps>{head}</Caps>
                    <span className={s.cardTitle}>{title}</span>
                  </span>
                  <span className={s.skeletonCard}>— loading…</span>
                </div>
              );
            })}
            <div className={s.card}>
              <Caps>Blocking prerequisites</Caps>
              <span className={s.skeletonCard}>computed with the plan</span>
            </div>
          </div>
          <Panel flush className={s.tablePanel} bodyClassName={s.tableBody}>
            <DataTable className={s.table} columns={columns} rows={[]} rowKey={(g) => String(g.index)} loadingRows={10} />
          </Panel>
        </PageBody>
      </>
    );
  }

  const itemCount = WAVES.reduce((sum, wave) => sum + (groups[wave]?.length ?? 0), 0);
  const findingCount = WAVES.reduce((sum, wave) => sum + (data.wave_counts[wave] ?? 0), 0);

  // ---- nothing to migrate ----
  if (findingCount === 0) {
    return (
      <>
        {header("PQC migration plan ordered by Mosca urgency.")}
        <PageBody>
          <StatePanel
            variant="empty"
            tag="Nothing to migrate"
            tagTone="safe"
            meta={`${shortId(scanId)} · ${data.unscored} finding${data.unscored === 1 ? "" : "s"}`}
            title="No findings require a migration item"
            actions={
              <Link to={`/scans/${scanId}/findings`} className={buttonClass("primary")}>
                Open findings
              </Link>
            }
          >
            {data.unscored > 0
              ? `Every finding in this scan (${data.unscored}) was classified as needing no migration, so no wave holds anything.`
              : "This scan has no findings, so there is nothing to plan."}
          </StatePanel>
        </PageBody>
      </>
    );
  }

  const blockedIn = (wave: Wave) =>
    (groups[wave] ?? []).filter((g) => g.item.recommendations.some((rec) => rec.status === "blocked")).length;
  const held = data.blocked_chains.reduce((sum, chain) => sum + chain.finding_count, 0);

  const sections: TableSection<ItemGroup>[] = WAVES.filter((wave) => (groups[wave]?.length ?? 0) > 0).map((wave) => {
    const open = !collapsed.has(wave);
    const blocked = blockedIn(wave);
    return {
      key: wave,
      rows: open ? groups[wave] : [],
      header: (
        <span className={s.group} style={toneVars(WAVE_TONE[wave])}>
          <button
            type="button"
            className={s.groupToggle}
            aria-expanded={open}
            onClick={() =>
              setCollapsed((current) => {
                const next = new Set(current);
                if (next.has(wave)) next.delete(wave);
                else next.add(wave);
                return next;
              })
            }
          >
            <Icon name={open ? "chevronDown" : "chevronRight"} size={14} />
            {WAVE_LABEL[wave]}
          </button>
          <span className={s.groupMeta}>
            {groups[wave].length} item{groups[wave].length === 1 ? "" : "s"} · {data.wave_counts[wave]} finding
            {data.wave_counts[wave] === 1 ? "" : "s"}
            {blocked > 0 && ` · ${blocked} blocked`}
          </span>
          <span className={s.groupNote} title={WAVE_DESCRIPTION[wave]}>
            {WAVE_DESCRIPTION[wave]}
          </span>
        </span>
      ),
    };
  });

  return (
    <>
      {header(
        `${itemCount} item${itemCount === 1 ? "" : "s"} from ${findingCount} finding${findingCount === 1 ? "" : "s"}, ordered by Mosca urgency within each wave. Z = ${data.z_years_used ?? "—"}.`,
      )}
      <PageBody>
        {data.z_years_used === null && (
          <Banner
            tone="warn"
            title="Not yet scored against a Z"
            actions={
              <Link to={`/scans/${scanId}`} className={buttonClass("secondary")}>
                Open Mosca inputs
              </Link>
            }
          >
            Z is set on the Overview, beside the waves it moves. Until then Mosca urgency is not applied.
          </Banner>
        )}

        <div className={s.cards}>
          {WAVES.map((wave) => {
            const [head, title] = splitLabel(wave);
            const items = groups[wave]?.length ?? 0;
            const blocked = blockedIn(wave);
            return (
              <div key={wave} className={s.card} style={toneVars(WAVE_TONE[wave])} title={WAVE_DESCRIPTION[wave]}>
                <span className={s.cardHead}>
                  <span className={s.cardSquare} aria-hidden="true" />
                  <Caps>{head}</Caps>
                  <span className={s.cardTitle}>{title}</span>
                </span>
                <span className={s.cardCount}>
                  <span className={s.cardNumber}>{items}</span>
                  <span className={s.cardSub}>{blocked > 0 ? `${blocked} blocked` : `${data.wave_counts[wave]} findings`}</span>
                </span>
              </div>
            );
          })}
          <div className={s.card}>
            <Caps>Blocking prerequisites</Caps>
            {data.blocked_chains.length === 0 ? (
              <span className={s.cardSub}>Nothing is blocked.</span>
            ) : (
              <ul className={s.blockers} title={`${data.blocked_chains.length} chains holding ${held} findings`}>
                {data.blocked_chains.slice(0, 4).map((chain, index) => (
                  <li key={index}>
                    <span className={s.blockerText} title={chain.prerequisites.map((p) => `${p.unmet} — observed ${p.observed ?? "nothing"}`).join("\n")}>
                      {chain.prerequisites[0]?.unmet}
                      {chain.prerequisites.length > 1 && ` (+${chain.prerequisites.length - 1})`}
                    </span>
                    <span className={s.blockerCount} title={chain.assets.join(", ")}>
                      {chain.finding_count}
                    </span>
                  </li>
                ))}
                {data.blocked_chains.length > 4 && (
                  <li>
                    <span className={s.cardSub}>{data.blocked_chains.length - 4} more chains</span>
                  </li>
                )}
              </ul>
            )}
          </div>
        </div>

        <Panel flush className={s.tablePanel} bodyClassName={s.tableBody}>
          <DataTable
            className={s.table}
            wrap
            columns={columns}
            sections={sections}
            rowKey={(g) => `${g.wave}-${g.index}`}
            onRowClick={(g) => navigate(findingsLink(g))}
          />
        </Panel>
        {data.unscored > 0 && (
          <span className={s.footnote}>
            {data.unscored} finding{data.unscored === 1 ? "" : "s"} need no migration and are not listed · {WAVE_SHORT.verify} holds
            low-confidence items to confirm first.
          </span>
        )}
      </PageBody>
    </>
  );
}
