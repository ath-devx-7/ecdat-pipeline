import { useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type FindingDetail, type FindingPage, type Verdict, type Wave } from "../api";
import { PageBody, PageHeader, shortId } from "../components/ui/AppShell";
import { DataTable, type Column } from "../components/ui/DataTable";
import { DetailPanel, DetailSection } from "../components/ui/DetailPanel";
import { FilterBar } from "../components/ui/FilterBar";
import { Icon } from "../components/ui/Icon";
import { Banner, Button, buttonClass, Caps, SeverityBadge } from "../components/ui/primitives";
import { StatePanel } from "../components/ui/StatePanel";
import { cx, toneVars, type Tone } from "../components/ui/tone";
import {
  COLLECTOR_LABEL,
  COLLECTOR_NAMES,
  CONFIDENCES,
  SOURCE_LAYERS,
  STATUS_LABEL,
  STATUS_TONE,
  VERDICT_LABEL,
  VERDICT_TONE,
  VERDICTS,
  WAVE_SHORT,
  WAVE_TONE,
  WAVES,
  describeAlgorithm,
  titleCase,
} from "../lib/labels";
import s from "./Findings.module.css";

// §13 screen 4. Filters are the URL, so a filtered view can be linked to.
// Every value a filter accepts is listed, but only the ones this scan's
// findings carry (the API's facets) can be picked — so a filter never offers a
// value that selects nothing, and the values it cannot offer are still visible
// as "none in this scan" rather than silently missing. Clicking a row opens the
// whole rationale and the raw evidence — a verdict without its citation is an
// opinion.

const FILTERS = ["verdict", "wave", "collector", "confidence", "source_layer"] as const;
type FilterKey = (typeof FILTERS)[number];

const FILTER_LABEL: Record<FilterKey, string> = {
  verdict: "Verdict",
  wave: "Wave",
  collector: "Collector",
  confidence: "Confidence",
  source_layer: "Source layer",
};

// The full vocabulary of each filter, in the backend's own order.
const VOCABULARY: Record<FilterKey, readonly string[]> = {
  verdict: VERDICTS,
  wave: WAVES,
  collector: COLLECTOR_NAMES,
  confidence: CONFIDENCES,
  source_layer: SOURCE_LAYERS,
};

const valueLabel = (key: FilterKey, value: string) =>
  key === "verdict"
    ? VERDICT_LABEL[value as Verdict]
    : key === "wave"
      ? WAVE_SHORT[value as Wave]
      : key === "collector"
        ? (COLLECTOR_LABEL[value] ?? titleCase(value))
        : titleCase(value);

const valueTone = (key: FilterKey, value: string): Tone | null =>
  key === "verdict" ? VERDICT_TONE[value as Verdict] : key === "wave" ? WAVE_TONE[value as Wave] : null;

// `x_source` and `y_source` are written by the scorer and are plain strings —
// "rule[1]: etc/openssl.cnf*", "scan default", "action_class:config". Rendered
// as they were recorded rather than prettified: the rationale is an audit
// trail, and a relabelled value is no longer the value that was stored.
function sourceOf(rationale: Record<string, unknown> | null, key: string): string | null {
  const value = rationale?.[key];
  return typeof value === "string" ? value : null;
}

export default function Findings() {
  const { scanId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const [page, setPage] = useState<FindingPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [text, setText] = useState(params.get("q") ?? "");
  const query = params.toString();

  useEffect(() => {
    setPage(null);
    setError(null);
    api
      .findings(scanId, new URLSearchParams(query))
      .then(setPage)
      .catch((err) => setError(err.message));
  }, [scanId, query]);

  useEffect(() => setText(params.get("q") ?? ""), [params]);

  const active = useMemo(() => {
    const chosen = {} as Record<FilterKey, Set<string>>;
    for (const key of FILTERS) chosen[key] = new Set(params.getAll(key));
    return chosen;
  }, [params]);

  // The facets are scan-wide, so they are the same on every page; kept from
  // the last response so the sections do not blank while the next one loads.
  const [facets, setFacets] = useState<Record<string, string[]> | null>(null);
  useEffect(() => {
    if (page) setFacets(page.facets);
  }, [page]);

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

  function search(value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set("q", value);
    else next.delete("q");
    next.delete("offset");
    setParams(next);
  }

  function goTo(offset: number) {
    const next = new URLSearchParams(params);
    if (offset > 0) next.set("offset", String(offset));
    else next.delete("offset");
    setParams(next);
  }

  const filtered = FILTERS.some((key) => active[key].size > 0) || params.has("q");
  const clearAll = () => setParams(new URLSearchParams());
  const items = page?.items ?? [];
  const open = items.find((finding) => finding.id === openId) ?? null;
  // Every finding on screen came back without a verdict: the policy engine
  // produced nothing for them, so what is listed is raw detection only.
  const unclassified = items.length > 0 && items.every((finding) => finding.verdict === null);

  const columns: Column<FindingDetail>[] = [
    {
      key: "algorithm",
      header: "Algorithm",
      width: 170,
      sortValue: (f) => describeAlgorithm(f).toLowerCase(),
      skeletonWidth: 110,
      render: (f) => (
        <span className={s.cellStack}>
          <span className={s.algo} title={describeAlgorithm(f)}>
            {describeAlgorithm(f)}
          </span>
          {f.algorithm_family && f.algorithm_family !== f.algorithm_name && (
            <span className={s.as} title={f.algorithm_name}>
              as {f.algorithm_name}
            </span>
          )}
        </span>
      ),
    },
    {
      key: "primitive",
      header: "Primitive",
      width: 104,
      sortValue: (f) => f.primitive,
      skeletonWidth: 60,
      render: (f) => <span className={s.muted}>{titleCase(f.primitive)}</span>,
    },
    {
      key: "verdict",
      header: "Verdict",
      width: 158,
      sortValue: (f) => (f.verdict ? VERDICTS.indexOf(f.verdict.verdict) : VERDICTS.length),
      skeletonWidth: 90,
      render: (f) =>
        f.verdict ? (
          <SeverityBadge tone={VERDICT_TONE[f.verdict.verdict]}>{VERDICT_LABEL[f.verdict.verdict]}</SeverityBadge>
        ) : (
          <SeverityBadge tone="unknown">Not evaluated</SeverityBadge>
        ),
    },
    {
      key: "wave",
      header: "Wave",
      width: 84,
      sortValue: (f) => (f.risk ? WAVES.indexOf(f.risk.wave) : WAVES.length),
      skeletonWidth: 44,
      render: (f) =>
        f.risk ? (
          <SeverityBadge tone={WAVE_TONE[f.risk.wave]} marker={false}>
            {WAVE_SHORT[f.risk.wave]}
          </SeverityBadge>
        ) : (
          <span className={s.targetNone}>—</span>
        ),
    },
    {
      key: "advice",
      header: "Advice",
      width: 190,
      skeletonWidth: 110,
      render: (f) =>
        f.recommendations.length === 0 ? (
          <span className={s.targetNone}>—</span>
        ) : (
          <span className={s.advice}>
            {f.recommendations.map((rec) => (
              <SeverityBadge key={rec.id} tone={STATUS_TONE[rec.status]} marker={false} title={STATUS_LABEL[rec.status]}>
                {rec.target ?? STATUS_LABEL[rec.status]}
              </SeverityBadge>
            ))}
          </span>
        ),
    },
    {
      key: "collector",
      header: "Collector",
      width: 104,
      sortValue: (f) => f.collector,
      skeletonWidth: 60,
      render: (f) => <span className={s.muted}>{COLLECTOR_LABEL[f.collector] ?? titleCase(f.collector)}</span>,
    },
    {
      key: "layer",
      header: "Layer",
      width: 76,
      sortValue: (f) => SOURCE_LAYERS.indexOf(f.source_layer),
      skeletonWidth: 44,
      render: (f) => <span className={s.muted}>{titleCase(f.source_layer)}</span>,
    },
    {
      key: "confidence",
      header: "Conf.",
      width: 70,
      sortValue: (f) => CONFIDENCES.indexOf(f.confidence),
      skeletonWidth: 36,
      render: (f) => <span className={s.muted}>{titleCase(f.confidence)}</span>,
    },
    {
      key: "location",
      header: "Location",
      sortValue: (f) => f.evidence_location ?? "",
      skeletonWidth: 200,
      render: (f) => (
        <span className={s.loc} title={f.evidence_location ?? undefined}>
          {f.evidence_location ?? "—"}
        </span>
      ),
    },
  ];

  const offset = page?.offset ?? Number(params.get("offset") ?? 0);
  const limit = page?.limit ?? 200;
  const total = page?.total ?? 0;

  if (error && !page) {
    return (
      <>
        <PageHeader title="Findings" subtitle="The findings could not be loaded." />
        <PageBody>
          <StatePanel variant="error" tag="Findings unavailable" meta={shortId(scanId)} title="The findings could not be loaded" log={[error]} />
        </PageBody>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Findings"
        subtitle={
          !page
            ? "Loading findings…"
            : unclassified
              ? "Raw detections only — no policy verdicts were recorded."
              : "Filter by any section below. Click a row for its verdict, risk, recommendations and evidence."
        }
      />
      <PageBody flush>
        <FilterBar
          className={s.filters}
          search={{ value: text, onChange: setText, onSubmit: search, placeholder: "Search name, family or location" }}
          onClear={filtered ? clearAll : undefined}
          count={page ? `${total} shown` : undefined}
        />

        <div className={s.facets}>
          {FILTERS.map((key) => {
            const present = new Set(facets?.[key] ?? []);
            // Anything the API reports that the vocabulary does not know yet
            // is still offered, after the known values.
            const values = [...VOCABULARY[key], ...[...present].filter((value) => !VOCABULARY[key].includes(value))];
            return (
              <div key={key} className={s.facetGroup} role="group" aria-label={FILTER_LABEL[key]}>
                <Caps>{FILTER_LABEL[key]}</Caps>
                <div className={s.facetChips}>
                  {values.map((value) => {
                    const on = active[key].has(value);
                    // A chosen value stays clickable even if absent, so it can
                    // always be un-chosen from a hand-edited URL.
                    const available = facets === null || present.has(value) || on;
                    const tone = valueTone(key, value);
                    return (
                      <button
                        key={value}
                        type="button"
                        className={cx(s.facetChip, on && s.facetOn)}
                        style={tone ? toneVars(tone) : undefined}
                        aria-pressed={on}
                        disabled={!available}
                        title={available ? undefined : "None in this scan"}
                        onClick={() => toggle(key, value)}
                      >
                        {tone && <span className={s.facetSquare} aria-hidden="true" />}
                        {valueLabel(key, value)}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        {unclassified && (
          <Banner tone="error" className={s.banner} title="No policy verdicts for these findings — waves and recommendations are withheld">
            Every finding listed here came back without a verdict from the policy pack, so what is shown is unscored raw
            detection.
          </Banner>
        )}

        <div className={cx(s.split, open && s.splitOpen)}>
          <div className={s.tableCol}>
            <DataTable
              className={s.table}
              wrap
              columns={columns}
              rows={items}
              rowKey={(f) => f.id}
              selectedKey={openId}
              onRowClick={(f) => setOpenId(openId === f.id ? null : f.id)}
              loadingRows={page ? 0 : 14}
              empty={
                filtered ? (
                  <StatePanel
                    variant="empty"
                    framed={false}
                    title="Nothing matches these filters"
                    actions={
                      <Button variant="primary" onClick={clearAll}>
                        Clear filters
                      </Button>
                    }
                  >
                    Filters combine as OR within a section and AND across sections. Remove one to widen the view.
                  </StatePanel>
                ) : (
                  <StatePanel variant="empty" framed={false} title="No findings in this scan">
                    The collectors ran over the approved files and probe targets and recorded no cryptography. Check the
                    Overview's coverage detail for collectors that did not run or extensions nothing ruled on.
                  </StatePanel>
                )
              }
            />
            <div className={s.pager}>
              <span>
                {!page ? "Loading…" : total === 0 ? "0 shown" : `${offset + 1}–${offset + items.length} of ${total} · ${limit} per page`}
              </span>
              <span className={s.pagerButtons}>
                <Button small className={s.pageButton} aria-label="Previous page" disabled={!page || offset === 0} onClick={() => goTo(Math.max(0, offset - limit))}>
                  <Icon name="chevronLeft" size={14} />
                </Button>
                <Button small className={s.pageButton} aria-label="Next page" disabled={!page || offset + limit >= total} onClick={() => goTo(offset + limit)}>
                  <Icon name="chevronRight" size={14} />
                </Button>
              </span>
            </div>
          </div>

          {open && <Detail finding={open} scanId={scanId} onClose={() => setOpenId(null)} />}
        </div>
      </PageBody>
    </>
  );
}

function Detail({ finding, scanId, onClose }: { finding: FindingDetail; scanId: string; onClose: () => void }) {
  return (
    <DetailPanel
      breadcrumb={
        <span className={s.mono}>
          {shortId(scanId)} · finding {shortId(finding.id)}
        </span>
      }
      onClose={onClose}
      title={describeAlgorithm(finding)}
      footerEnd={
        finding.risk ? (
          <Link to={`/scans/${scanId}/roadmap`} className={buttonClass("primary")}>
            Open in roadmap
          </Link>
        ) : undefined
      }
    >
      <dl className={s.kv}>
        <dt>Observed as</dt>
        <dd className={s.mono}>{finding.algorithm_name}</dd>
        <dt>OID</dt>
        <dd className={s.mono}>{finding.algorithm_oid ?? "—"}</dd>
        <dt>Location</dt>
        <dd className={s.mono}>{finding.evidence_location ?? "—"}</dd>
        <dt>Collector</dt>
        <dd>
          {COLLECTOR_LABEL[finding.collector] ?? titleCase(finding.collector)} · {finding.source_layer} ·{" "}
          {finding.confidence} confidence
        </dd>
      </dl>

      <DetailSection title="Verdict">
        {finding.verdict ? (
          <div className={s.box}>
            <div className={s.boxHead}>
              <SeverityBadge tone={VERDICT_TONE[finding.verdict.verdict]}>{VERDICT_LABEL[finding.verdict.verdict]}</SeverityBadge>
              <span className={s.boxRef}>
                rule {finding.verdict.rule_id ?? "—"} · pack {finding.verdict.policy_version}
              </span>
            </div>
            <div className={s.boxText}>{finding.verdict.source_citation}</div>
          </div>
        ) : (
          <div className={s.recNote}>Not classified.</div>
        )}
      </DetailSection>

      <DetailSection title="Risk">
        {finding.risk ? (
          <>
            <div className={s.recHead}>
              <SeverityBadge tone={WAVE_TONE[finding.risk.wave]} marker={false}>
                {WAVE_SHORT[finding.risk.wave]}
              </SeverityBadge>
              <span className={s.muted}>
                {finding.risk.urgency_years !== null ? `overdue by ${finding.risk.urgency_years} years` : "Mosca not applied"}
              </span>
            </div>
            <dl className={s.kv} style={{ marginTop: 8 }}>
              <dt>X · Y · Z</dt>
              <dd className={s.mono}>
                {finding.risk.x_years ?? "—"} · {finding.risk.y_years ?? "—"} · {finding.risk.z_years ?? "—"}
              </dd>
              {/* Where X and Y came from. Two of the three inputs are
                  assumptions rather than measurements, and a wave nobody can
                  trace back to the assumption behind it is a wave nobody can
                  argue with. */}
              {sourceOf(finding.risk.rationale, "x_source") && (
                <>
                  <dt>X from</dt>
                  <dd className={s.mono}>{sourceOf(finding.risk.rationale, "x_source")}</dd>
                </>
              )}
              {sourceOf(finding.risk.rationale, "y_source") && (
                <>
                  <dt>Y from</dt>
                  <dd className={s.mono}>{sourceOf(finding.risk.rationale, "y_source")}</dd>
                </>
              )}
            </dl>
            {finding.risk.rationale && typeof finding.risk.rationale.because === "string" && (
              <div className={s.recNote}>{finding.risk.rationale.because}</div>
            )}
          </>
        ) : (
          <div className={s.recNote}>No wave — needs no migration.</div>
        )}
      </DetailSection>

      <DetailSection title="Recommendations">
        {finding.recommendations.length === 0 && <div className={s.recNote}>None.</div>}
        {finding.recommendations.map((rec) => (
          <div key={rec.id} className={s.recBox}>
            <div className={s.recHead}>
              <SeverityBadge tone={STATUS_TONE[rec.status]}>{STATUS_LABEL[rec.status]}</SeverityBadge>
              {rec.target && <span className={s.recTarget}>{rec.target}</span>}
              {rec.hybrid_target && rec.hybrid_target !== rec.target && (
                <span className={s.param}>(hybrid {rec.hybrid_target})</span>
              )}
            </div>
            {rec.action_class && <div className={s.recNote}>Action: {titleCase(rec.action_class)}</div>}
            {rec.prerequisites && rec.prerequisites.length > 0 && (
              <ol className={s.ordered}>
                {rec.prerequisites.map((p, index) => (
                  <li key={index}>
                    <span className={s.mono}>{p.unmet}</span> — observed {p.observed ?? <em>nothing</em>}
                    {p.observed_at && <span className={s.param}> at {p.observed_at}</span>}
                    {p.note && <div className={s.recNote}>{p.note}</div>}
                  </li>
                ))}
              </ol>
            )}
            {rec.side_effects && <div className={s.recNote}>{rec.side_effects}</div>}
            {rec.source_citation && <div className={s.recNote}>{rec.source_citation}</div>}
          </div>
        ))}
      </DetailSection>

      <DetailSection title="Evidence" aside={finding.created_at ? finding.created_at.slice(0, 16).replace("T", " ") : undefined}>
        <pre className={s.code}>{JSON.stringify(finding.evidence_raw, null, 2)}</pre>
      </DetailSection>
    </DetailPanel>
  );
}
