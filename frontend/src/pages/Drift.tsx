import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type AlignmentNoteView, type AlignmentView, type Scan } from "../api";
import { PageBody, PageHeader, shortId } from "../components/ui/AppShell";
import { DataTable, type Column } from "../components/ui/DataTable";
import { Banner, buttonClass, Caps, Panel, SeverityBadge } from "../components/ui/primitives";
import { StatePanel } from "../components/ui/StatePanel";
import { toneVars, type Tone } from "../components/ui/tone";
import s from "./Drift.module.css";

// §13 screen 5. Two states, both drawn: `compared`, with each note shown as
// what the config declared beside what the probe observed, and `skipped`, with
// the reason. "No drift found" and "drift was never checked" are different
// statements about a host, and an empty panel would make them look the same.
//
// The backend says *that* a declaration and an observation diverge, and why,
// in the note; it does not rank the divergence as weaker or stronger. So a
// service is "Diverges" or "Match", never a direction nobody computed.

function format(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.join(" ");
  return String(value);
}

const serviceOf = (note: AlignmentNoteView) =>
  note.observed?.host !== undefined ? `${note.observed.host}:${note.observed.port ?? ""}` : note.asset_key;

interface Service {
  key: string;
  notes: AlignmentNoteView[];
}

function declaredOf(note: AlignmentNoteView): string {
  return format(note.declared?.declared) || note.config.protocol_version || note.config.algorithm_name;
}

function observedOf(note: AlignmentNoteView): string {
  const version = format(note.observed?.version) || note.live.algorithm_name;
  if (note.observed?.offered === undefined) return version;
  return `${version} ${note.observed.offered ? "accepted" : "refused"}`;
}

function suitesOf(note: AlignmentNoteView): string | null {
  const accepted = note.observed?.accepted_suite_count;
  return accepted === undefined || accepted === null ? null : String(accepted);
}

function Pill({ tone, label, count }: { tone: Tone; label: string; count: number }) {
  return (
    <span className={s.pill} style={toneVars(tone)}>
      <span className={s.pillSquare} aria-hidden="true" />
      {label}
      <span className={s.pillCount}>{count}</span>
    </span>
  );
}

export default function Drift() {
  const { scanId = "" } = useParams();
  const [data, setData] = useState<AlignmentView | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    api.alignment(scanId).then(setData).catch((err) => setError(err.message));
    // The mode tells a files-only scan (drift was never possible) from a
    // probe that could not complete (drift was attempted).
    api.scan(scanId).then(setScan).catch(() => setScan(null));
  }, [scanId]);

  const services = useMemo<Service[]>(() => {
    if (!data || data.status !== "compared") return [];
    const byKey = new Map<string, Service>();
    for (const key of data.compared_services) byKey.set(key, { key, notes: [] });
    for (const note of data.notes) {
      const key = serviceOf(note);
      const entry = byKey.get(key) ?? { key, notes: [] };
      entry.notes.push(note);
      byKey.set(key, entry);
    }
    // Divergent services first: they are the reason to open this screen.
    return [...byKey.values()].sort((a, b) => b.notes.length - a.notes.length || a.key.localeCompare(b.key));
  }, [data]);

  useEffect(() => {
    if (services.length && !services.some((service) => service.key === selected)) {
      setSelected(services[0].key);
    }
  }, [services, selected]);

  const header = (subtitle: string, actions?: ReactNode) => (
    <PageHeader title="Drift" subtitle={subtitle} actions={actions} />
  );

  if (error) {
    return (
      <>
        {header("Declared vs. negotiated TLS parameters.")}
        <PageBody>
          <StatePanel variant="error" tag="Drift unavailable" meta={shortId(scanId)} title="The drift comparison could not be loaded" log={[error]} />
        </PageBody>
      </>
    );
  }

  // ---- probing: the scan has not finished ----
  if (scan && (scan.status === "running" || scan.status === "staging" || scan.status === "awaiting_approval")) {
    const targets = scan.probe_targets ?? [];
    return (
      <>
        {header("Comparing declared configuration with live handshakes as probes complete.")}
        <PageBody>
          <StatePanel
            variant="loading"
            appearance="panel"
            title={scan.status === "running" ? "Probing endpoints" : "Waiting for file approval"}
            meta={`${targets.length} target${targets.length === 1 ? "" : "s"}`}
            log={targets.map((target) => `queued   ${target.host}:${target.port}`)}
          >
            A diff opens for each endpoint once analysis has finished. Handshakes only — no application data is sent.
          </StatePanel>
        </PageBody>
      </>
    );
  }

  if (!data) {
    return (
      <>
        {header("Loading…")}
        <PageBody>
          <Panel flush className={s.endpoints}>
            <DataTable columns={endpointColumns} rows={[]} rowKey={(row) => row.key} loadingRows={4} />
          </Panel>
        </PageBody>
      </>
    );
  }

  // ---- skipped ----
  if (data.status === "skipped") {
    if (scan?.mode === "files") {
      return (
        <>
          {header("Declared vs. negotiated TLS parameters.")}
          <PageBody>
            <StatePanel
              variant="empty"
              tag="Not available for this scan"
              meta={`${shortId(scanId)} · Files only`}
              title="Drift requires “Files + network probe” mode"
              actions={
                <>
                  <Link to="/" className={buttonClass("primary")}>
                    Configure a probe scan
                  </Link>
                  <Link to={`/scans/${scanId}/findings?source_layer=config`} className={buttonClass("secondary")}>
                    View declared-config findings
                  </Link>
                </>
              }
            >
              <p>
                Drift compares what configuration declares with what live endpoints actually negotiate. This scan
                analysed files only, so there are no observations to compare.
              </p>
              {data.reason && <p>{data.reason}</p>}
            </StatePanel>
          </PageBody>
        </>
      );
    }
    return (
      <>
        {header("Declared configuration only — no comparison.")}
        <PageBody>
          <Banner tone="error" title="Drift could not be computed">
            <div>{data.reason ?? "The comparison was skipped."}</div>
            <div style={{ marginTop: 4 }}>
              The check needs both halves: a config that declares TLS for a service, and that service answering the
              probe.
            </div>
          </Banner>
        </PageBody>
      </>
    );
  }

  // ---- compared ----
  const diverging = services.filter((service) => service.notes.length > 0).length;
  const matching = services.length - diverging;
  const current = services.find((service) => service.key === selected) ?? null;

  return (
    <>
      {header(
        `What configs declare vs. what ${services.length} live endpoint${services.length === 1 ? "" : "s"} negotiated.`,
        <span className={s.pills}>
          <Pill tone="high" label="Diverges" count={diverging} />
          <Pill tone="unknown" label="Match" count={matching} />
          {data.scope_skipped.length > 0 && <Pill tone="blocked" label="Not compared" count={data.scope_skipped.length} />}
        </span>,
      )}
      <PageBody>
        <Panel flush className={s.endpoints}>
          <DataTable
            columns={endpointColumns}
            rows={services}
            rowKey={(service) => service.key}
            selectedKey={selected}
            onRowClick={(service) => setSelected(service.key)}
          />
        </Panel>

        {current && (
          <div className={s.lower}>
            <Panel
              className={s.panelFill}
              title={
                <>
                  Diff <span style={{ textTransform: "none", fontFamily: "var(--font-mono)", color: "var(--text)" }}>{current.key}</span>
                </>
              }
              meta={
                <span className={s.legend}>
                  <span className={s.legendItem}>
                    <span className={s.legendSwatch} style={{ background: "var(--sev-high-bg)" }} />
                    diverges from declaration
                  </span>
                </span>
              }
              flush
            >
              {current.notes.length === 0 ? (
                <StatePanel variant="empty" framed={false} tag="Match" title="Declaration and handshake agree">
                  Every declaration that covers this service matches what it negotiated.
                </StatePanel>
              ) : (
                <table className={s.diff}>
                  <colgroup>
                    <col style={{ width: 110 }} />
                    <col />
                    <col />
                  </colgroup>
                  <thead>
                    <tr>
                      <th />
                      <th>
                        <span className={s.diffHeadTitle}>Declared</span>
                        <span className={s.diffHeadLoc}>{current.notes[0].config.evidence_location}</span>
                      </th>
                      <th>
                        <span className={s.diffHeadTitle}>Observed via probe</span>
                        <span className={s.diffHeadLoc}>{current.notes[0].live.evidence_location}</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {current.notes.map((note) => (
                      <tr key={note.id}>
                        <td className={s.rowLabel}>{format(note.declared?.directive) || note.config.algorithm_name}</td>
                        <td>
                          {declaredOf(note)}
                          {format(note.declared?.observation) && <span className={s.cellNote}>{format(note.declared?.observation)}</span>}
                          {note.declared?.activated_by_openssl_conf === false && (
                            <span className={s.cellNote}>not activated — the file is never applied</span>
                          )}
                        </td>
                        <td className={s.diverges}>
                          {observedOf(note)}
                          {suitesOf(note) !== null && (
                            <span className={s.cellNote}>
                              {format(note.observed?.accepted_suite_count)} suites accepted, {format(note.observed?.rejected_suite_count)} rejected
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Panel>

            <Panel
              className={s.panelFill}
              title="Assessment"
              meta={
                current.notes.length > 0 ? (
                  <SeverityBadge tone="high" marker={false}>
                    Diverges from declaration
                  </SeverityBadge>
                ) : (
                  <SeverityBadge tone="unknown" marker={false}>
                    Match
                  </SeverityBadge>
                )
              }
            >
              <div className={s.assessment}>
                {current.notes.length > 0 && (
                  <>
                    <Caps>Probable cause</Caps>
                    {current.notes.map((note) => (
                      <div key={note.id} className={s.cause}>
                        <p className={s.causeText}>{note.note}</p>
                      </div>
                    ))}
                    <div className={s.section}>
                      <Caps>Related findings</Caps>
                      <ul className={s.related}>
                        {current.notes.flatMap((note) =>
                          [note.config, note.live].map((finding) => (
                            <li key={`${note.id}-${finding.id}`}>
                              <Link
                                className={s.relatedLink}
                                to={`/scans/${scanId}/findings?q=${encodeURIComponent(finding.evidence_location ?? finding.algorithm_name)}`}
                              >
                                {finding.source_layer === "live" ? "live" : "config"}
                              </Link>
                              <span className={s.relatedText} title={finding.evidence_location ?? undefined}>
                                {finding.algorithm_name} · {finding.evidence_location}
                              </span>
                            </li>
                          )),
                        )}
                      </ul>
                    </div>
                  </>
                )}
                {current.notes.length === 0 && <p className={s.help}>Nothing to assess: no divergence was recorded.</p>}

                {data.scope_skipped.length > 0 && (
                  <div className={s.section}>
                    <Caps>Declarations not compared</Caps>
                    <p className={s.help} style={{ marginTop: 6 }}>
                      Server-wide defaults a virtual host may override are not held against one probed service.
                    </p>
                    <ul className={s.skipped}>
                      {data.scope_skipped.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </Panel>
          </div>
        )}
      </PageBody>
    </>
  );
}

const endpointColumns: Column<Service>[] = [
  {
    key: "endpoint",
    header: "Endpoint",
    width: 170,
    skeletonWidth: 110,
    render: (service) => (
      <span className={s.endpoint}>
        <span className={s.host}>{service.key}</span>
        {service.notes[0] && <span className={s.sub}>{service.notes[0].asset_key}</span>}
      </span>
    ),
  },
  {
    key: "declaredIn",
    header: "Declared in",
    skeletonWidth: 140,
    render: (service) =>
      service.notes[0]?.config.evidence_location ? (
        <span className={s.mono} title={service.notes[0].config.evidence_location}>
          {service.notes[0].config.evidence_location}
        </span>
      ) : (
        <span className={s.monoMuted}>— no divergent declaration</span>
      ),
  },
  {
    key: "declared",
    header: "Declared",
    width: 180,
    skeletonWidth: 90,
    render: (service) =>
      service.notes.length ? (
        <span className={s.mono}>{[...new Set(service.notes.map(declaredOf))].join("  ")}</span>
      ) : (
        <span className={s.monoMuted}>—</span>
      ),
  },
  {
    key: "observed",
    header: "Observed",
    width: 200,
    skeletonWidth: 110,
    render: (service) =>
      service.notes.length ? (
        <span className={s.mono}>{[...new Set(service.notes.map(observedOf))].join("  ")}</span>
      ) : (
        <span className={s.monoMuted}>as declared</span>
      ),
  },
  {
    key: "suites",
    header: "Obs. suites",
    width: 96,
    align: "right",
    skeletonWidth: 24,
    render: (service) => {
      const counts = service.notes.map(suitesOf).filter((count): count is string => count !== null);
      return <span className={s.mono}>{counts[0] ?? "—"}</span>;
    },
  },
  {
    key: "drift",
    header: "Drift",
    width: 170,
    skeletonWidth: 90,
    render: (service) =>
      service.notes.length ? (
        <SeverityBadge tone="high">
          Diverges · {service.notes.length} note{service.notes.length === 1 ? "" : "s"}
        </SeverityBadge>
      ) : (
        <SeverityBadge tone="unknown">Match</SeverityBadge>
      ),
  },
];
