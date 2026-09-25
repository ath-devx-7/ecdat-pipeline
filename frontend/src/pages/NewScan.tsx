import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type Policy, type ProbeTarget, type Scan, type ScanMode, type SourceType } from "../api";
import { PageBody, PageHeader, shortId } from "../components/ui/AppShell";
import { DataTable, type Column } from "../components/ui/DataTable";
import { Banner, Button, buttonClass, Caps, Panel, SeverityBadge } from "../components/ui/primitives";
import { StatePanel } from "../components/ui/StatePanel";
import { cx } from "../components/ui/tone";
import { COLLECTORS, MODE_SHORT, SCAN_STATUS_SHORT, SCAN_STATUS_TONE, scanLabel } from "../lib/labels";
import { BUILD_OUTPUT_DIRS, VENDORED_DIRS } from "../lib/exclusions";
import { formatBytes } from "../lib/tree";
import { useElapsed } from "../lib/useElapsed";
import s from "./NewScan.module.css";

// §13 screen 1. Scope only: what to read, and where to probe. Mosca's two
// human inputs live where the user can actually answer them — X on the approval
// screen, against the real file tree, and Z beside the waves it moves on the
// overview. A probe_only scan has no approval screen, so X is asked for here in
// that mode alone.

//: Years, as a number. Bounded to match the API, which rejects anything else.
export function clampYears(entered: string, previous: number): number {
  const value = Number(entered);
  if (entered.trim() === "" || Number.isNaN(value)) return previous;
  return Math.min(100, Math.max(0, Math.trunc(value)));
}

// `webkitdirectory` is what turns a file input into a folder picker, and it is
// not in React's typings; spread as a plain record rather than cast away the
// props type of the whole element.
const DIRECTORY_PICKER: Record<string, string> = { webkitdirectory: "", directory: "" };

const SKIPPED_DIRS = new Set([...VENDORED_DIRS, ...BUILD_OUTPUT_DIRS]);

// What the archive picker will offer in its dialog. A `docker save` tar is
// usually `.tar`; `.tar.gz` and `.tgz` are what a person gets after compressing
// one to move it, and the backend reads either because `tarfile` sniffs the
// compression. Advisory only — the picker's "all files" escape hatch stays, and
// the archive is validated by being opened, not by its name.
const ARCHIVE_ACCEPT = ".tar,.tar.gz,.tgz,application/x-tar,application/gzip";

export interface PickedFolder {
  // the folder the user picked, which is the first segment of every path
  name: string;
  // what will actually be uploaded, after `pickable`
  files: File[];
  // how many the filter dropped, so the count on screen is never silently short
  skipped: number;
}

export { scanLabel };

export function folderName(files: File[]): string {
  const first = files[0]?.webkitRelativePath ?? "";
  return first.split("/")[0] || "the chosen folder";
}

export function pickable(files: File[]): File[] {
  return files.filter((file) => {
    const relative = file.webkitRelativePath || file.name;
    return !relative.split("/").some((segment) => SKIPPED_DIRS.has(segment));
  });
}

export function parseTargets(text: string): ProbeTarget[] {
  return text
    .split(/[\n,]/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [host, port] = line.split(":");
      return { host: host.trim(), port: port ? Number(port) : 443 };
    });
}

// Why each line of the probe box would be refused, by line number, before
// anything is sent. The same split as `parseTargets`, so what passes here is
// exactly what that function will read.
export function targetProblems(text: string): string[] {
  const problems: string[] = [];
  text.split("\n").forEach((line, index) => {
    for (const part of line.split(",").map((p) => p.trim()).filter(Boolean)) {
      const [host, port, ...rest] = part.split(":");
      const portOk = port === undefined || (/^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535);
      if (!host.trim() || rest.length > 0 || !portOk) {
        problems.push(`Line ${index + 1}: ${part} is not host:port.`);
      }
    }
  });
  return problems;
}

type Field = "source" | "targets";

const SOURCES: { value: SourceType; label: string }[] = [
  { value: "github", label: "Git repository" },
  { value: "upload", label: "Local directory" },
  { value: "docker_archive", label: "Docker image tar" },
];

const MODES: { value: ScanMode; title: string; text: string }[] = [
  { value: "files", title: "Files only", text: "Static analysis of approved files" },
  { value: "files_and_probe", title: "Files + network probe", text: "Adds live TLS handshakes · enables Drift" },
  { value: "probe_only", title: "Network probe only", text: "Live TLS handshakes · no file approval" },
];

const pad = (n: number) => String(n).padStart(2, "0");

// "09-25 14:26", local time — the recent-scans column.
function startedAt(iso: string | null): string {
  if (!iso) return "–";
  const at = new Date(iso);
  return `${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${pad(at.getHours())}:${pad(at.getMinutes())}`;
}


const scanHref = (scan: Scan) =>
  scan.status === "awaiting_approval" ? `/scans/${scan.id}/files` : `/scans/${scan.id}`;

export default function NewScan() {
  const navigate = useNavigate();
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [mode, setMode] = useState<ScanMode>("files");
  // "Local folder" is the browse-and-upload control, so the default source type
  // is `upload`: the backend's `folder` type still reads a path in place, but
  // that needs a path on the *server*, which is not something a browser can
  // offer. The API keeps it for callers that do know one.
  const [sourceType, setSourceType] = useState<SourceType>("upload");
  const [sourceRef, setSourceRef] = useState("");
  const [upload, setUpload] = useState<PickedFolder | null>(null);
  const [archive, setArchive] = useState<File | null>(null);
  const [targets, setTargets] = useState("");
  const [lifetime, setLifetime] = useState(20);

  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<Field, string>>>({});
  // null until the list has loaded, so "no scans yet" is never shown early
  const [recent, setRecent] = useState<Scan[] | null>(null);
  const elapsed = useElapsed(busy);

  useEffect(() => {
    api.policy().then(setPolicy).catch(() => setPolicy(null));
    api.scans().then(setRecent).catch(() => setRecent([]));
  }, []);

  const wantsFiles = mode !== "probe_only";
  const wantsProbe = mode !== "files";
  const wantsUpload = wantsFiles && sourceType === "upload";
  // "Docker image" on this screen is always the uploaded tar. The API's
  // `docker_image` type still exists and still shells out to `docker save`, but
  // that needs a daemon holding the image on the *ECDAT host*, which a browser
  // cannot know about and a host running only this API often does not have —
  // the same reason "Local folder" is `upload` rather than `folder`.
  const wantsArchive = wantsFiles && sourceType === "docker_archive";
  const wantsUrl = wantsFiles && !wantsUpload && !wantsArchive;

  const uploadBytes = upload ? upload.files.reduce((sum, file) => sum + file.size, 0) : 0;
  const targetCount = parseTargets(targets).length;

  function choose(chosen: FileList | null) {
    const all = Array.from(chosen ?? []);
    if (all.length === 0) return; // picker dismissed; keep the previous choice
    const files = pickable(all);
    setUpload({ name: folderName(all), files, skipped: all.length - files.length });
    setFieldErrors((prev) => ({ ...prev, source: undefined }));
  }

  function chooseArchive(chosen: FileList | null) {
    const picked = chosen?.[0];
    if (!picked) return; // dialog dismissed; keep the previous choice
    setArchive(picked);
    setFieldErrors((prev) => ({ ...prev, source: undefined }));
  }

  // Everything that can be known wrong without asking the server, per field,
  // so the banner can say how many fields need attention and each field can
  // say what.
  function validate(): Partial<Record<Field, string>> {
    const found: Partial<Record<Field, string>> = {};
    if (wantsUpload) {
      if (!upload) found.source = "Choose a folder to upload first.";
      else if (!upload.files.length) {
        found.source =
          `Every file in ${upload.name} was left behind as build output or a vendored ` +
          "dependency. Pick a folder holding source, config or certificates.";
      }
    }
    if (wantsArchive && !archive) found.source = "Choose a saved image archive to upload first.";
    if (wantsUrl && !sourceRef.trim()) found.source = "Enter the repository URL to clone.";
    if (wantsProbe) {
      const problems = targetProblems(targets);
      if (problems.length) found.targets = problems.join(" ");
      else if (targetCount === 0) found.targets = "Enter at least one host:port to probe.";
    }
    return found;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    const found = validate();
    setFieldErrors(found);
    if (Object.keys(found).length) return;
    setBusy(true);
    try {
      // Two steps, so POST /api/scans stays a JSON body: the bytes go to
      // /api/uploads and the scan names the id that comes back.
      let ref = sourceRef.trim();
      if (wantsUpload && upload) {
        setUploading(true);
        try {
          ref = (await api.uploadFolder(upload.files)).upload_id;
        } finally {
          setUploading(false);
        }
      }
      if (wantsArchive && archive) {
        setUploading(true);
        try {
          ref = (await api.uploadImageArchive(archive)).archive_id;
        } finally {
          setUploading(false);
        }
      }
      const scan = await api.createScan({
        mode,
        source_type: wantsFiles ? sourceType : "none",
        source_ref: wantsFiles ? ref : undefined,
        probe_targets: wantsProbe ? parseTargets(targets) : [],
        // Null for a file scan: the approval screen supplies it, and sending
        // a placeholder now would put a number nobody chose on the scan row.
        data_lifetime_years: wantsFiles ? null : lifetime,
      });
      navigate(wantsFiles ? `/scans/${scan.id}/files` : `/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const fieldProblems = Object.values(fieldErrors).filter(Boolean);
  const collectorCount = COLLECTORS.filter((collector) => collector.modes.includes(mode)).length;

  // What the running callout says is happening, from what this screen knows:
  // the upload's own size, or the ref being staged. No progress is reported
  // by either endpoint, so no bar is drawn.
  const runningTitle = uploading ? "Uploading" : wantsFiles ? "Surface scan running" : "Probing";
  const runningMeta = wantsUpload ? upload?.name : wantsArchive ? archive?.name : undefined;
  const runningLog = uploading
    ? wantsUpload && upload
      ? `${upload.files.length.toLocaleString("en-US")} files · ${formatBytes(uploadBytes)}`
      : archive
        ? formatBytes(archive.size)
        : ""
    : wantsUrl
      ? `cloning ${sourceRef.trim()}`
      : wantsUpload
        ? `enumerating ${upload?.name ?? ""}`
        : wantsArchive
          ? `unpacking ${archive?.name ?? ""}`
          : parseTargets(targets).map((t) => `${t.host}:${t.port}`).join(" · ");

  const recentColumns: Column<Scan>[] = [
    {
      key: "id",
      header: "ID",
      width: 84,
      render: (scan) => (
        <Link to={scanHref(scan)} className={s.idLink} title={scan.id} onClick={(e) => e.stopPropagation()}>
          {shortId(scan.id)}
        </Link>
      ),
    },
    { key: "target", header: "Target", render: (scan) => <span title={scanLabel(scan)}>{scanLabel(scan)}</span> },
    { key: "mode", header: "Mode", width: 92, render: (scan) => <span className={s.cellMuted}>{MODE_SHORT[scan.mode]}</span> },
    { key: "started", header: "Started", width: 112, mono: true, render: (scan) => startedAt(scan.created_at) },
    {
      key: "status",
      header: "Status",
      width: 120,
      render: (scan) => (
        <SeverityBadge tone={SCAN_STATUS_TONE[scan.status]} marker={false}>
          {SCAN_STATUS_SHORT[scan.status]}
        </SeverityBadge>
      ),
    },
  ];

  const zYear = policy ? new Date().getFullYear() + policy.z_years_default : null;

  return (
    <>
      <PageHeader
        title="New Scan"
        subtitle="Nothing is read from a target until you approve its files on the next screen."
      />
      <PageBody>
        <div className={s.layout}>
          <form onSubmit={submit} className={s.form} noValidate>
            <div className={s.formScroll}>
              {busy && (
                <StatePanel
                  variant="loading"
                  appearance="callout"
                  className={s.callout}
                  title={runningTitle}
                  meta={runningMeta}
                  elapsed={elapsed}
                  log={runningLog ? [runningLog] : undefined}
                >
                  {wantsFiles
                    ? "Configuration is locked until the surface scan finishes. You will review discovered files before analysis runs."
                    : "Configuration is locked until every target has been probed."}
                </StatePanel>
              )}

              {!busy && (fieldProblems.length > 0 || error) && (
                <Banner
                  tone="error"
                  className={s.callout}
                  title={
                    fieldProblems.length > 0
                      ? `Scan not started — ${fieldProblems.length} field${fieldProblems.length === 1 ? " needs" : "s need"} attention`
                      : "Scan not started"
                  }
                >
                  <div className={s.bannerList}>{error ?? fieldProblems.join(" ")}</div>
                </Banner>
              )}

              <fieldset className={s.fieldset} disabled={busy}>
                <div className={s.section}>
                  <Caps className={s.sectionCaps}>Target</Caps>
                  {wantsFiles ? (
                    <>
                      <div className={s.field}>
                        <span className={s.label}>Source type</span>
                        <div className={s.segments} role="radiogroup" aria-label="Source type">
                          {SOURCES.map((option) => (
                            <button
                              key={option.value}
                              type="button"
                              role="radio"
                              aria-checked={sourceType === option.value}
                              className={cx(s.segment, sourceType === option.value && s.segmentOn)}
                              onClick={() => {
                                setSourceType(option.value);
                                setFieldErrors((prev) => ({ ...prev, source: undefined }));
                              }}
                            >
                              {option.label}
                            </button>
                          ))}
                        </div>
                      </div>

                      {wantsUpload && (
                        <div className={s.field}>
                          <span className={s.label}>Directory</span>
                          <div className={s.row}>
                            <input
                              readOnly
                              tabIndex={-1}
                              className={cx(s.input, s.mono, s.readonly, s.grow, fieldErrors.source && s.invalid)}
                              value={upload?.name ?? ""}
                              placeholder="No directory chosen"
                              aria-label="Chosen directory"
                            />
                            {/* The input is the control and the label is what it
                                looks like: a file input cannot be styled, and a
                                button cannot open a folder picker without one
                                behind it. */}
                            <label className={buttonClass("secondary")}>
                              <input
                                type="file"
                                multiple
                                {...DIRECTORY_PICKER}
                                className={s.hiddenInput}
                                onChange={(e) => choose(e.target.files)}
                                disabled={busy}
                              />
                              {upload ? "Change…" : "Browse…"}
                            </label>
                          </div>
                          {fieldErrors.source ? (
                            <p className={s.fieldError}>{fieldErrors.source}</p>
                          ) : (
                            <p className={s.help}>
                              {!upload
                                ? "Pick a folder anywhere on this machine. Your browser asks you to confirm before it reads it."
                                : `${upload.files.length.toLocaleString("en-US")} file${upload.files.length === 1 ? "" : "s"} · ${formatBytes(uploadBytes)}` +
                                  (upload.skipped > 0
                                    ? ` · ${upload.skipped.toLocaleString("en-US")} left behind (${[...SKIPPED_DIRS].join(", ")}): build output and vendored trees are not deployed artefacts.`
                                    : " · ready to upload.")}{" "}
                              Nothing is read until you approve paths on the next screen.
                            </p>
                          )}
                        </div>
                      )}

                      {wantsArchive && (
                        <div className={s.field}>
                          <span className={s.label}>Image archive</span>
                          <div className={s.row}>
                            <input
                              readOnly
                              tabIndex={-1}
                              className={cx(s.input, s.mono, s.readonly, s.grow, fieldErrors.source && s.invalid)}
                              value={archive ? `${archive.name} · ${formatBytes(archive.size)}` : ""}
                              placeholder="No archive chosen"
                              aria-label="Chosen image archive"
                            />
                            <label className={buttonClass("secondary")}>
                              <input
                                type="file"
                                accept={ARCHIVE_ACCEPT}
                                className={s.hiddenInput}
                                onChange={(e) => chooseArchive(e.target.files)}
                                disabled={busy}
                              />
                              {archive ? "Change…" : "Browse…"}
                            </label>
                          </div>
                          {fieldErrors.source ? (
                            <p className={s.fieldError}>{fieldErrors.source}</p>
                          ) : (
                            <>
                              <p className={s.help}>
                                Save the image where it lives — <code>docker save myimage:tag -o image.tar</code>{" "}
                                — and upload the tar. No Docker daemon is needed on this host, and nothing is
                                pulled from a registry.
                              </p>
                              <p className={s.help}>
                                Left behind on the host: {VENDORED_DIRS.join(", ")}. Build output is kept — in
                                an image <code>dist</code> and <code>build</code> are often where the deployed
                                binary lives.
                              </p>
                            </>
                          )}
                        </div>
                      )}

                      {wantsUrl && (
                        <div className={s.field}>
                          <label className={s.label} htmlFor="source_ref">
                            Repository URL
                          </label>
                          <input
                            id="source_ref"
                            className={cx(s.input, s.mono, fieldErrors.source && s.invalid)}
                            value={sourceRef}
                            onChange={(e) => {
                              setSourceRef(e.target.value);
                              setFieldErrors((prev) => ({ ...prev, source: undefined }));
                            }}
                            placeholder="https://github.com/org/repo.git"
                          />
                          {fieldErrors.source && <p className={s.fieldError}>{fieldErrors.source}</p>}
                        </div>
                      )}
                    </>
                  ) : (
                    <p className={s.help}>A network-probe-only scan reads no files; only the targets below are contacted.</p>
                  )}
                </div>

                <div className={s.section}>
                  <Caps className={s.sectionCaps}>Scan mode</Caps>
                  <div className={s.cards} role="radiogroup" aria-label="Scan mode">
                    {MODES.map((option) => (
                      <label key={option.value} className={cx(s.card, mode === option.value && s.cardOn)}>
                        <input
                          type="radio"
                          name="mode"
                          value={option.value}
                          checked={mode === option.value}
                          onChange={() => {
                            setMode(option.value);
                            setFieldErrors({});
                          }}
                        />
                        <span className={s.cardTitle}>{option.title}</span>
                        <span className={s.cardText}>{option.text}</span>
                      </label>
                    ))}
                  </div>

                  {wantsProbe && (
                    <div className={s.field} style={{ marginTop: "var(--sp-4)" }}>
                      <label className={s.label} htmlFor="targets">
                        Probe targets <span className={s.labelHint}>host:port, one per line</span>
                      </label>
                      <textarea
                        id="targets"
                        className={cx(s.textarea, fieldErrors.targets && s.invalid)}
                        rows={4}
                        value={targets}
                        onChange={(e) => {
                          setTargets(e.target.value);
                          setFieldErrors((prev) => ({ ...prev, targets: undefined }));
                        }}
                        placeholder="10.0.4.12:443"
                      />
                      {fieldErrors.targets ? (
                        <p className={s.fieldError}>{fieldErrors.targets}</p>
                      ) : (
                        <p className={s.help}>
                          {targetCount > 0 && `${targetCount} target${targetCount === 1 ? "" : "s"} · `}
                          Entered explicitly, never inferred from scanned files · the prober refuses any host not
                          listed here
                        </p>
                      )}
                    </div>
                  )}

                  {/* X is asked for on the approval screen, where the user is
                      looking at their own file tree and can give one file a
                      different lifetime from the rest. A probe_only scan never
                      reaches that screen, so it is the one mode that still
                      answers here. Z is not asked for at all: it is an
                      assumption about the world rather than about this scan,
                      and it belongs beside the waves it moves, on the
                      overview. */}
                  {!wantsFiles && (
                    <div className={s.field}>
                      <label className={s.label} htmlFor="lifetime">
                        Data lifetime (X) <span className={s.labelHint}>years this traffic must stay confidential</span>
                      </label>
                      <input
                        id="lifetime"
                        type="number"
                        className={cx(s.input, s.mono)}
                        style={{ width: 120 }}
                        min={0}
                        max={100}
                        value={lifetime}
                        onChange={(e) => setLifetime(clampYears(e.target.value, lifetime))}
                      />
                      <p className={s.help}>
                        Mosca's inequality needs it: without X a probed key exchange can only be sent to Verify,
                        never placed in a wave.
                      </p>
                    </div>
                  )}
                </div>

                <div className={s.section}>
                  <div className={s.sectionHead}>
                    <Caps className={s.sectionCaps}>Collectors</Caps>
                    <span className={s.labelHint}>set by scan mode</span>
                  </div>
                  <ul className={s.collectors}>
                    {COLLECTORS.map((collector) => {
                      const runs = collector.modes.includes(mode);
                      return (
                        <li key={collector.name} className={cx(s.collector, !runs && s.collectorOff)}>
                          <span
                            className={cx(s.tick, runs && s.tickOn)}
                            role="img"
                            aria-label={runs ? "Runs in this mode" : "Does not run in this mode"}
                          >
                            {runs && (
                              <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden="true">
                                <path d="M2 5.2 4 7.2 8 3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                              </svg>
                            )}
                          </span>
                          <div>
                            <span className={s.collectorName}>{collector.name}</span>
                            <span className={s.collectorTools}>{collector.tools}</span>
                            <div className={s.collectorText}>{collector.description}</div>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              </fieldset>
            </div>

            <div className={s.footer}>
              <span className={s.footerText}>
                {busy
                  ? uploading
                    ? "Uploading · analysis has not started"
                    : wantsFiles
                      ? "Enumerating files · analysis has not started"
                      : "Probing targets"
                  : wantsFiles
                    ? `${collectorCount} collectors · next: approve discovered files`
                    : `${collectorCount} collector${collectorCount === 1 ? "" : "s"} · next: overview`}
              </span>
              <Button type="submit" variant="primary" disabled={busy}>
                {busy
                  ? uploading
                    ? "Uploading…"
                    : wantsFiles
                      ? "Surface scan running…"
                      : "Probing…"
                  : wantsFiles
                    ? "Run surface scan"
                    : "Run probe"}
              </Button>
            </div>
          </form>

          <div className={s.side}>
            <Panel title="Recent scans" flush className={s.recent} bodyClassName={s.recentBody}>
              {recent !== null && recent.length === 0 ? (
                <div className={s.recentEmpty}>
                  <p className={s.recentEmptyTitle}>No scans on this instance yet</p>
                  <p className={s.recentEmptyText}>
                    Completed scans and their file approvals are kept on this instance. Configure a target on the
                    left to begin.
                  </p>
                </div>
              ) : (
                <DataTable
                  className={s.recentTable}
                  columns={recentColumns}
                  rows={recent ?? []}
                  rowKey={(scan) => scan.id}
                  onRowClick={(scan) => navigate(scanHref(scan))}
                  loadingRows={recent === null ? 6 : 0}
                />
              )}
            </Panel>

            <Panel title="Offline content" meta="Stamped onto each scan at creation" flush>
              {policy && zYear !== null && (
                <dl className={s.kv}>
                  <dt className={s.kvLabel}>Policy pack</dt>
                  <dd className={s.kvValue} title={policy.version}>
                    {policy.version} · {policy.algorithm_rule_count} rules
                  </dd>
                  <dd className={cx(s.kvNote, policy.stale && s.kvStale)}>
                    {policy.stale ? `${policy.age_days} days old` : `published ${policy.published}`}
                  </dd>

                  <dt className={s.kvLabel}>PQC targets</dt>
                  <dd className={s.kvValue}>{policy.pqc_target_count} targets</dd>
                  <dd className={s.kvNote}>{policy.prefer_hybrid ? "hybrid preferred" : "pure PQC preferred"}</dd>

                  <dt className={s.kvLabel}>Mosca Z default</dt>
                  <dd className={s.kvValue}>
                    {zYear} · {policy.z_years_default} year{policy.z_years_default === 1 ? "" : "s"} from today
                  </dd>
                  <dd className={s.kvNote}>set by policy</dd>

                  <dt className={s.kvLabel}>Mosca Y default</dt>
                  <dd className={s.kvValue}>
                    {policy.y_years_default} year{policy.y_years_default === 1 ? "" : "s"}
                  </dd>
                  <dd className={s.kvNote}>set by policy</dd>
                </dl>
              )}
            </Panel>
          </div>
        </div>
      </PageBody>
    </>
  );
}
