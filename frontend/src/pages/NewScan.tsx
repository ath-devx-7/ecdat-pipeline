import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type Policy, type ProbeTarget, type Scan, type ScanMode, type SourceType } from "../api";
import { titleCase } from "../lib/labels";
import { formatBytes } from "../lib/tree";

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

// Vendored trees and caches. Never a deployed artefact, in a source tree or in
// an image, so they are dropped everywhere: here before the upload, and again on
// the host by `surface_exclude_dirs` (backend/app/config.py), which is what an
// image archive goes through — a tar cannot be filtered client-side. Keep this
// list and that one in step.
const VENDORED_DIRS = [".git", "node_modules", "__pycache__", ".venv", "venv"];

// Build output, dropped from a picked folder only. In a source tree it is
// scratch, and it would cost upload time and the file cap before a single
// source file reached the approval screen. In an *image* the same names are
// often where the deployed binary was COPYed to, so the backend does not prune
// them — see the note on `surface_exclude_dirs`.
const BUILD_OUTPUT_DIRS = ["dist", "build"];

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

// An upload's `source_ref` is the id the upload endpoint handed back, which is a
// UUID and says nothing to a person. Everything else names itself.
export function scanLabel(scan: Scan): string {
  if (scan.source_type === "upload") return "Uploaded folder";
  if (scan.source_type === "docker_archive") return "Uploaded image archive";
  const probed = scan.probe_targets?.map((target) => `${target.host}:${target.port}`).join(", ");
  return scan.source_ref || probed || scan.id;
}

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
  const [recent, setRecent] = useState<Scan[]>([]);

  useEffect(() => {
    api.policy().then(setPolicy);
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

  function choose(chosen: FileList | null) {
    const all = Array.from(chosen ?? []);
    if (all.length === 0) return; // picker dismissed; keep the previous choice
    const files = pickable(all);
    setUpload({ name: folderName(all), files, skipped: all.length - files.length });
  }

  function chooseArchive(chosen: FileList | null) {
    const picked = chosen?.[0];
    if (picked) setArchive(picked); // dialog dismissed; keep the previous choice
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      // Two steps, so POST /api/scans stays a JSON body: the bytes go to
      // /api/uploads and the scan names the id that comes back.
      let ref = sourceRef.trim();
      if (wantsUpload) {
        if (!upload) throw new Error("Choose a folder to upload first.");
        if (!upload.files.length) {
          throw new Error(
            `Every file in ${upload.name} was left behind as build output or a vendored ` +
              "dependency. Pick a folder holding source, config or certificates.",
          );
        }
        setUploading(true);
        try {
          ref = (await api.uploadFolder(upload.files)).upload_id;
        } finally {
          setUploading(false);
        }
      }
      if (wantsArchive) {
        if (!archive) throw new Error("Choose a saved image archive to upload first.");
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

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <form onSubmit={submit} className="card space-y-5 lg:col-span-2">
        <h1 className="text-xl font-semibold">New scan</h1>

        <div>
          <span className="label">Mode</span>
          <div className="flex gap-2">
            {(["files", "files_and_probe", "probe_only"] as ScanMode[]).map((option) => (
              <button
                type="button"
                key={option}
                onClick={() => setMode(option)}
                className={mode === option ? "btn" : "btn-secondary"}
              >
                {titleCase(option)}
              </button>
            ))}
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Drift detection needs both halves: only <em>files and probe</em> compares what a
            config declares against what the server negotiates.
          </p>
        </div>

        {wantsFiles && (
          <div className="grid gap-3 sm:grid-cols-3">
            <div>
              <label className="label" htmlFor="source_type">
                Source type
              </label>
              <select
                id="source_type"
                className="input"
                value={sourceType}
                onChange={(e) => setSourceType(e.target.value as SourceType)}
              >
                <option value="upload">Local folder</option>
                <option value="github">Git repository</option>
                <option value="docker_archive">Docker image</option>
              </select>
            </div>
            <div className="sm:col-span-2">
              {wantsUpload ? (
                <>
                  <span className="label">Folder</span>
                  <div className="flex flex-wrap items-center gap-2">
                    {/* The input is the control and the label is what it looks
                        like: a file input cannot be styled, and a button cannot
                        open a folder picker without one behind it. */}
                    <label className="btn-secondary cursor-pointer">
                      <input
                        type="file"
                        multiple
                        {...DIRECTORY_PICKER}
                        className="sr-only"
                        onChange={(e) => choose(e.target.files)}
                      />
                      {upload ? "Choose a different folder…" : "Browse…"}
                    </label>
                    {upload && (
                      <span className="truncate text-sm text-slate-700">
                        <span className="mono">{upload.name}</span> &mdash;{" "}
                        {upload.files.length} file{upload.files.length === 1 ? "" : "s"}
                        {upload.skipped > 0 && ` (${upload.skipped} skipped)`}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-slate-500">
                    {!upload
                      ? "Pick a folder anywhere on this machine. Your browser asks you to confirm before it reads it."
                      : upload.skipped > 0
                        ? `Left behind: ${[...SKIPPED_DIRS].join(", ")}. Build output and vendored trees are not deployed artefacts, and they would consume the file cap before a single source file reached the approval screen.`
                        : "Ready to upload."}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    The bytes are stored on the ECDAT host, but nothing is read from them until
                    you approve paths on the next screen.
                  </p>
                </>
              ) : wantsArchive ? (
                <>
                  <span className="label">Image archive</span>
                  <div className="flex flex-wrap items-center gap-2">
                    <label className="btn-secondary cursor-pointer">
                      <input
                        type="file"
                        accept={ARCHIVE_ACCEPT}
                        className="sr-only"
                        onChange={(e) => chooseArchive(e.target.files)}
                      />
                      {archive ? "Choose a different archive…" : "Browse…"}
                    </label>
                    {archive && (
                      <span className="truncate text-sm text-slate-700">
                        <span className="mono">{archive.name}</span> &mdash;{" "}
                        {formatBytes(archive.size)}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-slate-500">
                    Save the image where it lives &mdash;{" "}
                    <code>docker save myimage:tag -o image.tar</code> &mdash; and upload the
                    tar. No Docker daemon is needed on this host, and nothing is pulled from a
                    registry.
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    The layers are unpacked into the image&rsquo;s final filesystem and listed
                    on the next screen. Nothing inside is read until you approve paths.
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Left behind, as for a folder: {VENDORED_DIRS.join(", ")}. A tar cannot be
                    filtered in the browser, so these are dropped on the host when the unpacked
                    image is listed. Build output is kept here, unlike for a folder &mdash; in
                    an image <code>dist</code> and <code>build</code> are often where the
                    deployed binary lives.
                  </p>
                </>
              ) : (
                <>
                  <label className="label" htmlFor="source_ref">
                    Clone URL
                  </label>
                  <input
                    id="source_ref"
                    className="input"
                    value={sourceRef}
                    onChange={(e) => setSourceRef(e.target.value)}
                    placeholder="https://github.com/org/repo.git"
                    required
                  />
                </>
              )}
            </div>
          </div>
        )}

        {wantsProbe && (
          <div>
            <label className="label" htmlFor="targets">
              Probe targets — one <code>host:port</code> per line
            </label>
            <textarea
              id="targets"
              className="input font-mono"
              rows={3}
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder={"localhost:8443\nlocalhost:8444"}
              required
            />
            <p className="mt-1 text-xs text-slate-500">
              Entered explicitly, never inferred from scanned files. The prober refuses any host
              not listed here.
            </p>
          </div>
        )}

        {/* X is asked for on the approval screen, where the user is looking at
            their own file tree and can give one file a different lifetime from
            the rest — a judgement nobody can make against an empty form. A
            probe_only scan never reaches that screen, so it is the one mode
            that still answers here. Z is not asked for at all: it is an
            assumption about the world rather than about this scan, and it
            belongs beside the waves it moves, on the overview. */}
        {!wantsFiles && (
          <div className="sm:w-1/2">
            <label className="label" htmlFor="lifetime">
              Data lifetime (X) — years these hosts' traffic must stay confidential
            </label>
            <input
              id="lifetime"
              type="number"
              className="input"
              min={0}
              max={100}
              value={lifetime}
              onChange={(e) => setLifetime(clampYears(e.target.value, lifetime))}
            />
            <p className="mt-1 text-xs text-slate-500">
              Mosca's inequality needs it: without X a probed key exchange can only be sent to
              Verify, never placed in a wave.
            </p>
          </div>
        )}

        {error && <div className="rounded-md bg-red-50 p-3 text-sm text-red-800">{error}</div>}

        <p className="text-xs text-slate-500">
          Policy pack {policy?.version ?? "…"} — stamped onto this scan at creation, so every
          verdict stays reproducible against the pack that produced it.
        </p>

        <button className="btn" disabled={busy}>
          {uploading
            ? "Uploading…"
            : busy
              ? "Staging…"
              : wantsFiles
                ? "Stage and choose files"
                : "Probe now"}
        </button>
      </form>

      <aside className="card">
        <h2 className="mb-2 text-sm font-semibold">Recent scans</h2>
        {recent.length === 0 && <p className="text-sm text-slate-500">None yet.</p>}
        <ul className="divide-y divide-slate-100 text-sm">
          {recent.map((scan) => (
            <li key={scan.id} className="py-2">
              <Link
                to={scan.status === "awaiting_approval" ? `/scans/${scan.id}/files` : `/scans/${scan.id}`}
                className="font-medium text-slate-900 hover:underline"
              >
                {scanLabel(scan)}
              </Link>
              <div className="text-xs text-slate-500">
                {titleCase(scan.mode)} · {titleCase(scan.status)} · {scan.created_at?.slice(0, 16).replace("T", " ")}
              </div>
            </li>
          ))}
        </ul>
      </aside>
    </div>
  );
}
