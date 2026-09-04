import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, zStorageKey, type Policy, type ProbeTarget, type Scan, type ScanMode, type SourceType } from "../api";
import { titleCase } from "../lib/labels";

// §13 screen 1. The data-lifetime dropdown is X in Mosca's inequality and the
// Z slider is the arrival assumption; both are inputs a person supplies, and
// the slider default is read from the policy pack rather than hardcoded.

const LIFETIMES: { label: string; years: number }[] = [
  { label: "< 1 year", years: 0 },
  { label: "5–10 years", years: 10 },
  { label: "20+ years", years: 20 },
];

// `webkitdirectory` is what turns a file input into a folder picker, and it is
// not in React's typings; spread as a plain record rather than cast away the
// props type of the whole element.
const DIRECTORY_PICKER: Record<string, string> = { webkitdirectory: "", directory: "" };

// Dropped before anything is sent. These are build output and vendored trees:
// they are not deployed artefacts, and they would consume the per-scan file cap
// before a single source file reached the approval screen. Here it also costs
// upload time, because every one of them would go over the wire first.
const SKIPPED_DIRS = new Set([
  ".git",
  "node_modules",
  "__pycache__",
  ".venv",
  "venv",
  "dist",
  "build",
]);

export interface PickedFolder {
  // the folder the user picked, which is the first segment of every path
  name: string;
  // what will actually be uploaded, after `pickable`
  files: File[];
  // how many the filter dropped, so the count on screen is never silently short
  skipped: number;
}

// An upload's `source_ref` is the upload id, which is a UUID and says nothing
// to a person. Everything else names itself.
export function scanLabel(scan: Scan): string {
  if (scan.source_type === "upload") return "Uploaded folder";
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
  const [targets, setTargets] = useState("");
  const [lifetime, setLifetime] = useState(20);
  const [z, setZ] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent, setRecent] = useState<Scan[]>([]);

  useEffect(() => {
    api.policy().then((p) => {
      setPolicy(p);
      setZ((current) => current ?? p.z_years_default);
    });
    api.scans().then(setRecent).catch(() => setRecent([]));
  }, []);

  const wantsFiles = mode !== "probe_only";
  const wantsProbe = mode !== "files";
  const wantsUpload = wantsFiles && sourceType === "upload";

  function choose(chosen: FileList | null) {
    const all = Array.from(chosen ?? []);
    if (all.length === 0) return; // picker dismissed; keep the previous choice
    const files = pickable(all);
    setUpload({ name: folderName(all), files, skipped: all.length - files.length });
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
      const scan = await api.createScan({
        mode,
        source_type: wantsFiles ? sourceType : "none",
        source_ref: wantsFiles ? ref : undefined,
        probe_targets: wantsProbe ? parseTargets(targets) : [],
        data_lifetime_years: lifetime,
      });
      if (z !== null) localStorage.setItem(zStorageKey(scan.id), String(z));
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
                <option value="docker_image">Docker image</option>
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
              ) : (
                <>
                  <label className="label" htmlFor="source_ref">
                    {sourceType === "github" ? "Clone URL" : "Image tag"}
                  </label>
                  <input
                    id="source_ref"
                    className="input"
                    value={sourceRef}
                    onChange={(e) => setSourceRef(e.target.value)}
                    placeholder={
                      sourceType === "github"
                        ? "https://github.com/org/repo.git"
                        : "registry/image:tag"
                    }
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

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="lifetime">
              Data lifetime (X — how long the data must stay confidential)
            </label>
            <select
              id="lifetime"
              className="input"
              value={lifetime}
              onChange={(e) => setLifetime(Number(e.target.value))}
            >
              {LIFETIMES.map((option) => (
                <option key={option.years} value={option.years}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="z">
              Years until a cryptographically relevant quantum computer (Z)
              {z !== null && <span className="ml-2 text-slate-800">{z}</span>}
            </label>
            <input
              id="z"
              type="range"
              min={1}
              max={40}
              value={z ?? 12}
              disabled={z === null}
              onChange={(e) => setZ(Number(e.target.value))}
              className="w-full"
            />
            <p className="mt-1 text-xs text-slate-500">
              Policy default {policy?.z_years_default ?? "…"} years (pack {policy?.version ?? "…"}).
              Z is an assumption, not a measurement; it can be moved again on the overview.
            </p>
          </div>
        </div>

        {error && <div className="rounded-md bg-red-50 p-3 text-sm text-red-800">{error}</div>}

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
