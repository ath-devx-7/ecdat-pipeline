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
  const [sourceType, setSourceType] = useState<SourceType>("folder");
  const [sourceRef, setSourceRef] = useState("");
  const [targets, setTargets] = useState("");
  const [lifetime, setLifetime] = useState(20);
  const [z, setZ] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
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

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const scan = await api.createScan({
        mode,
        source_type: wantsFiles ? sourceType : "none",
        source_ref: wantsFiles ? sourceRef.trim() : undefined,
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
                <option value="folder">Local folder</option>
                <option value="github">Git repository</option>
                <option value="docker_image">Docker image</option>
              </select>
            </div>
            <div className="sm:col-span-2">
              <label className="label" htmlFor="source_ref">
                {sourceType === "folder" ? "Path" : sourceType === "github" ? "Clone URL" : "Image tag"}
              </label>
              <input
                id="source_ref"
                className="input"
                value={sourceRef}
                onChange={(e) => setSourceRef(e.target.value)}
                placeholder={
                  sourceType === "folder"
                    ? "/absolute/path/to/ecdat_pipeline/demo"
                    : sourceType === "github"
                      ? "https://github.com/org/repo.git"
                      : "registry/image:tag"
                }
                required
              />
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
          {busy ? "Staging…" : wantsFiles ? "Stage and choose files" : "Probe now"}
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
                {scan.source_ref ?? scan.probe_targets?.map((t) => `${t.host}:${t.port}`).join(", ") ?? scan.id}
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
