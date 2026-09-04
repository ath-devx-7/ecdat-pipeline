import type { ReactNode } from "react";
import type { ScanDiagnostics, ScanStatus } from "../api";
import { titleCase } from "../lib/labels";

// Why a scan's result looks the way it does, in one line.
//
// "This scan is partial" on its own is not actionable — an empty result and a
// broken one read identically. But the answer is a sentence, not a page: the
// banner names the collector that stopped and the extensions nothing ruled on,
// and the per-collector and per-extension tables sit behind a disclosure for the
// reader who wants them. An explanation long enough to push the findings below
// the fold has replaced one problem with another.

export function ScanCoverage({
  status,
  diagnostics,
}: {
  status: ScanStatus;
  diagnostics: ScanDiagnostics | null;
}) {
  // A scan stored before diagnostics existed has none. That is not the same as
  // "nothing degraded", so nothing reassuring is rendered from a missing value.
  if (!diagnostics) {
    if (status !== "partial") return null;
    return (
      <Banner tone="warn">
        This scan is <strong>partial</strong> and predates per-collector reporting, so which
        collector degraded is not recorded. The findings are incomplete, not wrong.
      </Banner>
    );
  }

  const degraded = diagnostics.collectors.filter((run) => run.ran && run.error);
  const blind = diagnostics.extensions.filter(
    (entry) => entry.code_scanned && !entry.ruled && entry.approved_files > 0,
  );
  const partial = status === "partial";

  // Nothing broke and every scanned extension had a rule behind it.
  if (!partial && degraded.length === 0 && blind.length === 0) return null;

  const blindFiles = blind.reduce((total, entry) => total + entry.approved_files, 0);

  return (
    <Banner tone={partial ? "warn" : "muted"}>
      <span>
        {partial && (
          <>
            <strong>Partial scan</strong> — findings are incomplete, not wrong.{" "}
          </>
        )}
        {degraded.length > 0 && (
          <>
            {degraded.map((run) => titleCase(run.name)).join(", ")} stopped early
            {degraded[0].reason ? `: ${degraded[0].reason}` : ""}.{" "}
          </>
        )}
        {blind.length > 0 && (
          <>
            {blindFiles} file{blindFiles === 1 ? "" : "s"} in{" "}
            {blind.map((entry) => entry.extension).join(", ")} had no rule behind{" "}
            {blind.length === 1 ? "it" : "them"} — zero findings there means nothing was
            looked for.
          </>
        )}
      </span>{" "}
      <details className="mt-1">
        <summary className="cursor-pointer underline">Coverage detail</summary>
        <CollectorTable diagnostics={diagnostics} />
        <ExtensionTable diagnostics={diagnostics} />
      </details>
    </Banner>
  );
}

function Banner({ tone, children }: { tone: "warn" | "muted"; children: ReactNode }) {
  const palette =
    tone === "warn" ? "bg-amber-50 text-amber-900" : "bg-slate-50 text-slate-700";
  return <div className={`w-full rounded-md p-2 text-xs ${palette}`}>{children}</div>;
}

function CollectorTable({ diagnostics }: { diagnostics: ScanDiagnostics }) {
  if (diagnostics.collectors.length === 0) return null;
  return (
    <div className="mt-2 overflow-x-auto">
      <table className="w-full min-w-[30rem] text-left">
        <thead className="text-[0.65rem] uppercase tracking-wide opacity-70">
          <tr>
            <th className="py-1 pr-3 font-medium">Collector</th>
            <th className="py-1 pr-3 font-medium">Files</th>
            <th className="py-1 pr-3 font-medium">Findings</th>
            <th className="py-1 pr-3 font-medium">Time</th>
            <th className="py-1 font-medium">Result</th>
          </tr>
        </thead>
        <tbody className="align-top">
          {diagnostics.collectors.map((run) => (
            <tr key={run.name} className="border-t border-black/10">
              <td className="py-1 pr-3">{titleCase(run.name)}</td>
              <td className="py-1 pr-3 font-mono">{run.ran ? run.file_count : "—"}</td>
              <td className="py-1 pr-3 font-mono">{run.ran ? run.finding_count : "—"}</td>
              <td className="py-1 pr-3 font-mono">
                {run.ran ? `${run.duration_seconds.toFixed(2)}s` : "—"}
              </td>
              <td className="py-1">
                {!run.ran ? (
                  <span className="opacity-70">not run in this scan mode</span>
                ) : run.reason ? (
                  <span className="font-medium">{run.reason}</span>
                ) : (
                  <span className="opacity-70">ok</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ExtensionTable({ diagnostics }: { diagnostics: ScanDiagnostics }) {
  // Already ordered by approved files descending: the extension with the most
  // files and the fewest findings is the one worth looking at.
  const rows = diagnostics.extensions.filter((entry) => entry.approved_files > 0).slice(0, 10);
  if (rows.length === 0) return null;
  const hidden = diagnostics.extensions.length - rows.length;

  return (
    <div className="mt-2 overflow-x-auto">
      <table className="w-full min-w-[30rem] text-left">
        <thead className="text-[0.65rem] uppercase tracking-wide opacity-70">
          <tr>
            <th className="py-1 pr-3 font-medium">Extension</th>
            <th className="py-1 pr-3 font-medium">Approved</th>
            <th className="py-1 pr-3 font-medium">Findings</th>
            <th className="py-1 font-medium">Coverage</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((entry) => (
            <tr key={entry.extension} className="border-t border-black/10">
              <td className="py-1 pr-3 font-mono">{entry.extension}</td>
              <td className="py-1 pr-3 font-mono">{entry.approved_files}</td>
              <td className="py-1 pr-3 font-mono">{entry.finding_count}</td>
              <td className="py-1">
                {!entry.code_scanned ? (
                  <span className="opacity-70">not a code extension</span>
                ) : entry.ruled ? (
                  <span className="opacity-70">code rules apply</span>
                ) : (
                  <span className="font-medium">no rule for this language</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {hidden > 0 && (
        <p className="mt-1 opacity-70">{hidden} further extensions not shown.</p>
      )}
    </div>
  );
}
