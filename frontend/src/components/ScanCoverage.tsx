import type { ScanDiagnostics, ScanStatus } from "../api";
import { titleCase } from "../lib/labels";

// What a `partial` scan actually lost, and what a `complete` one may never have
// looked for.
//
// "This scan is partial" on its own is not an actionable sentence: an empty
// result and a broken one read identically. Two tables replace it. The first
// names every collector — including the ones this scan's mode never called, so
// silence is legible — with what it was handed, what it returned, and the reason
// it stopped. The second pairs approved files against findings per extension,
// because 300 .go files with 0 findings is either a codebase with no crypto in
// it or a scanner with no Go rules, and only the rule column separates them.

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
      <div className="w-full rounded-md bg-amber-50 p-2 text-xs text-amber-900">
        This scan is <strong>partial</strong>: at least one collector failed or ran out of
        budget, and this scan predates per-collector reporting, so which one is not recorded.
        The findings below are incomplete, not wrong.
      </div>
    );
  }

  const degraded = diagnostics.collectors.filter((run) => run.ran && run.error);
  const blind = diagnostics.extensions.filter(
    (entry) => entry.code_scanned && !entry.ruled && entry.approved_files > 0,
  );

  // Nothing broke and every scanned extension had a rule behind it: there is no
  // gap to explain, so no panel.
  if (status !== "partial" && degraded.length === 0 && blind.length === 0) return null;

  const partial = status === "partial";
  const tone = partial ? "bg-amber-50 text-amber-900" : "bg-slate-50 text-slate-700";

  return (
    <div className={`w-full rounded-md p-3 text-xs ${tone}`}>
      <p>
        {partial ? (
          <>
            This scan is <strong>partial</strong>: the findings below are incomplete, not
            wrong.{" "}
            {degraded.length > 0
              ? `${degraded.length} collector${degraded.length === 1 ? "" : "s"} degraded.`
              : "No collector reported a failure — the gap is in coverage, below."}
          </>
        ) : (
          <>
            This scan completed, but{" "}
            <strong>
              {blind.length} scanned extension{blind.length === 1 ? "" : "s"}
            </strong>{" "}
            had no rule behind {blind.length === 1 ? "it" : "them"}. Zero findings there means
            nothing was looked for.
          </>
        )}
      </p>

      <CollectorTable diagnostics={diagnostics} />
      <ExtensionTable diagnostics={diagnostics} />
    </div>
  );
}

function CollectorTable({ diagnostics }: { diagnostics: ScanDiagnostics }) {
  if (diagnostics.collectors.length === 0) return null;
  return (
    <div className="mt-3 overflow-x-auto">
      <table className="w-full min-w-[32rem] text-left">
        <thead className="text-[0.65rem] uppercase tracking-wide opacity-70">
          <tr>
            <th className="py-1 pr-3 font-medium">Collector</th>
            <th className="py-1 pr-3 font-medium">Files handed</th>
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
  const rows = diagnostics.extensions.filter((entry) => entry.approved_files > 0).slice(0, 12);
  if (rows.length === 0) return null;
  const hidden = diagnostics.extensions.length - rows.length;

  return (
    <div className="mt-3 overflow-x-auto">
      <div className="text-[0.65rem] uppercase tracking-wide opacity-70">
        Approved files against findings, by extension
      </div>
      <table className="mt-1 w-full min-w-[32rem] text-left">
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
        <p className="mt-1 opacity-70">
          {hidden} further extension{hidden === 1 ? "" : "s"} not shown.
        </p>
      )}
    </div>
  );
}
