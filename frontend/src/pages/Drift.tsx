import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, type AlignmentView } from "../api";

// §13 screen 5. Two states, both drawn: `compared`, with each note shown as
// what the config declared beside what the probe observed, and `skipped`, with
// the reason. "No drift found" and "drift was never checked" are different
// statements about a host, and an empty panel would make them look the same.

export default function Drift() {
  const { scanId = "" } = useParams();
  const [data, setData] = useState<AlignmentView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.alignment(scanId).then(setData).catch((err) => setError(err.message));
  }, [scanId]);

  if (error) return <div className="card text-sm text-red-800">{error}</div>;
  if (!data) return <div className="text-sm text-slate-500">Loading…</div>;

  if (data.status === "skipped") {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-semibold">Drift</h1>
        <div className="card">
          <span className="badge bg-slate-200 text-slate-700">Not checked</span>
          <p className="mt-2 text-sm">{data.reason}</p>
          <p className="mt-2 text-xs text-slate-500">
            The drift check compares what a configuration declares against what a probed service
            negotiates. It needs both: a <em>files and probe</em> scan with a config that declares TLS
            and a target that answers.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-semibold">Drift</h1>
        <span className="text-sm text-slate-600">
          {data.note_count} divergence{data.note_count === 1 ? "" : "s"} across{" "}
          {data.compared_services.length} probed service{data.compared_services.length === 1 ? "" : "s"}:{" "}
          <span className="font-mono text-xs">{data.compared_services.join(", ")}</span>
        </span>
      </div>

      {data.note_count === 0 && (
        <div className="card text-sm">
          <span className="badge bg-green-100 text-green-800">Aligned</span> Every declaration that
          covers a probed service matches what the service negotiated.
        </div>
      )}

      {data.notes.map((note) => (
        <div key={note.id} className="card space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">{note.asset_key}</div>
          <div className="grid gap-3 md:grid-cols-2">
            <Half
              title="Configuration declares"
              tone="bg-blue-50"
              location={note.config.evidence_location}
              rows={[
                ["Directive", String(note.declared?.directive ?? note.config.algorithm_name)],
                ["Declared", format(note.declared?.declared)],
                ["Kind", String(note.declared?.observation ?? "")],
                ["Protocol version", note.config.protocol_version ?? ""],
                [
                  "Activated",
                  note.declared?.activated_by_openssl_conf === undefined
                    ? ""
                    : note.declared.activated_by_openssl_conf
                      ? "yes"
                      : "no — the file is never applied",
                ],
              ]}
            />
            <Half
              title="Probe observed"
              tone="bg-amber-50"
              location={note.live.evidence_location}
              rows={[
                ["Service", `${note.observed?.host ?? ""}:${note.observed?.port ?? ""}`],
                ["Version", String(note.observed?.version ?? note.live.algorithm_name)],
                ["Offered", note.observed?.offered === undefined ? "" : note.observed.offered ? "accepted" : "refused"],
                [
                  "Suites",
                  note.observed?.accepted_suite_count === undefined
                    ? ""
                    : `${note.observed.accepted_suite_count} accepted, ${note.observed.rejected_suite_count} rejected`,
                ],
              ]}
            />
          </div>
          <p className="rounded border border-slate-200 bg-slate-50 p-3 text-sm">{note.note}</p>
        </div>
      ))}

      {data.scope_skipped.length > 0 && (
        <div className="card text-sm">
          <div className="label">Declarations not compared</div>
          <p className="mb-1 text-xs text-slate-500">
            Server-wide defaults a virtual host may override are not held against one probed service.
          </p>
          <ul className="list-disc pl-5 font-mono text-xs">
            {data.scope_skipped.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function format(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.join(" ");
  return String(value);
}

function Half({
  title,
  tone,
  location,
  rows,
}: {
  title: string;
  tone: string;
  location: string | null;
  rows: [string, string][];
}) {
  return (
    <div className={`rounded-md p-3 ${tone}`}>
      <div className="text-sm font-semibold">{title}</div>
      <div className="mb-2 font-mono text-xs text-slate-600">{location}</div>
      <dl className="grid grid-cols-3 gap-x-2 gap-y-0.5 text-xs">
        {rows
          .filter(([, value]) => value)
          .map(([key, value]) => (
            <Row key={key} label={key} value={value} />
          ))}
      </dl>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-slate-500">{label}</dt>
      <dd className="col-span-2 font-mono">{value}</dd>
    </>
  );
}
