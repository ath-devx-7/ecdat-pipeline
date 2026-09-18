import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type ApproveResponse, type DirectoryNode, type FileTree, type TreeNode } from "../api";
import { countSelected, filePaths, formatBytes, selectAll, selectionState, toggleNode } from "../lib/tree";

// §13 screen 2 — the permission gate. Nothing has been read yet; the tree is
// path and size only, and the paths ticked here are exactly the list the
// collectors are allowed to open. The screen blocks until submitted.
//
// It is also where X is answered (§12). The data lifetime is the one Mosca
// input nobody can measure from a file, and this is the only screen where the
// user is looking at their own tree — "the customer records have to stay secret
// for thirty years and the build cache does not" is a judgement about *these*
// paths, and it cannot be made against an empty form on the previous screen.
//
// The global number applies to everything. Set a folder and every file beneath
// it takes that value, overwriting whatever those files had — a folder is the
// coarse gesture, and a folder edit that left some children behind would be a
// gesture whose result the user could not predict. Rows that differ from the
// global are shaded, so the exceptions are visible without opening anything.

//: The scan-wide X the screen opens with. A working default, not a measurement.
const DEFAULT_X = 20;

//: Years, bounded to what the API accepts. A blank or unparseable box keeps the
//: previous value rather than silently becoming zero — "0 years" is a real
//: answer about data and must be typed deliberately.
function clampYears(entered: string, previous: number): number {
  const value = Number(entered);
  if (entered.trim() === "" || Number.isNaN(value)) return previous;
  return Math.min(100, Math.max(0, Math.trunc(value)));
}

//: Every file path under a node — a folder edit applies to exactly these.
function descendantPaths(node: TreeNode): string[] {
  if (node.type === "file") return [node.path];
  return node.children.flatMap(descendantPaths);
}

//: What one row is scored at: its own value if it has one, else the global.
function effectiveYears(path: string, perFile: Map<string, number>, global: number): number {
  const own = perFile.get(path);
  return own === undefined ? global : own;
}

//: A folder reads as changed when anything under it differs from the global,
//: which is what makes an exception visible without expanding the tree.
function differsFromGlobal(node: TreeNode, perFile: Map<string, number>, global: number): boolean {
  return descendantPaths(node).some((path) => effectiveYears(path, perFile, global) !== global);
}

export default function FileSelection() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const [tree, setTree] = useState<FileTree | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set([""]));
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ApproveResponse | null>(null);
  const [years, setYears] = useState(DEFAULT_X);
  //: Only the files that differ. An absent path means "whatever the scan says",
  //: which is a different claim from "the same number, written down twice".
  const [perFile, setPerFile] = useState<Map<string, number>>(new Map());

  useEffect(() => {
    api
      .files(scanId)
      .then((loaded) => {
        setTree(loaded);
        // A re-opened tree shows the lifetimes that were actually stored.
        const stored = new Map<string, number>();
        const walk = (node: TreeNode) => {
          if (node.type === "file") {
            if (node.data_lifetime_years !== null) stored.set(node.path, node.data_lifetime_years);
          } else node.children.forEach(walk);
        };
        walk(loaded.root);
        if (stored.size > 0) setPerFile(stored);
        // Open the first level so the tree is readable without a click.
        setExpanded(new Set(["", ...loaded.root.children.filter((c) => c.type === "directory").map((c) => c.path)]));
      })
      .catch((err) => setError(err.message));
  }, [scanId]);

  const total = useMemo(() => (tree ? filePaths(tree.root).length : 0), [tree]);

  async function approve() {
    setRunning(true);
    setError(null);
    try {
      // Only overrides that still differ from the global are worth sending:
      // a file the user set to the same number as everything else is not an
      // exception, and storing it as one would make the report read like one.
      const overrides: Record<string, number> = {};
      for (const [path, value] of perFile) {
        if (value !== years) overrides[path] = value;
      }
      const outcome = await api.approve(scanId, [...selected], { years, perFile: overrides });
      setResult(outcome);
      navigate(`/scans/${scanId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  }

  if (error && !tree) {
    return (
      <div className="card text-sm text-red-800">
        {error} — <Link to="/" className="underline">start a new scan</Link>
      </div>
    );
  }
  if (!tree) return <div className="text-sm text-slate-500">Loading the file tree…</div>;

  if (tree.status !== "awaiting_approval") {
    return (
      <div className="card text-sm">
        This scan is <strong>{tree.status}</strong>; its file selection has already been submitted.{" "}
        <Link to={`/scans/${scanId}`} className="underline">Open the overview.</Link>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="card flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">Choose what may be read</h1>
        <span className="text-sm text-slate-600">
          <strong>{selected.size}</strong> of {total} files selected
        </span>
        <div className="ml-auto flex items-center gap-2">
          <label className="flex items-center gap-2 text-sm" htmlFor="years">
            <span className="text-slate-600">Data lifetime (X)</span>
            <input
              id="years"
              type="number"
              className="w-20 rounded-md border border-slate-300 bg-white px-2 py-1 text-sm focus:border-slate-500 focus:outline-none"
              min={0}
              max={100}
              value={years}
              disabled={running}
              onChange={(e) => setYears(clampYears(e.target.value, years))}
            />
            <span className="text-slate-600">years</span>
          </label>
          <button className="btn-secondary" onClick={() => setSelected(selectAll(tree.root))} disabled={running}>
            Select all
          </button>
          <button className="btn-secondary" onClick={() => setSelected(new Set())} disabled={running}>
            Clear
          </button>
          <button className="btn-secondary" onClick={() => setExpanded(allDirectories(tree.root))} disabled={running}>
            Expand all
          </button>
          <button className="btn-secondary" onClick={() => setExpanded(new Set([""]))} disabled={running}>
            Collapse all
          </button>
          <button className="btn" onClick={approve} disabled={running || selected.size === 0}>
            {running ? "Running collectors…" : `Approve ${selected.size} and scan`}
          </button>
        </div>
      </div>

      <p className="px-1 text-xs text-slate-500">
        How long this data must stay confidential — X in Mosca's inequality. Every file uses the
        number above unless you give it its own; setting a folder sets everything inside it.
        Changed rows are shaded.
      </p>

      {running && (
        <div className="rounded-md border border-slate-200 bg-white p-3 text-sm text-slate-700">
          Collectors are running over the approved paths only. This request blocks until every
          collector has finished or hit its budget.
        </div>
      )}
      {error && <div className="rounded-md bg-red-50 p-3 text-sm text-red-800">{error}</div>}
      {result && <div className="text-sm text-slate-600">Scan {result.status}: {result.finding_count} findings.</div>}

      <div className="card overflow-x-auto">
        <ul className="text-sm">
          {tree.root.children.map((child) => (
            <TreeRow
              key={child.path}
              node={child}
              depth={0}
              selected={selected}
              expanded={expanded}
              years={years}
              perFile={perFile}
              onYears={(node, value) =>
                setPerFile((current) => {
                  const next = new Map(current);
                  // A folder assigns to every file under it, so the value the
                  // user typed on the folder is the value each file now has.
                  for (const path of descendantPaths(node)) next.set(path, value);
                  return next;
                })
              }
              onToggle={(node) => setSelected(toggleNode(selected, node))}
              onExpand={(path) =>
                setExpanded((current) => {
                  const next = new Set(current);
                  if (next.has(path)) next.delete(path);
                  else next.add(path);
                  return next;
                })
              }
            />
          ))}
        </ul>
      </div>
    </div>
  );
}

function allDirectories(root: DirectoryNode): Set<string> {
  const paths = new Set<string>([""]);
  const walk = (node: TreeNode) => {
    if (node.type === "directory") {
      paths.add(node.path);
      node.children.forEach(walk);
    }
  };
  walk(root);
  return paths;
}

function TreeRow({
  node,
  depth,
  selected,
  expanded,
  years,
  perFile,
  onYears,
  onToggle,
  onExpand,
}: {
  node: TreeNode;
  depth: number;
  selected: Set<string>;
  expanded: Set<string>;
  years: number;
  perFile: Map<string, number>;
  onYears: (node: TreeNode, value: number) => void;
  onToggle: (node: TreeNode) => void;
  onExpand: (path: string) => void;
}) {
  const state = selectionState(selected, node);
  const checkbox = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (checkbox.current) checkbox.current.indeterminate = state === "some";
  }, [state]);

  const isDirectory = node.type === "directory";
  const open = isDirectory && expanded.has(node.path);

  // A folder's box shows one number only when everything under it agrees;
  // a mixed folder shows blank rather than picking one of its children's
  // values and implying the others match it.
  const descendants = descendantPaths(node);
  const values = new Set(descendants.map((path) => effectiveYears(path, perFile, years)));
  const shown = values.size === 1 ? [...values][0] : "";
  const changed = differsFromGlobal(node, perFile, years);

  return (
    <li>
      <div
        className={`flex items-center gap-2 rounded px-1 py-0.5 hover:bg-slate-100 ${
          changed ? "bg-slate-200/70" : ""
        }`}
        style={{ paddingLeft: `${depth * 1.25}rem` }}
      >
        {isDirectory ? (
          <button
            type="button"
            className="w-4 text-slate-500"
            onClick={() => onExpand(node.path)}
            aria-label={open ? "Collapse" : "Expand"}
          >
            {open ? "▾" : "▸"}
          </button>
        ) : (
          <span className="w-4" />
        )}
        <input
          ref={checkbox}
          type="checkbox"
          checked={state === "all"}
          onChange={() => onToggle(node)}
          aria-label={node.path}
        />
        <span className={isDirectory ? "font-medium" : ""}>{node.name}</span>
        {isDirectory ? (
          <span className="text-xs text-slate-500">
            {countSelected(selected, node)}/{node.file_count} · {formatBytes(node.size_bytes)}
          </span>
        ) : (
          <span className="text-xs text-slate-400">{formatBytes(node.size_bytes)}</span>
        )}
        <label className="ml-auto flex items-center gap-1 text-xs text-slate-500">
          <input
            type="number"
            className="w-16 rounded border border-slate-300 bg-white px-1 py-0.5 text-xs focus:border-slate-500 focus:outline-none"
            min={0}
            max={100}
            value={shown}
            placeholder="mixed"
            aria-label={`Data lifetime for ${node.path}`}
            onChange={(e) => onYears(node, clampYears(e.target.value, years))}
          />
          y
        </label>
      </div>
      {open && (
        <ul>
          {(node as DirectoryNode).children.map((child) => (
            <TreeRow
              key={child.path}
              years={years}
              perFile={perFile}
              onYears={onYears}
              node={child}
              depth={depth + 1}
              selected={selected}
              expanded={expanded}
              onToggle={onToggle}
              onExpand={onExpand}
            />
          ))}
        </ul>
      )}
    </li>
  );
}
