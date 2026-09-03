import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type ApproveResponse, type DirectoryNode, type FileTree, type TreeNode } from "../api";
import { countSelected, filePaths, formatBytes, selectAll, selectionState, toggleNode } from "../lib/tree";

// §13 screen 2 — the permission gate. Nothing has been read yet; the tree is
// path and size only, and the paths ticked here are exactly the list the
// collectors are allowed to open. The screen blocks until submitted.

export default function FileSelection() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const [tree, setTree] = useState<FileTree | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set([""]));
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ApproveResponse | null>(null);

  useEffect(() => {
    api
      .files(scanId)
      .then((loaded) => {
        setTree(loaded);
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
      const outcome = await api.approve(scanId, [...selected]);
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
        <div className="ml-auto flex gap-2">
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
  onToggle,
  onExpand,
}: {
  node: TreeNode;
  depth: number;
  selected: Set<string>;
  expanded: Set<string>;
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

  return (
    <li>
      <div
        className="flex items-center gap-2 rounded px-1 py-0.5 hover:bg-slate-50"
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
      </div>
      {open && (
        <ul>
          {(node as DirectoryNode).children.map((child) => (
            <TreeRow
              key={child.path}
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
