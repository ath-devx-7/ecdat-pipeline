import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type DirectoryNode, type FileNode, type FileTree, type TreeNode } from "../api";
import { PageBody, PageHeader } from "../components/ui/AppShell";
import { DataTable, type Column } from "../components/ui/DataTable";
import { FilterSelect } from "../components/ui/FilterBar";
import { Icon } from "../components/ui/Icon";
import { Button, buttonClass, Panel } from "../components/ui/primitives";
import { StatePanel } from "../components/ui/StatePanel";
import { cx } from "../components/ui/tone";
import { VENDORED_DIRS } from "../lib/exclusions";
import { SCAN_STATUS_LABEL } from "../lib/labels";
import { formatBytes } from "../lib/tree";
import { useElapsed } from "../lib/useElapsed";
import s from "./FileSelection.module.css";

// §13 screen 2 — the permission gate. Nothing has been read yet; the tree is
// path and size only, and the paths ticked here are exactly the list the
// collectors are allowed to open. The screen blocks until submitted.
//
// The target is shown as it is laid out on disk: every folder and subfolder,
// each with a checkbox that selects or clears everything beneath it. While a
// filter is set, a folder's checkbox and "Select all" act on the files the
// filter shows, never on hidden ones.
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

const n = (value: number) => value.toLocaleString("en-US");

//: Years, bounded to what the API accepts. A blank or unparseable box keeps the
//: previous value rather than silently becoming zero — "0 years" is a real
//: answer about data and must be typed deliberately.
function clampYears(entered: string, previous: number): number {
  const value = Number(entered);
  if (entered.trim() === "" || Number.isNaN(value)) return previous;
  return Math.min(100, Math.max(0, Math.trunc(value)));
}

//: ".py", or "(none)" for a name with no extension. Dotfiles have none.
function extensionOf(path: string): string {
  const name = path.slice(path.lastIndexOf("/") + 1);
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot).toLowerCase() : "(none)";
}

//: The path box takes a substring or a `*` glob, case-insensitive.
function pathMatcher(query: string): (path: string) => boolean {
  const trimmed = query.trim();
  if (!trimmed) return () => true;
  const pattern = trimmed.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  const re = new RegExp(pattern, "i");
  return (path) => re.test(path);
}

interface TreeIndex {
  files: FileNode[];
  // every file path at or below each folder, keyed by the folder's path
  under: Map<string, string[]>;
  folders: string[];
}

// Walked once per tree, so a checkbox never re-walks the subtree under it.
function indexTree(root: DirectoryNode): TreeIndex {
  const files: FileNode[] = [];
  const under = new Map<string, string[]>();
  const folders: string[] = [];
  const walk = (node: TreeNode): string[] => {
    if (node.type === "file") {
      files.push(node);
      return [node.path];
    }
    folders.push(node.path);
    const paths = node.children.flatMap(walk);
    under.set(node.path, paths);
    return paths;
  };
  walk(root);
  return { files, under, folders };
}

type Tri = "none" | "some" | "all";

function triState(paths: string[], selected: Set<string>): Tri {
  if (paths.length === 0) return "none";
  let chosen = 0;
  for (const path of paths) if (selected.has(path)) chosen += 1;
  return chosen === 0 ? "none" : chosen === paths.length ? "all" : "some";
}

interface Row {
  node: TreeNode;
  depth: number;
}

// The visible rows, in tree order. While a filter is set every folder holding
// a match is open, so a match is never hidden behind a collapsed parent.
function flatten(root: DirectoryNode, expanded: Set<string>, visible: Set<string> | null, index: TreeIndex): Row[] {
  const rows: Row[] = [];
  const walk = (node: TreeNode, depth: number) => {
    if (node.type === "file") {
      if (!visible || visible.has(node.path)) rows.push({ node, depth });
      return;
    }
    if (visible && !(index.under.get(node.path) ?? []).some((path) => visible.has(path))) return;
    rows.push({ node, depth });
    if (visible || expanded.has(node.path)) node.children.forEach((child) => walk(child, depth + 1));
  };
  root.children.forEach((child) => walk(child, 0));
  return rows;
}

function TriCheckbox({ state, onChange, label, disabled }: {
  state: Tri;
  onChange: () => void;
  label: string;
  disabled?: boolean;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = state === "some";
  }, [state]);
  return (
    <input
      ref={ref}
      type="checkbox"
      className={s.check}
      checked={state === "all"}
      onChange={onChange}
      aria-label={label}
      disabled={disabled}
    />
  );
}

export default function FileSelection() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const [tree, setTree] = useState<FileTree | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set([""]));
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [years, setYears] = useState(DEFAULT_X);
  //: Only the files that differ. An absent path means "whatever the scan says",
  //: which is a different claim from "the same number, written down twice".
  const [perFile, setPerFile] = useState<Map<string, number>>(new Map());
  const [query, setQuery] = useState("");
  const [extension, setExtension] = useState("");
  const [unselectedOnly, setUnselectedOnly] = useState(false);
  const elapsed = useElapsed(running);

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

  const index = useMemo(() => (tree ? indexTree(tree.root) : null), [tree]);
  const files = useMemo(() => index?.files ?? [], [index]);
  const total = files.length;
  const totalBytes = useMemo(() => files.reduce((sum, file) => sum + (file.size_bytes ?? 0), 0), [files]);
  const selectedBytes = useMemo(
    () => files.reduce((sum, file) => sum + (selected.has(file.path) ? (file.size_bytes ?? 0) : 0), 0),
    [files, selected],
  );

  const extensions = useMemo(() => {
    const counts = new Map<string, { total: number; selected: number }>();
    for (const file of files) {
      const ext = extensionOf(file.path);
      const entry = counts.get(ext) ?? { total: 0, selected: 0 };
      entry.total += 1;
      if (selected.has(file.path)) entry.selected += 1;
      counts.set(ext, entry);
    }
    return [...counts.entries()].sort((a, b) => b[1].total - a[1].total || a[0].localeCompare(b[0]));
  }, [files, selected]);

  const filtering = query.trim() !== "" || extension !== "" || unselectedOnly;
  const visible = useMemo(() => {
    if (!filtering) return null;
    const matches = pathMatcher(query);
    return new Set(
      files
        .filter((file) => matches(file.path))
        .filter((file) => !extension || extensionOf(file.path) === extension)
        .filter((file) => !unselectedOnly || !selected.has(file.path))
        .map((file) => file.path),
    );
  }, [filtering, files, query, extension, unselectedOnly, selected]);
  const shownPaths = useMemo(() => (visible ? [...visible] : files.map((file) => file.path)), [visible, files]);

  const rows = useMemo(
    () => (tree && index ? flatten(tree.root, expanded, visible, index) : []),
    [tree, index, expanded, visible],
  );

  const overridden = [...perFile.entries()].filter(([, value]) => value !== years).length;

  // Every file a row stands for: the file itself, or all files under a folder
  // — narrowed to what the filter shows, so a click never touches hidden files.
  function pathsOf(node: TreeNode): string[] {
    const all = node.type === "file" ? [node.path] : (index?.under.get(node.path) ?? []);
    return visible ? all.filter((path) => visible.has(path)) : all;
  }

  function setMany(paths: string[], on: boolean) {
    setSelected((current) => {
      const next = new Set(current);
      for (const path of paths) {
        if (on) next.add(path);
        else next.delete(path);
      }
      return next;
    });
  }

  // A fully-ticked box clears; anything else (empty or partly ticked)
  // completes — what an indeterminate checkbox is expected to do.
  function toggleMany(paths: string[]) {
    setMany(paths, triState(paths, selected) !== "all");
  }

  function setYearsFor(paths: string[], value: number) {
    setPerFile((current) => {
      const next = new Map(current);
      for (const path of paths) next.set(path, value);
      return next;
    });
  }

  function toggleExpanded(path: string) {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  }

  function clearFilters() {
    setQuery("");
    setExtension("");
    setUnselectedOnly(false);
  }

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
      await api.approve(scanId, [...selected], { years, perFile: overrides });
      navigate(`/scans/${scanId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  }

  const back = (
    <Link to="/" className={buttonClass("secondary")}>
      Back to configuration
    </Link>
  );

  // ---- error: the tree could not be read at all ----
  if (error && !tree) {
    return (
      <>
        <PageHeader title="File Selection" subtitle="The file list could not be loaded." />
        <PageBody>
          <StatePanel
            variant="error"
            tag="File list unavailable"
            meta={scanId.slice(0, 8)}
            title="The discovered files could not be loaded"
            log={[error]}
            nextSteps={["Start the scan again from the configuration screen."]}
            actions={back}
          />
        </PageBody>
      </>
    );
  }

  // ---- error: staging failed ----
  if (tree?.status === "failed") {
    return (
      <>
        <PageHeader title="File Selection" subtitle="Surface scan did not complete." />
        <PageBody>
          <StatePanel
            variant="error"
            tag="Surface scan failed"
            meta={scanId.slice(0, 8)}
            title="The target could not be listed"
            nextSteps={["Check that the folder, archive or repository was readable, then start the scan again."]}
            actions={back}
          >
            No files were enumerated, so there is nothing to approve.
          </StatePanel>
        </PageBody>
      </>
    );
  }

  // ---- already submitted ----
  if (tree && tree.status !== "awaiting_approval" && tree.status !== "staging") {
    return (
      <>
        <PageHeader title="File Selection" subtitle="This selection has already been approved." />
        <PageBody>
          <StatePanel
            variant="empty"
            tag={SCAN_STATUS_LABEL[tree.status]}
            tagTone="safe"
            meta={`${scanId.slice(0, 8)} · ${n(tree.approved_count)} of ${n(tree.file_count)} files approved`}
            title="File selection already submitted"
            actions={
              <Link to={`/scans/${scanId}`} className={buttonClass("primary")}>
                Open overview
              </Link>
            }
          >
            The approved paths are fixed once analysis starts; the findings were read from exactly those files.
          </StatePanel>
        </PageBody>
      </>
    );
  }

  // ---- empty: nothing any collector can analyse ----
  if (tree && tree.status === "awaiting_approval" && total === 0) {
    return (
      <>
        <PageHeader title="File Selection" subtitle="Nothing to approve for this target." />
        <PageBody>
          <StatePanel
            variant="empty"
            tag="No eligible files"
            meta={scanId.slice(0, 8)}
            title="The surface scan found nothing any enabled collector can analyse"
            nextSteps={[
              "If this target should contain source, check that it is the build tree and not a documentation export.",
              `Vendored trees and caches (${VENDORED_DIRS.join(", ")}) are left behind by design.`,
            ]}
            actions={back}
          >
            Every entry was either excluded by a default rule or was not a file any collector reads, so there is nothing
            to approve.
          </StatePanel>
        </PageBody>
      </>
    );
  }

  // ---- populated, or enumerating (tree not yet in hand / still staging) ----
  const enumerating = !tree || tree.status === "staging";
  const busy = enumerating || running;

  const columns: Column<Row>[] = [
    {
      key: "check",
      header: (
        <TriCheckbox
          state={triState(shownPaths, selected)}
          onChange={() => toggleMany(shownPaths)}
          label={filtering ? "Select every file shown" : "Select every file"}
          disabled={busy || shownPaths.length === 0}
        />
      ),
      width: 40,
      skeletonWidth: 14,
      render: ({ node }) => (
        <TriCheckbox
          state={triState(pathsOf(node), selected)}
          onChange={() => toggleMany(pathsOf(node))}
          label={node.type === "directory" ? `Select everything in ${node.path}` : node.path}
          disabled={running}
        />
      ),
    },
    {
      key: "path",
      header: "Path",
      skeletonWidth: 260,
      render: ({ node, depth }) => {
        const indent = { paddingLeft: depth * 18 };
        if (node.type === "directory") {
          const open = visible !== null || expanded.has(node.path);
          const under = index?.under.get(node.path) ?? [];
          const chosen = under.filter((path) => selected.has(path)).length;
          return (
            <span className={s.pathCell} style={indent}>
              <button
                type="button"
                className={s.twisty}
                onClick={() => toggleExpanded(node.path)}
                aria-label={open ? `Collapse ${node.path}` : `Expand ${node.path}`}
                aria-expanded={open}
                disabled={visible !== null}
              >
                <Icon name={open ? "chevronDown" : "chevronRight"} size={14} />
              </button>
              <span className={s.dirName}>{node.name}</span>
              <span className={s.dirMeta}>
                {n(node.file_count)} files · {n(chosen)} selected · {formatBytes(node.size_bytes) || "0 B"}
              </span>
            </span>
          );
        }
        return (
          <span className={s.pathCell} style={indent}>
            <span className={s.twistySpacer} />
            <span className={s.fileName} title={node.path}>
              {node.name}
            </span>
          </span>
        );
      },
    },
    {
      key: "size",
      header: "Size",
      width: 100,
      align: "right",
      skeletonWidth: 60,
      render: ({ node }) => <span className={s.size}>{formatBytes(node.size_bytes) || "0 B"}</span>,
    },
    {
      key: "x",
      header: "X (years)",
      width: 100,
      skeletonWidth: 60,
      render: ({ node }) => {
        // A folder's box shows one number only when everything under it
        // agrees; a mixed folder shows blank rather than picking one of its
        // children's values and implying the others match it.
        const paths = node.type === "file" ? [node.path] : (index?.under.get(node.path) ?? []);
        const values = new Set(paths.map((path) => perFile.get(path) ?? years));
        const shown = values.size === 1 ? [...values][0] : "";
        return (
          <input
            type="number"
            className={s.years}
            min={0}
            max={100}
            value={shown}
            placeholder="mixed"
            disabled={running}
            aria-label={`Data lifetime for ${node.path}`}
            onChange={(e) => setYearsFor(paths, clampYears(e.target.value, years))}
          />
        );
      },
    },
  ];

  const differs = (node: TreeNode) => {
    const paths = node.type === "file" ? [node.path] : (index?.under.get(node.path) ?? []);
    return paths.some((path) => (perFile.get(path) ?? years) !== years);
  };

  return (
    <>
      <PageHeader
        title="File Selection"
        subtitle={
          enumerating
            ? "Loading the discovered files."
            : "Approval gate — nothing is analysed until you approve this selection. Uncheck anything out of scope."
        }
      />
      <PageBody>
        <div className={s.layout}>
          <section className={s.main}>
            <div className={s.toolbar}>
              <Button small onClick={() => setMany(shownPaths, true)} disabled={busy || shownPaths.length === 0}>
                {filtering ? `Select ${n(shownPaths.length)} shown` : "Select all"}
              </Button>
              <Button small onClick={() => setSelected(new Set())} disabled={busy || selected.size === 0}>
                Clear
              </Button>
              <span className={s.divider} aria-hidden="true" />
              <Button
                small
                onClick={() => index && setExpanded(new Set(index.folders))}
                disabled={busy || filtering}
                title={filtering ? "Every folder holding a match is already open" : undefined}
              >
                Expand all
              </Button>
              <Button small onClick={() => setExpanded(new Set([""]))} disabled={busy || filtering}>
                Collapse all
              </Button>
              <span className={s.divider} aria-hidden="true" />
              <input
                type="search"
                className={s.pathFilter}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter path, e.g. kex_*"
                aria-label="Filter path"
                disabled={enumerating}
              />
              <FilterSelect
                label="Extension"
                value={extension}
                onChange={setExtension}
                allLabel="all"
                options={extensions.map(([ext, count]) => ({ value: ext, label: `${ext} (${count.total})` }))}
              />
              <label className={s.unselected}>
                <input
                  type="checkbox"
                  checked={unselectedOnly}
                  onChange={(e) => setUnselectedOnly(e.target.checked)}
                  disabled={enumerating}
                />
                Unselected only
              </label>
              {filtering && (
                <Button variant="link" onClick={clearFilters} style={{ fontSize: "var(--fs-xs)" }}>
                  Clear filters
                </Button>
              )}
              <span className={s.count}>
                {enumerating ? "" : filtering ? `${n(shownPaths.length)} of ${n(total)} files shown` : `${n(total)} files`}
              </span>
            </div>

            {running && (
              <StatePanel
                variant="loading"
                appearance="callout"
                className={s.callout}
                title="Running collectors"
                meta={`${n(selected.size)} approved files`}
                elapsed={elapsed}
              >
                Collectors are running over the approved paths only. This request blocks until every collector has
                finished or hit its budget.
              </StatePanel>
            )}

            <DataTable
              className={s.table}
              columns={columns}
              rows={rows}
              rowKey={({ node }) => `${node.type}:${node.path}`}
              rowClassName={({ node }) =>
                cx(
                  node.type === "directory" && s.dir,
                  differs(node) && s.changed,
                  node.type === "file" && !selected.has(node.path) && s.unchecked,
                ) || undefined
              }
              loadingRows={enumerating ? 18 : 0}
              empty={
                <StatePanel variant="empty" framed={false} title="No files match these filters">
                  <Button onClick={clearFilters}>Clear filters</Button>
                </StatePanel>
              }
            />

            <div className={s.footer}>
              <div className={s.footerText}>
                <div className={s.footerTitle}>
                  {enumerating
                    ? "– of – files selected · –"
                    : `${n(selected.size)} of ${n(total)} files selected · ${formatBytes(selectedBytes) || "0 B"}`}
                </div>
                <div className={s.footerSub}>
                  {enumerating
                    ? "Enumeration in progress · selection opens when the file list has loaded"
                    : `X = ${years} years for every file` +
                      (overridden ? ` except ${n(overridden)} with their own value` : "") +
                      " · collectors open approved paths only"}
                </div>
              </div>
              {error && tree && <span className={cx(s.footerChip, s.footerError)}>{error}</span>}
              {!enumerating && !error && selected.size === 0 && (
                <span className={s.footerChip}>Select at least one file to approve</span>
              )}
              {back}
              <Button variant="primary" onClick={approve} disabled={busy || selected.size === 0}>
                {running ? "Running collectors…" : `Approve ${n(selected.size)} and run analysis`}
              </Button>
            </div>
          </section>

          <aside className={s.side}>
            <Panel title="Data lifetime (X)" meta="Mosca's inequality">
              <label className={s.xRow} htmlFor="years">
                <input
                  id="years"
                  type="number"
                  className={s.xInput}
                  min={0}
                  max={100}
                  value={years}
                  disabled={busy}
                  onChange={(e) => setYears(clampYears(e.target.value, years))}
                />
                years, for every file
              </label>
              <p className={s.sideText}>
                How long this data must stay confidential. Every file uses this number unless you give it its own in the
                X column; setting a folder sets everything inside it. Changed rows are shaded.
              </p>
            </Panel>

            <Panel title="Selected by extension" flush>
              {!enumerating && (
                <dl className={s.kv}>
                  {extensions.slice(0, 12).map(([ext, count]) => (
                    <KvRow key={ext} label={ext} value={`${n(count.selected)} / ${n(count.total)}`} />
                  ))}
                  <KvRow
                    label="Scan total"
                    sans
                    value={`${formatBytes(selectedBytes) || "0 B"} / ${formatBytes(totalBytes) || "0 B"}`}
                  />
                </dl>
              )}
            </Panel>

            <Panel title="Excluded by default rules" flush>
              <dl className={s.kv}>
                {VENDORED_DIRS.map((dir) => (
                  <KvRow key={dir} label={`**/${dir}/**`} value="pruned" />
                ))}
              </dl>
              <p className={s.sideNote}>
                Pruned at any depth before the tree was built, so they are not counted here. Set on the host with{" "}
                <code>ECDAT_SURFACE_EXCLUDE_DIRS</code>.
              </p>
            </Panel>
          </aside>
        </div>
      </PageBody>
    </>
  );
}

function KvRow({ label, value, sans }: { label: string; value: string; sans?: boolean }) {
  return (
    <>
      <dt className={sans ? s.kvLabelSans : s.kvLabel}>{label}</dt>
      <dd className={s.kvValue}>{value}</dd>
    </>
  );
}
