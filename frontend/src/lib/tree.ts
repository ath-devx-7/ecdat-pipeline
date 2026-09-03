// Selection logic for the file-approval tree (SPEC.md §13 screen 2), kept pure
// so it can be tested without rendering anything. The selection is a set of
// file paths — exactly the list `POST /approve` takes — and every directory
// control is defined in terms of the files beneath it.

import type { DirectoryNode, TreeNode } from "../api";

export type SelectionState = "none" | "some" | "all";

/** Every file path at or below a node, in tree order. */
export function filePaths(node: TreeNode): string[] {
  if (node.type === "file") return [node.path];
  return node.children.flatMap(filePaths);
}

export function selectionState(selected: ReadonlySet<string>, node: TreeNode): SelectionState {
  const paths = filePaths(node);
  if (paths.length === 0) return "none";
  const chosen = paths.filter((path) => selected.has(path)).length;
  if (chosen === 0) return "none";
  return chosen === paths.length ? "all" : "some";
}

export function countSelected(selected: ReadonlySet<string>, node: TreeNode): number {
  return filePaths(node).filter((path) => selected.has(path)).length;
}

/**
 * Toggle a node. A directory that is fully selected deselects every file
 * under it; anything else selects every file under it — so one click on a
 * partially selected directory completes the selection rather than clearing
 * it, which is what a checkbox in the indeterminate state is expected to do.
 */
export function toggleNode(selected: ReadonlySet<string>, node: TreeNode): Set<string> {
  const next = new Set(selected);
  const paths = filePaths(node);
  if (selectionState(selected, node) === "all") {
    for (const path of paths) next.delete(path);
  } else {
    for (const path of paths) next.add(path);
  }
  return next;
}

export function selectAll(root: DirectoryNode): Set<string> {
  return new Set(filePaths(root));
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
