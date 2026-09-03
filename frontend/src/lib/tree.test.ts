import { describe, expect, it } from "vitest";
import type { DirectoryNode } from "../api";
import { countSelected, filePaths, selectAll, selectionState, toggleNode } from "./tree";

const file = (path: string) => ({
  type: "file" as const,
  id: path,
  name: path.split("/").pop()!,
  path,
  size_bytes: 10,
  approved: false,
});

const tree: DirectoryNode = {
  type: "directory",
  name: "",
  path: "",
  file_count: 4,
  size_bytes: 40,
  children: [
    {
      type: "directory",
      name: "etc",
      path: "etc",
      file_count: 2,
      size_bytes: 20,
      children: [file("etc/nginx.conf"), file("etc/openssl.cnf")],
    },
    {
      type: "directory",
      name: "certs",
      path: "certs",
      file_count: 2,
      size_bytes: 20,
      children: [file("certs/weak.crt"), file("certs/weak.key")],
    },
  ],
};

describe("file selection", () => {
  it("lists every file beneath a node in tree order", () => {
    expect(filePaths(tree)).toEqual([
      "etc/nginx.conf",
      "etc/openssl.cnf",
      "certs/weak.crt",
      "certs/weak.key",
    ]);
  });

  it("reports none, some and all for a directory", () => {
    const etc = tree.children[0];
    expect(selectionState(new Set(), etc)).toBe("none");
    expect(selectionState(new Set(["etc/nginx.conf"]), etc)).toBe("some");
    expect(selectionState(new Set(["etc/nginx.conf", "etc/openssl.cnf"]), etc)).toBe("all");
  });

  it("toggling a partially selected directory completes it, toggling a full one clears it", () => {
    const etc = tree.children[0];
    const some = new Set(["etc/nginx.conf"]);
    const completed = toggleNode(some, etc);
    expect([...completed].sort()).toEqual(["etc/nginx.conf", "etc/openssl.cnf"]);
    const cleared = toggleNode(completed, etc);
    expect(cleared.size).toBe(0);
  });

  it("toggling a directory leaves other directories alone", () => {
    const selected = new Set(["certs/weak.crt"]);
    const next = toggleNode(selected, tree.children[0]);
    expect(next.has("certs/weak.crt")).toBe(true);
    expect(next.size).toBe(3);
  });

  it("select-all is exactly the approve payload, and the count follows it", () => {
    const all = selectAll(tree);
    expect(all.size).toBe(4);
    expect(countSelected(all, tree)).toBe(4);
    expect(countSelected(all, tree.children[1])).toBe(2);
  });

  it("toggling a file toggles only that file", () => {
    const next = toggleNode(new Set(), file("certs/weak.key"));
    expect([...next]).toEqual(["certs/weak.key"]);
    expect(toggleNode(next, file("certs/weak.key")).size).toBe(0);
  });
});
