import { describe, expect, it } from "vitest";
import type { Scan } from "../api";
import { folderName, pickable, parseTargets, scanLabel } from "./NewScan";

// A folder upload copies every byte over the wire before anything is read from
// it, so what the picker drops matters more here than in a folder scan: these
// trees are build output and vendored dependencies, and they would eat the
// per-scan file cap before a single source file were offered for approval.

const pick = (relative: string) => {
  const file = new File(["x"], relative.split("/").pop()!);
  Object.defineProperty(file, "webkitRelativePath", { value: relative });
  return file;
};

const paths = (files: File[]) => files.map((file) => file.webkitRelativePath);

describe("pickable", () => {
  it("drops vendored and build directories at any depth", () => {
    const chosen = [
      pick("app/src/tls.py"),
      pick("app/.git/objects/ab/cdef"),
      pick("app/frontend/node_modules/left-pad/index.js"),
      pick("app/api/__pycache__/views.cpython-311.pyc"),
      pick("app/.venv/lib/site-packages/x.py"),
      pick("app/venv/bin/python"),
      pick("app/frontend/dist/index.js"),
      pick("app/build/main.o"),
    ];

    expect(paths(pickable(chosen))).toEqual(["app/src/tls.py"]);
  });

  it("keeps names that merely contain a skipped word", () => {
    // Segment by segment, not substring: `build.gradle` is a build file, not a
    // build directory, and it is exactly the kind of file a crypto scan wants.
    const chosen = [pick("app/build.gradle"), pick("app/gitignore-rules.md")];

    expect(paths(pickable(chosen))).toEqual(["app/build.gradle", "app/gitignore-rules.md"]);
  });
});

describe("parseTargets", () => {
  it("defaults a target with no port to 443", () => {
    expect(parseTargets("example.test\nlocalhost:8443")).toEqual([
      { host: "example.test", port: 443 },
      { host: "localhost", port: 8443 },
    ]);
  });
});

describe("folderName", () => {
  it("is the segment the picker prefixed every path with", () => {
    expect(folderName([pick("demo/nginx/nginx.conf"), pick("demo/app.py")])).toBe("demo");
  });

  it("falls back rather than showing an empty name", () => {
    expect(folderName([])).toBe("the chosen folder");
  });
});

describe("scanLabel", () => {
  const scan = (fields: Partial<Scan>): Scan =>
    ({ id: "scan-1", source_type: "folder", source_ref: null, probe_targets: null, ...fields }) as Scan;

  it("does not show an upload id, which names nothing to a person", () => {
    const uploaded = scan({ source_type: "upload", source_ref: "0b0f7f2e-0000-4000-8000-000000000000" });

    expect(scanLabel(uploaded)).toBe("Uploaded folder");
  });

  it("leaves every other source naming itself", () => {
    expect(scanLabel(scan({ source_ref: "/srv/app" }))).toBe("/srv/app");
    expect(scanLabel(scan({ source_type: "none", probe_targets: [{ host: "localhost", port: 8443 }] }))).toBe(
      "localhost:8443",
    );
    expect(scanLabel(scan({ source_type: "none" }))).toBe("scan-1");
  });
});
