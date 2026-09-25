// Vendored trees and caches. Never a deployed artefact, in a source tree or in
// an image, so they are dropped everywhere: in the browser before a folder
// upload (NewScan), and again on the host by `surface_exclude_dirs`
// (backend/app/config.py), which is what an image archive goes through — a tar
// cannot be filtered client-side. Keep this list and that one in step.
export const VENDORED_DIRS = [".git", "node_modules", "__pycache__", ".venv", "venv"];

// Build output, dropped from a picked folder only. In a source tree it is
// scratch, and it would cost upload time and the file cap before a single
// source file reached the approval screen. In an *image* the same names are
// often where the deployed binary was COPYed to, so the backend does not prune
// them — see the note on `surface_exclude_dirs`.
export const BUILD_OUTPUT_DIRS = ["dist", "build"];
