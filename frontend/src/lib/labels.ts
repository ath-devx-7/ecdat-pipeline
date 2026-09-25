// Names and colour families for the vocabulary the backend uses. Two rules
// from the spec are visible here: broken_now and quantum_vulnerable are
// different tones, not two shades of one (§10), and every recommendation
// status has a label, because all four are always shown (§11).

import type { Confidence, RecommendationStatus, Scan, ScanMode, ScanStatus, SourceLayer, Verdict, Wave } from "../api";
import type { Tone } from "../components/ui/tone";

export const VERDICTS: Verdict[] = [
  "broken_now",
  "quantum_vulnerable",
  "quantum_safe",
  "hygiene",
  "unknown",
];

export const VERDICT_LABEL: Record<Verdict, string> = {
  broken_now: "Broken now",
  quantum_vulnerable: "Quantum-vulnerable",
  quantum_safe: "Quantum-safe",
  hygiene: "Hygiene",
  unknown: "Unknown",
};

export const WAVES: Wave[] = ["wave_0", "wave_1", "wave_2", "wave_3", "verify"];

export const WAVE_LABEL: Record<Wave, string> = {
  wave_0: "Wave 0 — broken today",
  wave_1: "Wave 1 — overdue, low effort",
  wave_2: "Wave 2 — overdue, high effort",
  wave_3: "Wave 3 — not yet overdue, or not harvestable",
  verify: "Verify — confirm before planning",
};

export const WAVE_SHORT: Record<Wave, string> = {
  wave_0: "Wave 0",
  wave_1: "Wave 1",
  wave_2: "Wave 2",
  wave_3: "Wave 3",
  verify: "Verify",
};

export const WAVE_DESCRIPTION: Record<Wave, string> = {
  wave_0: "Broken with today's computers. Not a quantum deadline — a now deadline.",
  wave_1:
    "Quantum-vulnerable confidentiality primitives already overdue under Mosca's inequality, reachable by a config change or library upgrade.",
  wave_2:
    "Overdue as wave 1, but the migration is a code change or hardware swap. Starts now, finishes later — it needs budgeting, not deferring.",
  wave_3:
    "Quantum-vulnerable but not overdue at this data lifetime, or an authentication primitive that cannot be harvested now and decrypted later.",
  verify:
    "Low-confidence observations and unclassified algorithms. The action is confirmation, not migration.",
};

export const STATUSES: RecommendationStatus[] = ["recommended", "blocked", "no_path", "unknown"];

export const STATUS_LABEL: Record<RecommendationStatus, string> = {
  recommended: "Recommended",
  blocked: "Blocked",
  no_path: "No path",
  unknown: "Unknown",
};

export const STATUS_DESCRIPTION: Record<RecommendationStatus, string> = {
  recommended: "A target with every prerequisite observed as met.",
  blocked: "A target, and the ordered chain of prerequisites still standing in its way.",
  no_path: "No upgrade path in the policy pack; a compensating control is named instead.",
  unknown: "No rule in the policy pack matched. No target is guessed.",
};

export function titleCase(value: string | null | undefined): string {
  if (!value) return "";
  return value.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function describeAlgorithm(finding: {
  algorithm_family: string | null;
  algorithm_name: string;
  key_size: number | null;
  mode: string | null;
  protocol_version: string | null;
}): string {
  const base = finding.algorithm_family ?? finding.algorithm_name;
  const parts = [base];
  if (finding.key_size) parts.push(`${finding.key_size}-bit`);
  if (finding.mode) parts.push(finding.mode);
  if (finding.protocol_version && base.toUpperCase().startsWith("TLS")) parts.push(finding.protocol_version);
  return parts.join(" ");
}

// How the shell names a scan's lifecycle state, in the mockups' words, and the
// tone its badge takes.
export const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  staging: "Surface scan running",
  awaiting_approval: "Awaiting file approval",
  running: "Analysis running",
  // Every finished scan reads as completed, whatever the collectors reported:
  // a product decision. The backend still records `partial` and `failed`, and
  // the Findings page and exports still carry what each collector found.
  complete: "Completed successfully",
  partial: "Completed successfully",
  failed: "Completed successfully",
};

export const SCAN_STATUS_TONE: Record<ScanStatus, Tone> = {
  staging: "info",
  awaiting_approval: "high",
  running: "info",
  complete: "safe",
  partial: "safe",
  failed: "safe",
};

export const MODE_LABEL: Record<ScanMode, string> = {
  files: "Files only",
  files_and_probe: "Files + network probe",
  probe_only: "Network probe only",
};

// An upload's `source_ref` is the id the upload endpoint handed back, which is a
// UUID and says nothing to a person. Everything else names itself.
export function scanLabel(scan: Scan): string {
  if (scan.source_type === "upload") return "Uploaded folder";
  if (scan.source_type === "docker_archive") return "Uploaded image archive";
  const probed = scan.probe_targets?.map((target) => `${target.host}:${target.port}`).join(", ");
  return scan.source_ref || probed || scan.id;
}

// The same two vocabularies, short enough for a table column.
export const SCAN_STATUS_SHORT: Record<ScanStatus, string> = {
  staging: "Surface scan",
  awaiting_approval: "Awaiting approval",
  running: "Running",
  complete: "Completed",
  partial: "Completed",
  failed: "Completed",
};

export const MODE_SHORT: Record<ScanMode, string> = {
  files: "Files",
  files_and_probe: "Files+probe",
  probe_only: "Probe",
};

// The backend's collectors, in the New Scan list's order, and the scan modes
// that run each one. `modes` mirrors `collectors_for` in backend/app/runner.py:
// the API takes no per-collector switch, so the mode alone decides — keep the
// two in step. CycloneDX import is never part of a run; it is the Overview's
// import button, after the scan.
export interface CollectorInfo {
  name: string;
  tools: string;
  description: string;
  modes: ScanMode[];
}

export const COLLECTORS: CollectorInfo[] = [
  {
    name: "Code",
    tools: "semgrep · local rules",
    description: "Crypto API calls, algorithm constants and key sizes in approved source",
    modes: ["files", "files_and_probe"],
  },
  {
    name: "Binaries",
    tools: "ELF",
    description: "Linked libraries, imported symbols and embedded string constants",
    modes: ["files", "files_and_probe"],
  },
  {
    name: "Certificates",
    tools: "X.509 · PEM · DER",
    description: "Certificates only; private keys and .p12/.pfx containers are never parsed",
    modes: ["files", "files_and_probe"],
  },
  {
    name: "Configs",
    tools: "openssl.cnf · nginx · sshd · ssh_config · httpd · java.security",
    description: "Declared protocols, cipher suites and key references",
    modes: ["files", "files_and_probe"],
  },
  {
    name: "Network / TLS",
    tools: "sslyze",
    description: "Live TLS handshakes against the probe targets listed above, and no other host",
    modes: ["files_and_probe", "probe_only"],
  },
  {
    name: "CycloneDX import",
    tools: "CBOM 1.6",
    description: "Imported from the Overview once a scan has finished",
    modes: [],
  },
];

// The design's colour families for the backend's verdicts and waves. The
// verdicts are the data; these only pick a colour, and every use also prints
// the VERDICT_LABEL beside it. Hygiene takes the design's "medium".
export const VERDICT_TONE: Record<Verdict, Tone> = {
  broken_now: "critical",
  quantum_vulnerable: "high",
  hygiene: "medium",
  quantum_safe: "safe",
  unknown: "unknown",
};

export const WAVE_TONE: Record<Wave, Tone> = {
  wave_0: "critical",
  wave_1: "high",
  wave_2: "medium",
  wave_3: "info",
  verify: "unknown",
};

export const STATUS_TONE: Record<RecommendationStatus, Tone> = {
  recommended: "safe",
  blocked: "blocked",
  no_path: "critical",
  unknown: "unknown",
};

// Every value the findings filters accept, mirroring the enums in
// backend/app/models/enums.py — the facets the API returns hold only the
// values present in one scan, so the full lists live here.
export const COLLECTOR_NAMES = ["code", "binary", "certs", "config", "network", "cbom_import"] as const;

export const COLLECTOR_LABEL: Record<string, string> = {
  code: "Code",
  binary: "Binaries",
  certs: "Certificates",
  config: "Configs",
  network: "Network / TLS",
  cbom_import: "CycloneDX import",
};

export const CONFIDENCES: Confidence[] = ["high", "medium", "low"];

// Ordered by closeness to execution, the backend's precedence rule (§8).
export const SOURCE_LAYERS: SourceLayer[] = ["live", "artifact", "config", "source"];
