// Names and colours for the vocabulary the backend uses. Two rules from the
// spec are visible here: broken_now and quantum_vulnerable are different
// colours, not two shades of one (§10), and every recommendation status has a
// label, because all four are always shown (§11).

import type { RecommendationStatus, Verdict, Wave } from "../api";

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

export const VERDICT_COLOR: Record<Verdict, string> = {
  broken_now: "#dc2626",
  quantum_vulnerable: "#d97706",
  quantum_safe: "#16a34a",
  hygiene: "#2563eb",
  unknown: "#94a3b8",
};

export const VERDICT_BADGE: Record<Verdict, string> = {
  broken_now: "bg-red-100 text-red-800",
  quantum_vulnerable: "bg-amber-100 text-amber-800",
  quantum_safe: "bg-green-100 text-green-800",
  hygiene: "bg-blue-100 text-blue-800",
  unknown: "bg-slate-200 text-slate-700",
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

export const WAVE_COLOR: Record<Wave, string> = {
  wave_0: "#dc2626",
  wave_1: "#ea580c",
  wave_2: "#d97706",
  wave_3: "#0891b2",
  verify: "#94a3b8",
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

export const STATUS_BADGE: Record<RecommendationStatus, string> = {
  recommended: "bg-green-100 text-green-800",
  blocked: "bg-amber-100 text-amber-800",
  no_path: "bg-red-100 text-red-800",
  unknown: "bg-slate-200 text-slate-700",
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
