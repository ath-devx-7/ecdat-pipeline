// The backend's response shapes (backend/app/schemas), and one fetch helper.
// Everything goes through the same-origin `/api` prefix — see vite.config.ts.

export type ScanMode = "probe_only" | "files" | "files_and_probe";
export type SourceType = "folder" | "github" | "docker_image" | "none";
export type ScanStatus =
  | "staging"
  | "awaiting_approval"
  | "running"
  | "complete"
  | "partial"
  | "failed";
export type Verdict =
  | "broken_now"
  | "quantum_vulnerable"
  | "quantum_safe"
  | "hygiene"
  | "unknown";
export type Wave = "wave_0" | "wave_1" | "wave_2" | "wave_3" | "verify";
export type RecommendationStatus = "recommended" | "blocked" | "no_path" | "unknown";
export type Confidence = "high" | "medium" | "low";
export type SourceLayer = "live" | "artifact" | "config" | "source";
export type Primitive =
  | "key_exchange"
  | "signature"
  | "hash"
  | "cipher"
  | "protocol"
  | "unknown";

export interface ProbeTarget {
  host: string;
  port: number;
}

export interface Scan {
  id: string;
  mode: ScanMode;
  source_type: SourceType;
  source_ref: string | null;
  probe_targets: ProbeTarget[] | null;
  data_lifetime_years: number | null;
  policy_version: string | null;
  status: ScanStatus;
  file_count: number;
  approved_count: number;
  created_at: string | null;
  completed_at: string | null;
  diagnostics: ScanDiagnostics | null;
}

export interface FileNode {
  type: "file";
  id: string;
  name: string;
  path: string;
  size_bytes: number | null;
  approved: boolean;
}

export interface DirectoryNode {
  type: "directory";
  name: string;
  path: string;
  children: TreeNode[];
  file_count: number;
  size_bytes: number;
}

export type TreeNode = DirectoryNode | FileNode;

export interface FileTree {
  scan_id: string;
  status: ScanStatus;
  file_count: number;
  approved_count: number;
  root: DirectoryNode;
}

export interface CollectorRun {
  name: string;
  finding_count: number;
  duration_seconds: number;
  error: string | null;
  // false when this scan's mode never called the collector. "found nothing" and
  // "was not run" are different claims and the UI must not merge them.
  ran: boolean;
  file_count: number;
  // the collector's own words for the gap; `error` is the same with the
  // exception class in front
  reason: string | null;
}

export interface ExtensionCoverage {
  extension: string;
  approved_files: number;
  finding_count: number;
  // sent to Semgrep at all
  code_scanned: boolean;
  // some rule declares a language covering it
  ruled: boolean;
}

// Why a scan's result looks the way it does. Null before the collectors have
// run, and for a scan stored before the field existed — which is not the same
// as an empty one, so nothing may render "all clear" from a missing value.
export interface ScanDiagnostics {
  collectors: CollectorRun[];
  extensions: ExtensionCoverage[];
}

export interface ApproveResponse {
  scan_id: string;
  status: ScanStatus;
  approved_count: number;
  file_count: number;
  finding_count: number;
  collectors: CollectorRun[];
  diagnostics: ScanDiagnostics | null;
  verdict_counts: Record<string, number>;
  alignment: { status: string; reason?: string; note_count?: number };
  wave_counts: Record<string, number>;
  recommendation_counts: Record<string, number>;
}

export interface Policy {
  version: string;
  published: string;
  age_days: number;
  stale: boolean;
  staleness_warning_days: number;
  z_years_default: number;
  y_years_default: number;
  algorithm_rule_count: number;
  pqc_target_count: number;
  prefer_hybrid: boolean;
}

export interface VerdictView {
  verdict: Verdict;
  rule_id: string | null;
  source_citation: string | null;
  policy_version: string | null;
}

export interface RiskView {
  wave: Wave;
  urgency_years: number | null;
  x_years: number | null;
  y_years: number | null;
  z_years: number | null;
  rationale: Record<string, unknown> | null;
}

export interface Prerequisite {
  unmet: string;
  observed: string | null;
  observed_at?: string;
  note?: string;
}

export interface Recommendation {
  id: string;
  status: RecommendationStatus;
  target: string | null;
  hybrid_target: string | null;
  action_class: string | null;
  prerequisites: Prerequisite[] | null;
  side_effects: string | null;
  source_citation: string | null;
}

export interface FindingBrief {
  id: string;
  collector: string;
  algorithm_name: string;
  algorithm_family: string | null;
  algorithm_oid: string | null;
  primitive: Primitive;
  key_size: number | null;
  mode: string | null;
  protocol_version: string | null;
  evidence_location: string | null;
  confidence: Confidence;
  source_layer: SourceLayer;
}

export interface FindingDetail extends FindingBrief {
  evidence_raw: Record<string, unknown> | null;
  created_at: string | null;
  verdict: VerdictView | null;
  risk: RiskView | null;
  recommendations: Recommendation[];
}

export interface FindingPage {
  total: number;
  offset: number;
  limit: number;
  items: FindingDetail[];
  facets: Record<string, string[]>;
}

export interface Readiness {
  percent: number | null;
  quantum_safe: number;
  quantum_vulnerable: number;
  broken_now: number;
  hygiene: number;
  unassessed: number;
  assessed: number;
}

export interface AlignmentNoteView {
  id: string;
  asset_key: string;
  note: string;
  config: FindingBrief;
  live: FindingBrief;
  declared: Record<string, unknown> | null;
  observed: Record<string, unknown> | null;
}

export interface AlignmentView {
  status: "compared" | "skipped";
  reason: string | null;
  note_count: number;
  notes: AlignmentNoteView[];
  compared_services: string[];
  scope_skipped: string[];
}

export interface MoscaSummary {
  subject: number;
  overdue: number;
  unknown_primitive: number;
}

export interface Overview {
  scan: Scan;
  mosca: MoscaSummary;
  finding_count: number;
  readiness: Readiness;
  verdict_counts: Record<Verdict, number>;
  wave_counts: Record<Wave, number>;
  recommendation_counts: Record<RecommendationStatus, number>;
  primitive_counts: Record<string, number>;
  collector_counts: Record<string, number>;
  source_layer_counts: Record<string, number>;
  alignment: AlignmentView;
  policy: Policy;
  z_years_used: number | null;
  provenance_count: number;
}

export interface RoadmapItem {
  finding: FindingBrief;
  verdict: Verdict | null;
  urgency_years: number | null;
  rationale: Record<string, unknown> | null;
  recommendations: Recommendation[];
}

export interface BlockedChain {
  // Only `unmet` and `observed` — where each was seen is `assets`, and the
  // per-finding rows keep the full entry.
  prerequisites: { unmet: string; observed: string | null }[];
  finding_count: number;
  assets: string[];
}

export interface Roadmap {
  waves: Record<Wave, RoadmapItem[]>;
  wave_counts: Record<Wave, number>;
  unscored: number;
  z_years_used: number | null;
  blocked_chains: BlockedChain[];
}

export interface CbomImportResponse {
  scan_id: string;
  status: ScanStatus;
  provenance_id: string;
  tool: string | null;
  component_count: number;
  finding_count: number;
  skipped: string[];
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      // not JSON; keep the status text
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});

export interface ScanCreate {
  mode: ScanMode;
  source_type: SourceType;
  source_ref?: string;
  probe_targets: ProbeTarget[];
  data_lifetime_years: number;
}

export const api = {
  policy: () => request<Policy>("/api/policy"),
  scans: () => request<Scan[]>("/api/scans"),
  scan: (id: string) => request<Scan>(`/api/scans/${id}`),
  createScan: (body: ScanCreate) => request<Scan>("/api/scans", json(body)),
  files: (id: string) => request<FileTree>(`/api/scans/${id}/files`),
  approve: (id: string, paths: string[]) =>
    request<ApproveResponse>(`/api/scans/${id}/approve`, json({ paths })),
  overview: (id: string) => request<Overview>(`/api/scans/${id}/overview`),
  findings: (id: string, params: URLSearchParams) =>
    request<FindingPage>(`/api/scans/${id}/findings?${params.toString()}`),
  alignment: (id: string) => request<AlignmentView>(`/api/scans/${id}/alignment`),
  roadmap: (id: string) => request<Roadmap>(`/api/scans/${id}/roadmap`),
  rescore: (id: string, z_years: number) =>
    request<{ z_years: number; wave_counts: Record<Wave, number> }>(
      `/api/scans/${id}/rescore`,
      json({ z_years }),
    ),
  importCbom: (id: string, file: File) =>
    request<CbomImportResponse>(`/api/scans/${id}/cbom`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-filename": file.name },
      body: file,
    }),
  cbomUrl: (id: string) => `/api/scans/${id}/cbom`,
  reportUrl: (id: string) => `/api/scans/${id}/report.pdf`,
  reportHtmlUrl: (id: string) => `/api/scans/${id}/report.html`,
};

// The Z slider's value is remembered per scan on this browser only, so the
// New-scan screen can hand it to the overview that applies it (§12).
export const zStorageKey = (scanId: string) => `ecdat:z:${scanId}`;
