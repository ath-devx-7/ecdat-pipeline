// The colour families of TOKENS.md §3.4. Every tone maps to a solid / bg / fg
// triple in tokens.css, and every use of one also carries a text label.

import type { CSSProperties } from "react";

export type Tone = "critical" | "high" | "medium" | "safe" | "unknown" | "blocked" | "info";

export const toneVars = (tone: Tone) => ({
  "--tone-solid": `var(--sev-${tone})`,
  "--tone-bg": `var(--sev-${tone}-bg)`,
  "--tone-fg": `var(--sev-${tone}-fg)`,
}) as CSSProperties;

export const cx = (...names: (string | false | null | undefined)[]) => names.filter(Boolean).join(" ");
