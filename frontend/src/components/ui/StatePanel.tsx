import type { ReactNode } from "react";
import { Caps, ProgressBar, SeverityBadge } from "./primitives";
import s from "./StatePanel.module.css";
import { cx, type Tone } from "./tone";

// One component for every non-populated screen state.
//
// empty / error — a centred column: tag badge + mono meta, title, body, an
//   optional log block, NEXT STEPS, buttons. (02 Empty, 02 Error, 03 Empty,
//   05 Files-only, 06 Nothing to migrate, 06 Missing inputs.)
// loading — a full-width block: accent title + mono meta, elapsed on the
//   right, progress bar, an unboxed log, then `children` as the note. (01 Surface scan running,
//   05 Probing.) `appearance="callout"` gives it the tinted info fill.

interface Common {
  title: ReactNode;
  meta?: ReactNode;
  children?: ReactNode;
  // mono lines; a string[] is joined with newlines
  log?: string[] | ReactNode;
  className?: string;
}

interface Settled extends Common {
  variant: "empty" | "error";
  // the tag badge; its tone defaults to unknown (empty) or critical (error)
  tag?: ReactNode;
  tagTone?: Tone;
  nextSteps?: ReactNode[];
  actions?: ReactNode;
  // false renders the column without the surrounding full-height panel
  framed?: boolean;
}

interface Loading extends Common {
  variant: "loading";
  // fraction 0–1, null while the total is not yet known; omit when nothing
  // reports progress at all, and no bar is drawn
  progress?: number | null;
  elapsed?: ReactNode;
  appearance?: "panel" | "callout" | "bare";
}

export type StatePanelProps = Settled | Loading;

const logText = (log: string[] | ReactNode) => (Array.isArray(log) ? (log as string[]).join("\n") : log);

export function StatePanel(props: StatePanelProps) {
  if (props.variant === "loading") {
    const { title, meta, children, log, progress, elapsed, appearance = "panel", className } = props;
    return (
      <div
        className={cx(
          s.loading,
          appearance === "panel" && s.loadingFramed,
          appearance === "callout" && s.loadingCallout,
          className,
        )}
        role="status"
        aria-live="polite"
      >
        <div className={s.loadingHead}>
          <span className={s.loadingTitle}>{title}</span>
          {meta && <span className={s.meta}>{meta}</span>}
          {elapsed && <span className={s.elapsed}>{elapsed}</span>}
        </div>
        {progress !== undefined && (
          <ProgressBar value={progress} label={typeof title === "string" ? title : undefined} />
        )}
        {log && <div className={s.logPlain}>{logText(log)}</div>}
        {children && <div className={s.note}>{children}</div>}
      </div>
    );
  }

  const { variant, tag, tagTone, meta, title, children, log, nextSteps, actions, framed = true, className } = props;
  const column = (
    <div className={s.column} role={variant === "error" ? "alert" : undefined}>
      {(tag || meta) && (
        <div className={s.tagLine}>
          {tag && (
            <SeverityBadge tone={tagTone ?? (variant === "error" ? "critical" : "unknown")} marker={false}>
              {tag}
            </SeverityBadge>
          )}
          {meta && <span className={s.meta}>{meta}</span>}
        </div>
      )}
      <h2 className={s.title}>{title}</h2>
      {children && <div className={s.body}>{children}</div>}
      {log && <pre className={s.log}>{logText(log)}</pre>}
      {nextSteps && nextSteps.length > 0 && (
        <div className={s.nextSteps}>
          <Caps>Next steps</Caps>
          <ul>
            {nextSteps.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ul>
        </div>
      )}
      {actions && <div className={s.actions}>{actions}</div>}
    </div>
  );
  return framed ? <div className={cx(s.frame, className)}>{column}</div> : column;
}
