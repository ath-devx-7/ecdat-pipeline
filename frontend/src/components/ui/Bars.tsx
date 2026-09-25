import { Fragment, type CSSProperties, type ReactNode } from "react";
import s from "./Bars.module.css";
import { cx, toneVars, type Tone } from "./tone";

export interface StackPart {
  key: string;
  label: string;
  count: number;
  tone: Tone;
}

// One bar split by share, count printed inside each segment, and a legend
// underneath giving label, count and percentage — colour never stands alone.
export function StackedBar({ parts }: { parts: StackPart[] }) {
  const total = parts.reduce((sum, part) => sum + part.count, 0);
  const pct = (count: number) => (total ? Math.round((count / total) * 100) : 0);
  return (
    <div>
      {total === 0 ? (
        <div className={s.emptyStack} />
      ) : (
        <div className={s.stack} role="img" aria-label={parts.map((p) => `${p.label} ${p.count}`).join(", ")}>
          {parts
            .filter((part) => part.count > 0)
            .map((part) => (
              <div key={part.key} className={s.segment} style={{ ...toneVars(part.tone), flexGrow: part.count, flexBasis: 0 }}>
                {part.count}
              </div>
            ))}
        </div>
      )}
      <div className={s.legend}>
        {parts.map((part) => (
          <span key={part.key} className={s.legendItem} style={toneVars(part.tone)}>
            <span className={s.legendSquare} aria-hidden="true" />
            {part.label}
            <span className={s.legendCount}>
              {part.count} · {pct(part.count)}%
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}

export interface BarRow {
  key: string;
  label: ReactNode;
  // null draws an empty track and `valueText` (e.g. "off") instead of a count
  value: number | null;
  valueText?: string;
  tone?: Tone;
  mono?: boolean;
}

export function BarList({ rows, labelWidth = 140, max }: { rows: BarRow[]; labelWidth?: number; max?: number }) {
  const top = max ?? Math.max(1, ...rows.map((row) => row.value ?? 0));
  return (
    <div className={s.list} style={{ "--label-w": `${labelWidth}px` } as CSSProperties}>
      {rows.map((row) => {
        const off = row.value === null;
        return (
          <Fragment key={row.key}>
            <span className={cx(s.label, row.mono && s.labelMono, off && s.labelOff)}>{row.label}</span>
            <span className={s.track}>
              {!off && (
                <span
                  className={s.fill}
                  style={{ ...(row.tone ? toneVars(row.tone) : {}), width: `${((row.value ?? 0) / top) * 100}%`, display: "block" }}
                />
              )}
            </span>
            <span className={cx(s.value, off && s.valueOff)}>{off ? (row.valueText ?? "—") : row.value}</span>
          </Fragment>
        );
      })}
    </div>
  );
}
