import type { ButtonHTMLAttributes, CSSProperties, ReactNode } from "react";
import { Icon } from "./Icon";
import s from "./primitives.module.css";
import { cx, toneVars, type Tone } from "./tone";

// ---- badges ----

// A tone is never shown without its words: `children` is the label and is
// required, so a badge cannot be colour alone.
export function SeverityBadge({
  tone,
  children,
  marker = true,
  title,
}: {
  tone: Tone;
  children: ReactNode;
  marker?: boolean;
  title?: string;
}) {
  return (
    <span className={s.badge} style={toneVars(tone)} title={title}>
      {marker && <span className={s.square} aria-hidden="true" />}
      {children}
    </span>
  );
}

// The findings "verdict" column: a round dot and plain text, no fill.
export function ToneDot({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={s.dotLabel} style={toneVars(tone)}>
      <span className={s.dot} aria-hidden="true" />
      {children}
    </span>
  );
}

// ---- text ----

export function MonoText({
  children,
  muted,
  truncate,
  title,
  className,
}: {
  children: ReactNode;
  muted?: boolean;
  truncate?: boolean;
  title?: string;
  className?: string;
}) {
  return (
    <span className={cx(s.mono, muted && s.muted, truncate && s.truncate, className)} title={title}>
      {children}
    </span>
  );
}

export function Caps({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx(s.caps, className)}>{children}</span>;
}

// ---- buttons ----

export type ButtonVariant = "primary" | "secondary" | "link";

export function buttonClass(variant: ButtonVariant = "secondary", small = false): string {
  if (variant === "link") return s.link;
  return cx(s.button, variant === "primary" && s.primary, small && s.small);
}

export function Button({
  variant = "secondary",
  small,
  className,
  type = "button",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; small?: boolean }) {
  return <button type={type} className={cx(buttonClass(variant, small), className)} {...rest} />;
}

// ---- panel ----

export function Panel({
  title,
  meta,
  children,
  flush,
  className,
  bodyClassName,
  style,
}: {
  title?: ReactNode;
  meta?: ReactNode;
  children?: ReactNode;
  flush?: boolean;
  className?: string;
  bodyClassName?: string;
  style?: CSSProperties;
}) {
  return (
    <section className={cx(s.panel, className)} style={style}>
      {(title || meta) && (
        <header className={s.panelHead}>
          {title && <span className={s.caps}>{title}</span>}
          {meta && <span className={s.panelHeadMeta}>{meta}</span>}
        </header>
      )}
      <div className={cx(s.panelBody, flush && s.flush, bodyClassName)}>{children}</div>
    </section>
  );
}

// ---- banner ----

export type BannerTone = "error" | "warn" | "info";

export function Banner({
  tone,
  title,
  children,
  actions,
  className,
}: {
  tone: BannerTone;
  title: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx(s.banner, s[tone], className)} role={tone === "error" ? "alert" : "status"}>
      {tone !== "info" && <Icon name={tone === "error" ? "error" : "warning"} className={s.bannerIcon} />}
      <div className={s.bannerText}>
        <div className={s.bannerTitle}>{title}</div>
        {children}
      </div>
      {actions && <div className={s.bannerActions}>{actions}</div>}
    </div>
  );
}

// ---- progress & skeleton ----

// `value` is a fraction; null draws an empty track, which is what "no count
// yet" looks like — a bar never pretends to know progress it was not told.
export function ProgressBar({ value, done, label }: { value: number | null; done?: boolean; label?: string }) {
  const pct = value === null ? 0 : Math.max(0, Math.min(1, value)) * 100;
  return (
    <div
      className={s.track}
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value === null ? undefined : Math.round(pct)}
    >
      <div className={cx(s.fill, done && s.fillDone)} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function Skeleton({ width, height, light }: { width: number | string; height?: number; light?: boolean }) {
  return <span className={cx(s.skeleton, light && s.skeletonLight)} style={{ width, height }} aria-hidden="true" />;
}

// ---- KPI tile ----

export function KpiTile({
  label,
  tone,
  value,
  sub,
}: {
  label: ReactNode;
  // omitted: the square is drawn in the text colour ("Total findings")
  tone?: Tone;
  value: ReactNode;
  sub?: ReactNode;
}) {
  return (
    <div className={s.kpi} style={tone ? toneVars(tone) : undefined}>
      <div className={s.kpiLabel}>
        <span className={s.kpiSquare} aria-hidden="true" />
        <span className={s.caps}>{label}</span>
      </div>
      <div className={s.kpiValue}>{value}</div>
      {sub && <div className={s.kpiSub}>{sub}</div>}
    </div>
  );
}
