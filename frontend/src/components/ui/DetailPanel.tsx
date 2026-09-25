import type { ReactNode } from "react";
import s from "./DetailPanel.module.css";
import { Icon } from "./Icon";
import { Caps } from "./primitives";
import { cx } from "./tone";

// The right-hand inspector: breadcrumb + close, a title, caps-labelled
// sections, and an action footer that stays put while the body scrolls.
export function DetailPanel({
  breadcrumb,
  onClose,
  title,
  children,
  footer,
  footerEnd,
  className,
}: {
  breadcrumb?: ReactNode;
  onClose?: () => void;
  title?: ReactNode;
  children: ReactNode;
  // left-aligned footer buttons
  footer?: ReactNode;
  // right-aligned footer button (the primary action)
  footerEnd?: ReactNode;
  className?: string;
}) {
  return (
    <aside className={cx(s.panel, className)}>
      {(breadcrumb || onClose) && (
        <div className={s.head}>
          <span className={s.crumb}>{breadcrumb}</span>
          {onClose && (
            <button type="button" className={s.close} onClick={onClose} aria-label="Close">
              <Icon name="close" size={14} />
            </button>
          )}
        </div>
      )}
      <div className={s.body}>
        {title && <h2 className={s.title}>{title}</h2>}
        {children}
      </div>
      {(footer || footerEnd) && (
        <div className={s.footer}>
          {footer}
          {footerEnd && <span className={s.footerEnd}>{footerEnd}</span>}
        </div>
      )}
    </aside>
  );
}

export function DetailSection({ title, aside, children }: { title: ReactNode; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className={s.section}>
      <div className={s.sectionHead}>
        <Caps>{title}</Caps>
        {aside && <span className={s.sectionAside}>{aside}</span>}
      </div>
      {children}
    </section>
  );
}
