import type { ReactNode } from "react";
import s from "./FilterBar.module.css";
import { Icon } from "./Icon";
import { Button } from "./primitives";
import { cx } from "./tone";

export interface FilterOption {
  value: string;
  label: string;
}

// "Severity  All ⌄". The empty string is "All"; any other value marks the
// filter active, which is how the mockup highlights it.
export function FilterSelect({
  label,
  value,
  options,
  onChange,
  allLabel = "All",
}: {
  label: string;
  value: string;
  options: FilterOption[];
  onChange: (value: string) => void;
  allLabel?: string;
}) {
  const current = options.find((option) => option.value === value)?.label ?? allLabel;
  return (
    <label className={cx(s.select, value !== "" && s.active)}>
      <span className={s.selectLabel}>{label}</span>
      <span className={s.selectValue}>{current}</span>
      <Icon name="chevronDown" size={14} className={s.chevron} />
      <select className={s.native} value={value} onChange={(event) => onChange(event.target.value)} aria-label={label}>
        <option value="">{allLabel}</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function FilterBar({
  search,
  children,
  onClear,
  count,
  className,
}: {
  // onSubmit: commit on Enter (a server query) rather than on every keystroke
  search?: { value: string; onChange: (value: string) => void; placeholder: string; onSubmit?: (value: string) => void };
  // FilterSelect elements
  children?: ReactNode;
  // Shown as "Clear filters" only when given; pass it only while a filter is set.
  onClear?: () => void;
  count?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx(s.bar, className)}>
      {search && (
        <div className={s.search}>
          <Icon name="search" size={14} className={s.searchIcon} />
          <input
            type="search"
            className={s.searchInput}
            value={search.value}
            placeholder={search.placeholder}
            aria-label={search.placeholder}
            onChange={(event) => search.onChange(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") search.onSubmit?.(search.value.trim());
            }}
          />
        </div>
      )}
      {children}
      {onClear && (
        <Button variant="link" onClick={onClear} style={{ fontSize: "var(--fs-xs)", marginLeft: 8 }}>
          Clear filters
        </Button>
      )}
      {count !== undefined && <span className={s.count}>{count}</span>}
    </div>
  );
}
