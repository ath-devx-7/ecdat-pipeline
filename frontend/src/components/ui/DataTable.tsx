import { Fragment, useMemo, useState, type ReactNode } from "react";
import s from "./DataTable.module.css";
import { Skeleton } from "./primitives";
import { cx } from "./tone";

export interface Column<T> {
  key: string;
  header: ReactNode;
  render: (row: T) => ReactNode;
  width?: number | string;
  align?: "left" | "right";
  mono?: boolean;
  // A column is sortable when it has a sortValue (local sort) or when the
  // table is given onSortChange (the caller sorts, e.g. server-side).
  sortValue?: (row: T) => string | number | null;
  sortable?: boolean;
  // skeleton bar width while loading, in px
  skeletonWidth?: number;
}

export interface Sort {
  key: string;
  dir: "asc" | "desc";
}

export interface TableSection<T> {
  key: string;
  header: ReactNode;
  rows: T[];
}

interface Props<T> {
  columns: Column<T>[];
  rowKey: (row: T) => string;
  rows?: T[];
  // Grouped rows (a header row per group); used instead of `rows`.
  sections?: TableSection<T>[];
  selectedKey?: string | null;
  // extra class per row (group rows, changed rows)
  rowClassName?: (row: T) => string | undefined;
  onRowClick?: (row: T) => void;
  // Controlled sort. Without onSortChange the table sorts `rows` itself.
  sort?: Sort | null;
  onSortChange?: (sort: Sort) => void;
  defaultSort?: Sort;
  // Placeholder rows drawn after the real ones — "more are coming".
  loadingRows?: number;
  // Shown in place of the body when there are no rows and nothing is loading.
  empty?: ReactNode;
  // Let cells wrap onto a second line (path + sub-line layouts).
  wrap?: boolean;
  className?: string;
}

export function DataTable<T>({
  columns,
  rowKey,
  rows,
  sections,
  selectedKey,
  rowClassName,
  onRowClick,
  sort: controlledSort,
  onSortChange,
  defaultSort,
  loadingRows = 0,
  empty,
  wrap,
  className,
}: Props<T>) {
  const [localSort, setLocalSort] = useState<Sort | null>(defaultSort ?? null);
  const sort = onSortChange ? (controlledSort ?? null) : localSort;

  const sortedRows = useMemo(() => {
    if (!rows || onSortChange || !sort) return rows ?? [];
    const column = columns.find((c) => c.key === sort.key);
    if (!column?.sortValue) return rows;
    const get = column.sortValue;
    const sign = sort.dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const x = get(a);
      const y = get(b);
      if (x === y) return 0;
      if (x === null) return 1;
      if (y === null) return -1;
      return (x < y ? -1 : 1) * sign;
    });
  }, [rows, columns, sort, onSortChange]);

  function toggle(column: Column<T>) {
    const next: Sort =
      sort?.key === column.key
        ? { key: column.key, dir: sort.dir === "asc" ? "desc" : "asc" }
        : { key: column.key, dir: "desc" };
    if (onSortChange) onSortChange(next);
    else setLocalSort(next);
  }

  const renderRow = (row: T) => {
    const key = rowKey(row);
    return (
      <tr
        key={key}
        className={cx(s.row, onRowClick && s.clickable, selectedKey === key && s.selected, rowClassName?.(row))}
        onClick={onRowClick ? () => onRowClick(row) : undefined}
        aria-selected={selectedKey === key || undefined}
      >
        {columns.map((column) => (
          <td key={column.key} className={cx(s.td, column.align === "right" && s.right, column.mono && s.mono)}>
            {column.render(row)}
          </td>
        ))}
      </tr>
    );
  };

  const hasRows = sections ? sections.some((section) => section.rows.length > 0) : sortedRows.length > 0;

  return (
    <div className={cx(s.wrap, wrap && s.wrapCells, className)}>
      <table className={s.table}>
        <colgroup>
          {columns.map((column) => (
            <col key={column.key} style={column.width !== undefined ? { width: column.width } : undefined} />
          ))}
        </colgroup>
        <thead>
          <tr>
            {columns.map((column) => {
              const canSort = Boolean(column.sortValue || (onSortChange && column.sortable));
              const active = sort?.key === column.key;
              return (
                <th
                  key={column.key}
                  className={cx(s.th, column.align === "right" && s.right)}
                  aria-sort={active ? (sort!.dir === "asc" ? "ascending" : "descending") : undefined}
                >
                  {canSort ? (
                    <button type="button" className={cx(s.sortButton, active && s.sorted)} onClick={() => toggle(column)}>
                      {column.header}
                      {active && <span aria-hidden="true">{sort!.dir === "asc" ? "↑" : "↓"}</span>}
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sections
            ? sections.map((section) => (
                <Fragment key={section.key}>
                  <tr className={s.section}>
                    <td colSpan={columns.length}>{section.header}</td>
                  </tr>
                  {section.rows.map(renderRow)}
                </Fragment>
              ))
            : sortedRows.map(renderRow)}
          {Array.from({ length: loadingRows }, (_, i) => (
            <tr key={`skeleton-${i}`} className={s.row} aria-hidden="true">
              {columns.map((column) => (
                <td key={column.key} className={cx(s.td, column.align === "right" && s.right)}>
                  <Skeleton width={column.skeletonWidth ?? "70%"} />
                </td>
              ))}
            </tr>
          ))}
          {!hasRows && loadingRows === 0 && empty && (
            <tr>
              <td colSpan={columns.length} className={s.emptyCell}>
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
