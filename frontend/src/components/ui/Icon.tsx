// The glyphs the mockups draw, and no others. 16px, stroked in currentColor so
// they take the colour of the text beside them.

const PATHS = {
  newScan: (
    <>
      <rect x="2.5" y="2.5" width="11" height="11" rx="1.5" />
      <path d="M8 5.5v5M5.5 8h5" />
    </>
  ),
  fileSelection: <path d="M2.5 4l1 1 2-2M2.5 8.5l1 1 2-2M2.5 13l1 1 2-2M8 4h5.5M8 8.5h5.5M8 13h5.5" />,
  overview: (
    <>
      <rect x="2.5" y="2.5" width="4.5" height="6" />
      <rect x="9" y="2.5" width="4.5" height="3.5" />
      <rect x="2.5" y="10.5" width="4.5" height="3" />
      <rect x="9" y="8" width="4.5" height="5.5" />
    </>
  ),
  findings: (
    <>
      <rect x="2.5" y="2.5" width="11" height="11" />
      <path d="M2.5 6h11M2.5 9.5h11M6.5 6v7.5" />
    </>
  ),
  drift: (
    <>
      <circle cx="4" cy="4" r="1.5" />
      <circle cx="12" cy="12" r="1.5" />
      <path d="M4 5.5v3A3.5 3.5 0 0 0 7.5 12H10M12 10.5v-3A3.5 3.5 0 0 0 8.5 4H6" />
    </>
  ),
  roadmap: (
    <>
      <circle cx="4" cy="4" r="1.5" />
      <circle cx="12" cy="12" r="1.5" />
      <path d="M5.5 4H11a2 2 0 0 1 0 4H5a2 2 0 0 0 0 4h5.5" />
    </>
  ),
  search: (
    <>
      <circle cx="7" cy="7" r="4.5" />
      <path d="M10.5 10.5 14 14" />
    </>
  ),
  chevronDown: <path d="m4.5 6.5 3.5 3.5 3.5-3.5" />,
  chevronLeft: <path d="M9.5 4.5 6 8l3.5 3.5" />,
  chevronRight: <path d="M6.5 4.5 10 8l-3.5 3.5" />,
  close: <path d="m4 4 8 8M12 4l-8 8" />,
  warning: <path d="M8 2.5 14 13H2L8 2.5ZM8 6.5v3M8 11.2v.3" />,
  error: (
    <>
      <circle cx="8" cy="8" r="5.5" />
      <path d="M8 5v3.5M8 10.7v.3" />
    </>
  ),
  download: <path d="M8 2.5v8M4.5 7 8 10.5 11.5 7M3 13.5h10" />,
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 16, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.3}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {PATHS[name]}
    </svg>
  );
}
