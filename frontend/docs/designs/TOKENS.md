# ECDAT design tokens

Extracted from the 24 mockups in this folder (1440×900 @1x). Colours were sampled
from pixels with Pillow, not estimated by eye; sizes were measured on the 1x grid.
`src/styles/tokens.css` implements this file. Where the two disagree, fix one of them.

**Uncertain values are marked ⚠.** Pixel sampling of 1px lines at 1x picks up
anti-aliasing, so border colours are the darkest value found across the edge.

> Note: the mockups live in `docs/designs/` (plural), not `docs/design/`.

---

## 1. Fonts

| Role | Family | Weights used | Package |
|---|---|---|---|
| UI / prose | IBM Plex Sans | 400, 500, 600, 700 | `@fontsource/ibm-plex-sans` |
| Technical identifiers, numerals | IBM Plex Mono | 400, 500, 600 | `@fontsource/ibm-plex-mono` |

⚠ Family identified from glyph shapes (Plex Sans's `g`, `R`, `Q`; Plex Mono's slab `r`,
dotted zero). High confidence but not confirmed against a design file.

Mono is used for: scan IDs, paths, `host:port`, algorithm names + parameters, rule
IDs, versions, timestamps/elapsed, hashes, KPI numerals, table counts, the Mosca
score, log/terminal blocks, and the sidebar footer values.

## 2. Type scale

| Token | px | Weight | Used for |
|---|---|---|---|
| `--fs-2xs` | 11 | 500–600, caps, `letter-spacing: .08em` | Panel/section labels (`TARGET`, `RECENT SCANS`), table headers, badges, sidebar `CURRENT SCAN` |
| `--fs-xs` | 12 | 400 | Help text, sub-lines, page subtitle, mono cells, topbar meta |
| `--fs-sm` | 13 | 400 / 500 / 600 | Body, table cells, nav items, buttons, inputs |
| `--fs-md` | 15 | 600 | Page title (`New Scan`), detail-panel title |
| `--fs-lg` | 17 | 600 | State-panel title (`Archive could not be unpacked`) |
| `--fs-kpi` | 26 | 500, mono | KPI numerals, Mosca risk score |

Line height: 1.4 for body; 1.2 for KPI numerals. ⚠ Title sizes are ±1px.

## 3. Colour

### 3.1 Neutrals — content area (light)

| Token | Hex | Where |
|---|---|---|
| `--canvas` | `#f3f3f2` | Area behind panels; group rows in tables |
| `--surface` | `#ffffff` | Panels, top bar, table rows |
| `--surface-sunken` | `#f7f7f6` | Table header row, code/log blocks, detail chips |
| `--surface-page-head` | `#fafaf9` | Page header strip under the top bar |
| `--surface-disabled` | `#f5f5f4` | Locked inputs (surface scan running) |
| `--border` | `#e2e2e0` | Panels, inputs, buttons, dropdowns, code blocks ⚠ (sampled `#e2e2e0`–`#e9e9e7`) |
| `--border-subtle` | `#e9e9e8` | Top bar / page header bottom borders |
| `--divider` | `#f0f0ee` | Table row separators, list rules inside panels |
| `--text` | `#1b1b1a` | Primary text, KPI numerals |
| `--text-2` | `#52524e` | Secondary text (mode column, descriptions) |
| `--text-3` | `#5f5f5b` | Caps labels, table headers |
| `--text-help` | `#62625e` | Help lines, subtitles, deselected paths |
| `--text-faint` | `#8a8a85` | Code line numbers, placeholders, "off" |
| `--skeleton` | `#ececea` | Loading placeholder bars |
| `--skeleton-2` | `#f0f0ee` | Second line of a two-line skeleton; bar track |

### 3.2 Sidebar (dark)

| Token | Hex |
|---|---|
| `--sb-bg` | `#1c1c1b` |
| `--sb-divider` | `#2a2a28` |
| `--sb-active` | `#30302e` (active nav item fill) |
| `--sb-text` | `#b0b0ab` (nav items) |
| `--sb-text-strong` | `#ffffff` (brand, active item, scan id) |
| `--sb-text-muted` | `#7c7c77` (section heading, footer labels) |
| `--sb-count` | `#8e8e8a` (nav counts, version) |

Status squares on the dark sidebar are lighter tints: complete `#7fb58a`,
running `#86a9c4`, awaiting `#d9a45a`, failed `#d98b84`.

### 3.3 Accent (the only brand colour)

| Token | Hex | Where |
|---|---|---|
| `--accent` | `#35607f` | Primary button, active segment/tab, checkbox, progress fill, scan-ID links |
| `--accent-text` | `#2c5373` | "Surface scan running" / "Probing endpoints" titles, info badge text |
| `--accent-link` | `#3e6785` | Underlined text links (`Open roadmap`, `Clear filters`, `F-004`) |
| `--accent-ink` | `#1f3d52` | Recommended-target text in tables |
| `--accent-bg` | `#e2eaf0` | Info/running badge fill |
| `--accent-bg-soft` | `#f0f4f7` | Info panel fill, streaming strip |
| `--accent-select` | `#e8eff5` | Selected table row |
| `--accent-hover` | `#f6f8fa` | Hovered table row |
| `--accent-option` | `#f1f5f8` | Selected radio card, active filter dropdown |
| `--accent-border` | `#dae3eb` | Info panel border ⚠ (probe panel sampled `#d4dee7`) |
| `--accent-border-strong` | `#829db0` | Active filter dropdown, selected radio card (`#5b7f98` at the radio) |
| `--accent-chip-border` | `#c3d1db` | Target-algorithm chip in recommendation |
| `--accent-track` | `#d6e0e8` | Progress bar track |

### 3.4 Severity (colour + label, always both)

Each severity has three values: `solid` (squares, dots, bar fills), `bg` (badge fill),
`fg` (badge text).

| Severity | Mockup labels | solid | bg | fg |
|---|---|---|---|---|
| critical | Critical · Classically weak · Weaker than declared · Failed · Unreachable | `#b0473f` | `#f5e6e3` | `#8f2a24` |
| high | High · Quantum-vulnerable · Awaiting approval · Unassigned · Completed with errors | `#c07a1c` | `#f7ebd8` | `#7a4906` |
| medium | Medium · Grover-reduced | `#a8912c` | `#f2eed5` | `#605312` |
| safe | Safe · PQC-ready · Complete · Ready · Stronger than declared · Nothing to migrate | `#4d8659` | `#e4efe6` | `#2d6339` |
| unknown | Unknown · Unscored · Not evaluated · Match · Queued · Cancelled · Idle | `#8a8a85` (bars) / `#9a9a95` (dots, squares) | `#ebebe9` | `#51514c` |
| blocked | Blocked · Blocked recs · Undeclared · Accepted risk | `#7a7091` | `#eae8f0` | `#51496a` |
| info | Running · Surface scan · Analysis running · Probing… | `#35607f` | `#e2eaf0` | `#2c5373` |

⚠ **Mapping to the API is open.** The API's verdicts are `broken_now`,
`quantum_vulnerable`, `quantum_safe`, `hygiene`, `unknown`; it has no
critical/high/medium severity and no "Grover-reduced" verdict. The obvious
reading is broken_now→critical, quantum_vulnerable→high, quantum_safe→safe,
unknown→unknown. `hygiene` and "medium" have no clean counterpart. To be decided on
screens 03/04, not guessed here.

### 3.5 Banners (callouts)

| Kind | bg | border | title |
|---|---|---|---|
| error (validation, policy error, probe failed) | `#f8ecea` | `#ecd5d1` (`#e5c9c5` on probe failed) | `#8f2a24` |
| warning (completed with errors) | `#fbf3e6` | `#ebdfca` | `#6a3f05` |
| info (surface scan running) | `#f0f4f7` | `#dae3eb` | `#2c5373` |

Field errors: input border `#dfb5b2`, message text `#8f2a24`. Required-empty
input border `#c06c65`, message `#963833`.

### 3.6 Data visualisation

| Token | Hex | Where |
|---|---|---|
| bar track | `#f0f0ee` | Horizontal bars (algorithm family, collector) |
| neutral bar | `#6f8799` | By-source-collector bars; Mosca Y |
| Mosca X | `#b9c6cf` | |
| Mosca Z | `#e7e7e4` | |
| Mosca exposed | bg `#f2d9d5`, border `#be6760`, text `#8f2a24` | |
| axis rule | `#ececea` | |

Severity-stacked bar and algorithm bars use the severity `solid` values.

### 3.7 Drift diff

| Row | bg | text |
|---|---|---|
| weaker than declared (+) | `#f5dcd8` | `#5c1f1a` |
| stronger than declared | `#dcebdf` | — |
| declared, not offered (−, struck) | `#ececea` | `--text-help`, line-through |

### 3.8 Code / evidence block

bg `#f7f7f6`, border `#e2e2e0`, highlighted line `#f7e9cf`, line numbers `#8a8a85`.

## 4. Spacing

4px base grid.

| Token | px | Where |
|---|---|---|
| `--sp-1` | 4 | Badge gaps, icon–label |
| `--sp-2` | 8 | Button groups, cell padding-y |
| `--sp-3` | 12 | Panel header padding-x, table cell padding-x |
| `--sp-4` | 16 | Canvas padding, gap between panels, panel body padding |
| `--sp-5` | 20 | Between form sections |
| `--sp-6` | 24 | |
| `--sp-8` | 32 | State-panel vertical rhythm |

Fixed dimensions:

| Token | px |
|---|---|
| `--sidebar-w` | 233 |
| `--topbar-h` | 44 |
| `--pagehead-h` | 49 |
| `--row-h` | 33 (tables; findings 32) |
| `--control-h` | 32 (inputs, buttons, dropdowns, segments) |
| `--badge-h` | 18 |
| `--nav-item-h` | 32 |
| `--state-max-w` | 640 (state-panel content column, centred, top-offset ~80px) |

## 5. Radius & borders

| Token | Value |
|---|---|
| `--radius-sm` | 2px (panels, badges, chips, skeleton bars) |
| `--radius` | 3px (buttons, inputs, dropdowns, segmented control) ⚠ ±1px |
| `--radius-nav` | 4px (sidebar active item) |
| `--bw` | 1px everywhere; no 2px borders appear |

No shadows, gradients or animations appear in any mockup.

## 6. Recurring components

| Component | Seen on | Anatomy |
|---|---|---|
| **AppShell** | all 24 | Dark sidebar (brand + version, CURRENT SCAN block with status square, nav with counts, footer Policy/Rules/Store); white top bar (scan id · target · status badge · timing, right side pill + user); page header strip (title + subtitle + right-aligned actions) |
| **StatusBadge / SeverityBadge** | all | 18px pill-less tag, 11px text; severity variant prefixes a 6px square in `solid` |
| **VerdictDot** | 04, 06 | 8px circle in `solid` + label |
| **KpiTile** | 03 | caps label with 8px colour square, 26px mono number, 12px sub-line (ellipsised) |
| **Panel** | all | white, 1px border, 2px radius, optional header (caps label left, meta/action right, bottom divider) |
| **DataTable** | 01, 02, 03, 04, 05, 06 | sunken header row, 11px caps headers, 33px rows, `--divider` separators, selected row `--accent-select`; sortable column shows `↓` |
| **FilterBar** | 04, 02 | search input with magnifier, dropdown buttons `Label  Value ⌄` (active one gets `--accent-option` fill + strong border), `Clear filters` link, right-aligned result count |
| **DetailPanel** | 04, 05 | right column, 1px left border, header with breadcrumb + close ×, stacked caps-labelled sections, sticky action footer |
| **MonoText** | all | Plex Mono span; `muted` variant |
| **StatePanel** | 18 of 24 | full panel; centred column; optional tag badge + mono meta line; 17px title; body paragraph; optional mono log block; `NEXT STEPS` list; primary + secondary buttons. Loading variant: title + progress bar + elapsed + mono log |
| **Skeleton rows** | 02 enumerating, 04 streaming, 06 scoring | grey bars in table cells |
| **ProgressBar** | 01, 02, 03, 04, 05 | 4px bar, `--accent` fill on `--accent-track` (green fill when a collector is done) |
| **Banner** | 01, 03, 04, 05 | icon, bold title, detail line (often mono), right-aligned secondary + primary buttons |
| **SegmentedControl** | 01, 02 | joined buttons, active = `--accent` fill + white semibold |
| **RadioCard** | 01 | bordered card; selected = `--accent-option` fill + `--accent-border-strong` |
| **Button** | all | primary (accent fill, white, 600), secondary (white, border, 400), disabled (`#ebebe9`, `--text-help`) |
| **HBar** | 03 | label · track+fill · mono count |
| **StackedBar** | 03 | severity segments with count inside, legend below (`■ Critical 9 · 19%`) |
| **CodeBlock** | 04, 05, 02 | sunken, mono 12px, line numbers, highlighted lines |
| **KeyValueList** | 01, 02, 03, 04 | label left (sans, `--text-2`), value right or second column (mono) |
