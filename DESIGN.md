---
name: GuardBee
description: Ship the policy. Not the outage.
colors:
  void: "#06090a"
  panel: "#0b1012"
  panel-raised: "#0f1619"
  line: "#1c2b2c"
  line-bright: "#2a4345"
  ink: "#cfe8e4"
  ink-dim: "#6e8886"
  ink-faint: "#45595a"
  signal: "#22e9c7"
  signal-dim: "#0f6d5f"
  drop: "#ff5d5d"
  allow: "#ffb648"
  unchanged: "#5ee8a5"
typography:
  display:
    fontFamily: "Martian Mono, ui-monospace, monospace"
    fontSize: "1.5rem"
    fontWeight: 700
    lineHeight: 1.33
    letterSpacing: "0.08em"
  title:
    fontFamily: "Martian Mono, ui-monospace, monospace"
    fontSize: "0.75rem"
    fontWeight: 600
    lineHeight: 1.33
    letterSpacing: "0.025em"
  body:
    fontFamily: "IBM Plex Mono, ui-monospace, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.33
  body-lg:
    fontFamily: "IBM Plex Mono, ui-monospace, monospace"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.43
  label:
    fontFamily: "IBM Plex Mono, ui-monospace, monospace"
    fontSize: "0.65rem"
    fontWeight: 600
    letterSpacing: "0.18em"
rounded:
  none: "0px"
  sm: "2px"
  full: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "20px"
  page: "24px"
  page-wide: "40px"
components:
  button-primary:
    backgroundColor: "{colors.signal}"
    textColor: "{colors.void}"
    typography: "{typography.title}"
    rounded: "{rounded.none}"
    padding: "10px 16px"
  button-signal-outline:
    textColor: "{colors.signal}"
    rounded: "{rounded.none}"
    padding: "6px 12px"
  button-secondary:
    backgroundColor: "{colors.void}"
    textColor: "{colors.ink}"
    typography: "{typography.title}"
    rounded: "{rounded.none}"
    padding: "8px 12px"
  tab:
    textColor: "{colors.ink-dim}"
    typography: "{typography.title}"
    rounded: "{rounded.sm}"
    padding: "6px 16px"
  tab-active:
    backgroundColor: "{colors.signal}"
    textColor: "{colors.void}"
    rounded: "{rounded.sm}"
  input:
    backgroundColor: "{colors.void}"
    textColor: "{colors.ink}"
    typography: "{typography.body-lg}"
    rounded: "{rounded.none}"
    padding: "8px 12px"
  panel:
    backgroundColor: "{colors.panel}"
    rounded: "{rounded.none}"
    padding: "20px"
  chip-meta:
    backgroundColor: "{colors.panel-raised}"
    textColor: "{colors.ink-dim}"
    rounded: "{rounded.none}"
    padding: "2px 8px"
  chip-headline-drop:
    backgroundColor: "{colors.drop}"
    textColor: "{colors.void}"
    rounded: "{rounded.none}"
    padding: "4px 10px"
  chip-headline-allow:
    backgroundColor: "{colors.allow}"
    textColor: "{colors.void}"
    rounded: "{rounded.none}"
    padding: "4px 10px"
---

# Design System: GuardBee

## Overview

**Creative North Star: "The Console"**

GuardBee is a CLI wearing a browser, and the design leans into that instead of hiding it behind product chrome. Everything is set in monospace. Panels are drawn with 1px hairlines and square corners, like a terminal UI. Labels are uppercase and widely tracked, like an instrument readout. The dark theme is a phosphor CRT: near-black void, cyan-green ink, a faint scanline texture. The light theme is a technical lab console: white panels on cool grey, cyan accent, the same texture retuned so it is still visible. Both themes are first-class.

Density is high and deliberate. The primary user is a platform engineer reading flows, so rows are tight, type is small (0.75rem body), and metadata appears as chips. Colour is rationed. One electric signal accent marks what you can act on and where you are. Three verdict colours (drop red, allow amber, unchanged green) carry meaning and nothing else. Filled colour goes only on the answer: the Run verdict button and the newly-dropped and newly-allowed headline chips.

Controls should feel terminal-tactile, like keys and readouts on an instrument. A press gives a crisp response (the `active:scale-98` nudge on chips, a border shifting to signal on hover). There is no soft lift.

**Key Characteristics:**
- Monospace throughout: Martian Mono for display and labels, IBM Plex Mono for everything else.
- 1px hairline borders, square corners, flat surfaces.
- One signal accent, kept apart from the three verdict colours.
- Dark phosphor and light lab-console themes, equally maintained.
- Ambient scanlines and a radar wash fixed to the viewport, never tiled into components.

## Colors

The palette is a cool teal-black field, with a single electric cyan for action and three verdict colours that carry meaning. The frontmatter holds the dark (home) values. Light-theme values live in `ui/src/index.css` under `[data-theme="light"]` and in `.impeccable/design.json`. Every token is defined as `--theme-*` and exposed to Tailwind as `--color-*`.

### Primary
- **Phosphor Signal** (signal; light theme: deep cyan `#0891b2`): active tab, primary button fill, section labels, focus borders, live/pulsing status dots, links to act on, row actions, non-verdict status (a valid parse, a CCNP kind tag, a policy side the draft governs). In light mode it was moved from teal toward blue so it never reads as the unchanged green.
- **Signal Shadow** (signal-dim): the selection background, and low-opacity tints behind signal-outlined controls.

### Verdict semantics
- **Breach Red** (drop): `NEWLY_DROPPED`, `DROPPED`, errors, the "would BREAK" banner, blocked graph links ending at an ✕ gate.
- **Caution Amber** (allow): `NEWLY_ALLOWED`, `AUDIT`.
- **Steady Green** (unchanged): `UNCHANGED`, `FORWARDED`, allowed graph links.

These match the CLI's ANSI colouring in `colors.go`, so a category reads the same in the terminal and the browser.

### Neutral
- **Void** (void): the page background and the input wells.
- **Console Panel** (panel): every content panel and modal body.
- **Raised Panel** (panel-raised): popovers, dropdown menus, meta chips, table headers.
- **Hairline** (line): default borders, dividers, the rules beside section labels.
- **Bright Hairline** (line-bright): borders on overlays and hovered secondary controls, and scrollbar thumbs.
- **Phosphor Ink** (ink): primary text.
- **Dim Ink** (ink-dim): secondary text, inactive tabs, metadata.
- **Faint Ink** (ink-faint): placeholders, build version, tertiary hints.

### Named Rules
**The Signal Is Not a Verdict Rule.** The signal cyan never stands in for drop, allow or unchanged. Red, amber and green are never used decoratively. If a colour on screen doesn't mean a verdict, it is signal or a neutral.

**The Filled Answer Rule.** Solid colour fills are reserved for the answer GuardBee exists to give: the primary Run button and the newly-dropped and newly-allowed headline chips. Every other chip or tag is a 40%-opacity border over a 10% tint.

## Typography

**Display Font:** Martian Mono (with ui-monospace, monospace)
**Body Font:** IBM Plex Mono (with ui-monospace, monospace)

**Character:** Martian Mono is wide and engineered, and it carries headings, buttons and tabs in tracked uppercase. IBM Plex Mono is the readable workhorse for flows, YAML, identities and prose. Together they read as a terminal with a nameplate.

### Hierarchy
- **Display** (Martian Mono 700, 1.5rem, tracking 0.08em, uppercase): the app's GUARDBEE wordmark in the header only.
- **Title** (Martian Mono 600–700, 0.75rem, tracking 0.025–0.1em, uppercase): tabs, buttons, panel headings, empty-state headings.
- **Body** (IBM Plex Mono 400, 0.75rem): the default for tables, flow rows, YAML editors and help text. Use `leading-relaxed` for prose blocks and editors.
- **Body Large** (IBM Plex Mono 400, 0.875rem): form inputs, error and status banners.
- **Label** (0.6–0.7rem, 600–700, tracking 0.1–0.18em, uppercase): section labels (signal, flanked by hairlines), table column headers, verdict chips, the build-version line.

### Named Rules
**The Words-Not-Emoji Rule.** Controls and graph nodes carry words or the console's text symbols (✓ ✕ ✎ ⚠ ⎈ ⤢ ▾), never emoji. `ui/e2e/design.e2e.ts` checks every tab.

**The Readout Rule.** Anything that labels, rather than says, is uppercase and tracked. Anything the user reads as data (identities, ports, YAML, counts) keeps its own case.

## Layout

The page is full width, with a header bar (`panel` at 70% opacity, `backdrop-blur-sm`, bottom hairline) above a single main column. Gutters are 24px, growing to 40px at `lg` (1024px). The header wraps its brand block and tab nav with `flex-wrap`. The tab strip scrolls horizontally inside itself rather than pushing the page wider. Content panels stack with 20px internal padding. Two-column panel grids appear at `sm`/`xl` and collapse to one column below. Tabs stay mounted when hidden, so state survives switching.

The spacing rhythm follows Tailwind's 4px grid: 8px and 12px gaps inside controls and rows, 20px panel padding, 32px between page sections. The supported range is desktop and laptop widths; phones are out of scope. Wide tables and graphs scroll inside their own frame.

## Elevation & Depth

The system is flat by default. Depth comes from tone (void, then panel, then panel-raised) and from hairline weight (line, then line-bright), not from shadows. Shadows appear only on layers that float above the page: `shadow-lg` on popovers and dropdowns, `shadow-2xl` on modals. Those layers also switch to the bright hairline. The one luminous effect is the signal glow: a soft cyan halo (`0 0 8px` signal-glow) on live status dots, and the `glow-pulse` animation on in-progress indicators.

### Named Rules
**The Flat-Until-Floating Rule.** A surface that sits in the page flow never gets a shadow. Only overlays (popovers, menus, modals) lift, and when they lift they also brighten their border.

## Shapes

The shapes are square: 0px corners on panels, buttons, inputs, chips and table frames. A 2px radius (`rounded-sm`) softens only the tab strip and its pills. Full rounding is kept for things that are actually round: status dots, ⓘ affordances, quick-filter pills, probe stepper steps, and the circular POD/HOST/WORLD/API/IP endpoint nodes in the flow graphs. Scrollbars are 8px with square thumbs.

## Components

### Buttons
Terminal-tactile: they press like keys, they don't float.
- **Shape:** square corners (0px).
- **Primary:** signal fill, void text, Martian Mono bold uppercase, tracking 0.1em, 10px vertical padding. Used for Run verdict and modal confirmation. Hover drops opacity to 90%. Disabled is 40% opacity with a not-allowed cursor.
- **Signal outline:** 1px signal border over a 10% signal tint, signal text, bold uppercase 0.65–0.75rem. Hover fills it with signal and switches the text to void. Used for preset menus and workspace actions.
- **Secondary:** 1px hairline border over void at 60%, ink text, Martian Mono uppercase. Hover shifts the border to signal (or line-bright) and the text to signal or ink.
- **Text actions:** uppercase tracked Martian Mono links with no box, in dim ink that turns signal on hover (`TEXT_ACTION` in `shared/chipStyles.ts`). They are used for housekeeping on every run card and panel header, e.g. DUPLICATE TO FORM, COPY, CSV, COLLAPSE, SAVE, ⤢ EXPAND. Verdict and Flows run cards use the same set, never boxed buttons.
- **Row actions:** an action repeated on every table row (New block policy, Edit in Policy Editor, Allow / Block) is signal-coloured, never red. Red on a row means the row's verdict, nothing else.

### Tabs
- A single strip inside a hairline box on void at 60%, with 4px inner padding and a 2px radius. Each tab is Martian Mono 0.75rem semibold uppercase. Inactive tabs are dim ink and turn ink on hover. The active tab is filled signal with void text.

### Chips
- **Verdict chips:** a 40% category border over a 10% category tint, category-coloured text, uppercase label type.
- **Headline count chips:** filled drop or allow, void text, bold. They carry a count, a label and a ⓘ affordance that is deliberately not category-coloured, so it reads as the clickable part. Press scales them to 98%.
- **Meta chips:** hairline border on panel-raised, 0.7rem mono, dim ink (e.g. `context:`, `namespace:`, `last:`). Signal-tinted when they describe an active mode.
- **Quick-filter pills:** fully rounded and bordered. They are the one rounded chip type.

### Panels
- **Corner Style:** square (0px).
- **Background:** panel, on the void page.
- **Shadow Strategy:** none (see Flat-Until-Floating).
- **Border:** 1px hairline.
- **Internal Padding:** 20px, or 32px for centred empty states.
- **Entry:** `rise-in` (6px rise plus fade, 0.42s, `cubic-bezier(0.16, 1, 0.3, 1)`), with no fill mode, so fixed-position children aren't trapped.

### Inputs / Fields
- **Style:** 1px hairline border, void background, ink text, square corners, 8px by 12px padding. YAML editors use 0.75rem mono with relaxed leading and are resizable vertically.
- **Focus:** the border switches to signal and the browser outline is removed.
- **Error:** errors appear as a separate banner (drop 40% border, drop 10% tint, drop text), never as red fields.

### Section Label
A centred uppercase label in signal (0.65rem, tracking 0.18em), flanked by two hairline rules that fill the row (`SectionLabel` in `Chips.tsx`). It is the only heading style for a panel or a region inside one, on every tab: SCOPE, CANDIDATE POLICY, POLICY METADATA & SCOPE, FLOW GRAPH, CONNECTIVITY TESTS. Panel actions (Save, Expand, Presets, Reset form) go in its `actions` slot, after the closing rule.

### Tab Skeleton
Every tab follows the same order: a SCOPE (or metadata) panel with fields on one aligned row, then a `ResultsHeader` (white Martian Mono title over a hairline, with an optional Clear action), then the results, or an `EmptyState` (`>_` glyph, uppercase title, one-line instruction) before the first run. Checkboxes and buttons beside inputs are offset by one label height (`FIELD_ROW_OFFSET`) so they align with the inputs, not with the labels.

### Flow Graphs (signature)
Verdict, Flows and connectivity-test paths share one graph language (`GraphPathParts.tsx`, `graphPath.ts`). Endpoints are round nodes labelled POD/HOST/WORLD/API/IP, with namespace and name set beside them. Allowed links are solid green curves. Blocked links are dashed red and stop at an ✕ gate that carries a protocol:port ×count tag. Only links that changed (Verdict) or touch the selected node animate. On connectivity paths, allowed lanes' dashes travel source to destination (`probe-flow`, 0.9s linear). All decorative motion stops under `prefers-reduced-motion`.

## Do's and Don'ts

### Do:
- **Do** set every surface in monospace: Martian Mono for display and title roles, IBM Plex Mono for body and data.
- **Do** draw structure with 1px hairlines (line, line-bright on overlays) and keep corners square.
- **Do** keep signal cyan for action, focus and "you are here", and keep drop, allow and unchanged strictly for verdict meaning, matching `colors.go`.
- **Do** reserve solid fills for the answer: the primary Run button and the newly-dropped and newly-allowed headline chips.
- **Do** define every new colour as a `--theme-*` pair in both the dark and light blocks of `index.css`, and check it in both themes before shipping.
- **Do** honour `prefers-reduced-motion` for any looping animation.

### Don't:
- **Don't** add SaaS chrome: no soft rounded cards, pastel gradients, drop-shadowed tiles or generic dashboard styling.
- **Don't** use signal cyan to mean allowed or OK, and don't use red, amber or green as decoration or brand colour.
- **Don't** ship an effect that only works in dark mode. Light mode needs its own tuned values (as the scanline alpha does), not a copy.
- **Don't** put shadows on in-flow panels. Only popovers, menus and modals lift.
- **Don't** put emoji in controls, labels or graph nodes. Use words or the console's text symbols.
- **Don't** invent a new panel heading style. Every panel and region uses the Section Label, with actions in its slot.
- **Don't** tile the scanline or grid texture into components. It lives once, fixed to the viewport, on `body::before`.
