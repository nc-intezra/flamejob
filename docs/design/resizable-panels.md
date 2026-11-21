# Investigation: draggable resize & lock for dashboard panels

**Status:** investigation only — nothing here is implemented in v1.2.0. This note
captures the options, how each fits flamejob's current layout, and a
recommendation, so a later release can pick an approach deliberately.

## What we have today

`dashboard.html` is a single hand-written page. Layout is pure CSS, no JS layout
engine:

- `main` is a flex column of **regions**.
- `region-top` and `region-mid` are CSS **grids** (`grid-template-columns`), with
  fixed fractions (`1.5fr 1fr`, `1fr 1fr`) and `flex` ratios for height
  (`flex:2` vs `flex:1`).
- Panels are `.panel` flex children; the full-width Agents/Admin panels follow.

So "resize" means letting the user drag the **column split** inside a region
(horizontal) and the **region height split** (vertical), and "lock" means
freezing those splits (and ideally the whole arrangement) so a drag can't happen.

## The requirements, concretely

1. **Resize**: drag a gutter between two panels to re-apportion width; drag
   between the top and mid regions to re-apportion height.
2. **Lock**: a toggle that disables the gutters (and hides the drag handles), so
   the layout is fixed for operators who don't want to fiddle.
3. **Persist**: remember each user's sizes and lock state across reloads.
4. **Not regress**: keep the current responsive behaviour and the role-gated
   show/hide (`gatePanels`), and don't pull in a heavy framework.

## Options

### A. Native CSS `resize` + a flexbox/grid gutter — zero dependencies
Each resizable panel gets `resize: horizontal|both; overflow: auto`, or a thin
draggable gutter element updates a CSS variable (e.g. `--split-top: 1.5fr 1fr`)
via a few lines of pointer-event JS.

- **Pros:** no dependency; tiny; integrates directly with the existing grid by
  rewriting `grid-template-columns`/`flex` from a drag handler; trivial to lock
  (remove the gutter / set `pointer-events:none`); persistence is a
  `localStorage` string of the template values.
- **Cons:** we write the drag math (clamping, min sizes, touch) ourselves;
  native `resize` is corner-handle only and visually coarse; multi-gutter
  bookkeeping gets fiddly as panels are added.
- **Fit:** excellent for the *current* two-split layout; this is the smallest
  thing that satisfies all four requirements.

### B. Split.js — minimal split-pane library (~2 KB gzip, no deps)
Purpose-built for exactly draggable gutters between flex children; returns an
instance whose `getSizes()/setSizes()` we persist, and `destroy()`/re-init (or a
CSS class) handles lock.

- **Pros:** mature, tiny, framework-agnostic; handles the drag math, min sizes,
  gutters and touch for us; nested splits support both the column and the
  row/height splits.
- **Cons:** one small dependency to vendor (we currently ship a single HTML file
  and CDN-load only RapiDoc); its model is nested flex panes, so we'd restructure
  the two grid regions into Split containers; lock = destroy/rebuild or a guard.
- **Fit:** the sweet spot if we want robustness without a layout framework.
  Recommended default (see below).

### C. Full dockable layout manager — Golden Layout / Dockview / Gridstack.js
These give draggable **and** rearrangeable/dockable panels, drag-to-reorder,
tab groups, and built-in serialize/restore; Gridstack adds a lockable grid with
`locked`/`noResize`/`noMove` per widget.

- **Pros:** the richest UX — users could rearrange, stack, pop out panels; lock
  and persistence are first-class; Gridstack's `float`/`locked` map directly onto
  the "lock" ask.
- **Cons:** heaviest option (tens of KB + a real layout model), usually
  React-oriented (Dockview) or opinionated DOM ownership (Golden Layout), which
  fights a hand-written page; we'd hand our panels' lifecycle to the library and
  rework `gatePanels` to add/remove library items rather than toggle `display`;
  theming to match the three CSS-variable themes is extra work.
- **Fit:** overkill for "resize + lock two splits", but the right call *if* the
  roadmap wants a fully user-arrangeable dashboard.

### D. `interact.js` — low-level drag/resize primitives
General-purpose draggable/resizable/gesture library; we'd use its `resizable`
with edge handles and write the layout application ourselves.

- **Pros:** flexible, well-maintained, handles pointer/touch edge cases.
- **Cons:** more plumbing than Split.js for this specific need; we still own the
  grid-template math. Little advantage over A or B here.

## Lock mechanism (applies to any option)

- A header toggle (next to the theme/user buttons) flips a `data-locked` attribute
  on `#app`.
- Locked: set gutters `pointer-events:none` + hide handles (CSS), or
  `split.destroy()` for option B / set `noResize,noMove` for Gridstack.
- Persist the boolean alongside the sizes. Consider a per-role default (viewers
  locked, operators unlocked) since viewers rarely need to re-tune.

## Persistence

- **Per-user, per-browser:** `localStorage` (e.g. `fj_layout`, `fj_layout_locked`)
  — matches how `fj_theme`/`fj_token` already persist. Simplest; no backend.
- **Per-user, cross-device:** would need a `GET/PUT /auth/preferences` endpoint
  storing a small JSON blob on the user row. More work; only worth it if users
  move between machines and expect their layout to follow. Out of scope unless
  asked.
- Always **clamp on load** (min panel widths/heights) so a saved layout can't
  render a panel unusably small after a CSS change.

## Recommendation

- If we want this **soon and light:** **Option A** (CSS-variable grid + a couple
  of pointer-driven gutters) — no dependency, persists via `localStorage`, locks
  by disabling the gutters, and drops straight onto the existing grid regions.
  Smallest change, no new supply-chain surface.
- If we want it **robust and expect more panels:** **Option B (Split.js)** —
  vendor the ~2 KB file, wrap the two grid regions as nested splits, persist
  `getSizes()`, lock by destroy/rebuild. Best effort-to-robustness ratio.
- **Defer Option C** unless product wants a fully rearrangeable/dockable
  dashboard; it's a different, larger project and changes how panels are owned.

Suggested next step if greenlit: prototype Option A behind a hidden toggle on one
split (the top Jobs|Detail column) to validate feel and the persistence/clamp
logic before generalising to every gutter.
