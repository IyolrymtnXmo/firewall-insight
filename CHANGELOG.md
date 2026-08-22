# Changelog

All notable changes to Firewall Insight.

---

## v4.16.1 — five defects the live lab showed

### Fixed — cluster cards rendered as empty rectangles

v4.16 split the `gateway` role into `gateway` / `cluster` / `cluster-member`.
Cards mode styles by role, so the two new roles had no rule at all and drew
unfilled, unstroked boxes — External-Cluster, External-GW01 and External-GW02
all appeared as black rectangles while Internal-GW01 stayed purple. Both roles
now have card fills in light and dark, and a test asserts every role the map
emits is styled **in both modes**, so the next role split cannot repeat this.

### Fixed — the map used half the panel

Component packing guessed one shelf width, and on a panel twice as wide as it
was tall that put the management pair *below* the firewall estate. The tall
result then had to be scaled down to fit: the lab rendered at **0.6×**. Instead
of tuning the constant, it now lays the shelves out at six widths and keeps
whichever renders largest — which is what "best" means here. Same lab, same
panel: **1.26×**, and the HA pair sits beside the estate.

Components are also padded by their own nodes' radii rather than a constant.
A radius already tracks label width, so a fixed pad let `192.168.20.0/24` in
one component print over `CP-MGMT-01`'s address in the next. Measured on the
lab at 1920px and at 1500px: **0 overlapping labels** in every state.

### Fixed — a merged subnet was a dead end

Auto Merge answers "how many subnets sit behind these devices". There was no
way to ask "which ones" — the node was not clickable. A merged node is now
expandable: clicking it opens that one group back into its members without
turning merging off everywhere else.

### Fixed — a node added later started in the middle of the map

Unmerging a group creates a node in an arrangement that already exists. It was
seeded on the golden-angle spiral, i.e. in the centre of everything, and
dragged its links across the picture. A node that is new to an existing layout
now starts at the centroid of the neighbours it connects to.

### Fixed — Save Map underlined every label, one interaction late

Save pins all nodes, and the "placed" marker was a dotted underline, so after
saving all eleven names looked like links. It is now a small dot in the node's
corner. Save also re-renders, so the markers appear when you press it rather
than on the next unrelated click.

---

## v4.16.0 — clusters are one firewall, and Management HA is on the map

Two questions from the lab: *should External-Cluster, External-GW01 and
External-GW02 be merged?* and *how are CP-MGMT-01 and CP-MGMT-02 linked?*
`tools/diag_topology.py` (new, read-only) answered both against the live R82.

### Added — cluster membership, from the cluster's own member list

```
External-Cluster  [CpmiGatewayCluster]
  cluster-member-names: ['External-GW01', 'External-GW02']
External-GW01  cluster-member  back-reference: NONE
```

`show-gateways-and-servers` returns the cluster **and** its members as
top-level objects, and the members carry no pointer back, which is why the map
drew three peers. It is now one cluster node with a second plate behind it, its
members attached by a dashed membership link, and Collapse folds the members
into it. Roles split: `cluster`, `cluster-member`, `gateway`, `management`.

**Membership is never inferred from addresses.** A /30 with .1 and .2 looks
like sync, and a third address on a member's subnet looks like a VIP — those
readings are right most of the time, and a map that is "usually right" about
which boxes are one firewall is worse than one that says it does not know.
Strip `cluster-member-names` from the payload and the app draws no membership
at all; if a named member is missing from the response, it says so in
`limitations` rather than quietly showing a smaller cluster.

What *is* read off the graph: a subnet no cluster interface touches, reached
only through members of one cluster, is internal to it. `10.99.99.0/30` is
marked accordingly, and the tooltip gives the evidence before the conclusion —
"No interface of External-Cluster is on this network, only its members are. On
a ClusterXL deployment that is the sync network."

### Added — Management HA

I was wrong when I said the API does not expose this. It does, in a field I had
not checked:

```
CP-MGMT-01  management-blades: [logging-and-status, network-policy-management]
CP-MGMT-02  management-blades: [logging-and-status, network-policy-management,
                                secondary]
```

`management-blades.secondary` marks the standby, and a domain has exactly one
primary — so primary + secondary *is* the pair, by definition rather than by
inference. Both are labelled with their role and joined by a green dashed HA
link. Two primaries, or a log-only server, draws nothing and says why.

The map says HA is **configured**. It never says it is healthy: whether the
peers are currently synchronised is not in the object model, and that caveat
is in `limitations` and in the node tooltip.

### Added — internet-facing subnets

Cluster interface 2 reports `topology.leads-to-internet: true`, so
`172.23.34.0/24` is marked as facing outside. Only that flag marks it; nothing
is guessed from address ranges.

### Changed — traffic.py split

`traffic.py` held four concerns and this work pushed it past the 700-line guard
that `test_v413_structure.py` enforces — the split flagged as deferred in
v4.13. The graph builder moved to `app/topology_map.py` (182 lines);
`traffic.py` re-exports `network_map` so existing imports keep working.

### Fixed — layout, for the shape this created

- The HA pair has no interface to the estate, so it is a second connected
  component. Fruchterman-Reingold assumes one graph: gravity pulled both to the
  middle while repulsion shoved them apart, compressing one and flinging the
  other. Components are now laid out together and then shelf-packed as rigid
  bodies — deterministic, and skipped entirely once the user has placed a node
  by hand.
- A member link is pulled to 0.78× a subnet link, so members sit with their
  cluster.
- Spacing now clears the widest label (`max(panel-derived k, widest × 1.35)`);
  a panel-derived k could come out smaller than the labels it had to separate.
- Collapsing a cluster used to strand `10.99.99.0/30` with no links at all.
- `topoDeclutter()`: geometry keeps an edge label clear of its own two
  endpoints, but nothing cheap predicts it landing on a *third* node's label.
  After the layout settles, measure what rendered and drop the few that
  collide — the interface label gives way, never the node name. Measured on
  the lab: **8 overlapping labels → 0**.

### Tests

`tests/test_v416_cluster_ha.py` (28). 340 total.

---

## v4.15.1 — graph view polish, after seeing it against the live lab

Rendering the real 7-firewall lab (22 objects → 11 nodes, 11 links) exposed
five things the synthetic fixture did not.

### Fixed — the map used a third of the panel

The SVG had a fixed `1600×1000` viewBox with `preserveAspectRatio`, so on a
1540×600 panel the whole graph was letterboxed into a centred 1.6:1 box with
empty panel either side. The viewBox is now the container's own pixel size —
one world unit is one CSS pixel — and it is re-set on resize (trailing edge
only; a resize fires continuously and the layout must not thrash).

### Fixed — a bigger screen bought you smaller labels

Edge length was a constant 150 units, which laid 11 nodes out over ~1300×850.
That had to be fitted into the panel at **67%**, so 12.5px labels rendered at
8.4px. Spacing now scales to the panel (`√(area/n) × 0.45`, clamped to 90–170)
and gravity is anisotropic — pulling harder on one axis compresses it, so a
`√aspect` split makes the settled cloud roughly the panel's shape rather than a
tall column. Same lab now fits at **~0.9–1.1×**. A dense estate still overflows
and is explored by zooming, which is correct.

### Fixed — labels printed on top of each other

`3 connections` and `if2` landed in the same place in the lab: an edge label
sat exactly on the midpoint, which is also where a short edge passes under a
node's sub-label. Labels now sit 9px off to the side of the line, are dropped
entirely on edges shorter than half the ideal length, and are painted with a
background-coloured outline (`paint-order: stroke`) so they stay readable
wherever they land. Node repulsion radius now follows the *label* width, not
the chip — two 14-character subnet names need more room than two 18px boxes.
Measured: **0 overlaps** between edge labels and node sub-labels.

### Fixed — a node could settle behind the pan/zoom pad

`CP-MGMT-01` did. The pad floats over the canvas, so fit now treats its
footprint as unusable space. Measured: **0 nodes intersecting the pad**.

### Fixed — clicking some devices did nothing

Every device was marked expandable, but a management server has no subnets
behind it and a gateway whose subnets are all shared has no leaves either — so
the click toggled an empty set. Only a device with something to hide is
expandable now; the rest isolate on a single click. **Double-click isolates
anything** (on an expandable device the two single clicks toggle it there and
back first, so the net effect is just the focus).

### Changed — no more emoji in the chrome

The Export buttons were 📷 and 📄, which render at the font's own colour and
weight and looked pasted on next to the app's SVG icon set. Export, the search
step arrows, and the pad's five controls are now inline SVG line art that
inherits the button colour. Only `−` and `+` remain as text, where a glyph is
the right answer.

### Tests

`tests/test_v415_graph_map.py` grows to 63. 312 total.

---

## v4.15.0 — Network Mapping gets a graph view

### Added — a physics layout, the way AlgoSec's Discover and Map reads

v4.14's two-column layout answers "which port on this gateway reaches which
subnet" well, and answers "what does this network actually look like" badly:
the shape of an estate is not visible in a bundle of parallel edges. Network
Mapping now has **two layouts**, switched in the toolbar:

| | Graph (default) | Cards |
|---|---|---|
| Shape | gateways as hubs, subnets orbiting | two columns |
| Best for | what sits between A and B | which interface reaches which subnet |
| Interfaces | edge labels (`if1`, `if2`) | rows inside the device card |

The graph runs a **Fruchterman-Reingold** simulation in plain JavaScript — no
library, no build step, works offline. It is seeded on a golden-angle spiral
rather than `Math.random()`, so the same topology lays out identically every
time; without that a saved arrangement would be meaningless. Repulsion is
`k²/d` plus a hard shove that only applies while two nodes actually overlap,
which is what keeps labels off each other. Unlinked nodes (a management server
with no modelled interfaces) get gravity 3.2 instead of 0.9, so they sit
beside the estate instead of defining its bounding box.

### Added — the controls that make a big map usable

- **Save Map / Reset Map** — drag any node to place it, then save. Positions
  are keyed to a hash of the node set, so one topology's coordinates are never
  reapplied to a different estate. Reset clears them and re-runs the physics.
- **Auto Merge** — subnets reached through exactly the same set of devices
  share one node. It is a presentation grouping: nothing is dropped, the count
  is shown, hovering lists the members, and clicking it again undoes it. On a
  40-gateway estate this took the map from 241 nodes to 81.
- **Collapse all** — hides the subnets that hang off exactly one device, which
  leaves the backbone. A subnet reached by two gateways is never hidden: it is
  part of the path between them, so hiding it would change what the map says.
  A collapsed device carries a `+N` badge for what is behind it.
- **Search IP / Subnet / Name** with ▲ ▼ to step through matches — each hit is
  centred and flashed; non-matches dim rather than disappear.
- **Show / Hide Legend**, and **Export** to PNG and CSV. The PNG re-attaches
  the topology CSS rules and resolves their custom properties into the
  serialised SVG, because a detached SVG leaves the page stylesheet behind and
  would otherwise export as black shapes on a transparent field.
- **Pan/zoom pad** bottom-right: D-pad, −/+, fit-to-screen and a slider, plus
  scroll-to-zoom and drag-to-pan on the canvas itself.

### Fixed

- `topoBindEvents()` runs on every render, and it registered a `window` mouseup
  listener each time without removing the old one — one leaked handler per
  render for the life of the session. Drag state moved onto a module-level
  object and the listener is now registered once.
- A re-render (filter, focus, collapse) re-ran the whole simulation and threw
  away the user's arrangement and zoom. Positions now persist across renders;
  only genuinely new nodes trigger physics.

### Verified in headless Chromium

Against a fixture reproducing the lab (20 objects) and a synthetic 40-gateway
estate (481 objects):

```
lab      : 11 nodes / 9 links, min node separation 180 units, 0 overlaps
           layout identical across two independent runs
collapse : 8 nodes, 3 hidden      merge: 10 nodes, 2 subnets merged
focus    : 6 dimmed               search "192.168": 2 hits, 9 dimmed
step     : hit centred to (0,0) offset, flash applied
drag     : node pinned, status reads "1 placed"
save     : 11 positions stored -> reload -> all nodes fixed -> reset clears
export   : 7.9 KB of style inlined, 7,366 non-background pixels rasterised
40 GW    : 481 objects -> 241 nodes / 240 links, 0 overlaps, 6.2 s to settle
           Auto Merge -> 81 nodes (200 merged); Collapse all -> 41 nodes
390 px   : no horizontal overflow, pad reachable
0 page errors in any state
```

### Tests

`tests/test_v415_graph_map.py` (46 tests). 295 total.

---

## v4.14.0 — Network Mapping redesign

### Changed — interfaces are no longer nodes

The old view drew every interface as its own node in a middle column. In the
lab that is 4 gateways + 2 management hosts + 5 subnets = 11 real things, but
the view rendered **22 nodes across 3 columns**, and every subnet edge had to
cross the interface column. The result was a hairball that told you less than
the raw JSON did.

An interface is not a peer of a gateway — it is a *part* of one. So it is now
a row inside the gateway card:

```
before                                  after
  [GW01] ── [interface 1] ── [10.99.99.0/30]     [GW01        2 ports ›] ── [10.99.99.0/30]
        └── [interface 2] ── [172.23.31.0/24]      interface 1  10.99.99.1/30
                                                   interface 2  172.23.31.177/24
  22 nodes, 3 columns                            11 nodes, 2 columns
```

- **Click a gateway** to open or close its interface rows. Collapsed, edges
  leave the card edge; expanded, each edge leaves the row it belongs to and is
  labelled with the interface, so you can see *which* port reaches a subnet.
- **Click a network** to isolate it — everything not connected to it dims,
  rather than disappearing, because the context is what makes the hit useful.
- **Filter box** dims non-matching nodes by name or address.
- **Expand all / Collapse all / zoom / Reset**, plus scroll-to-zoom and
  drag-to-pan. A drag of more than 4px is not treated as a click, so panning
  across a card no longer toggles it.
- Networks are ordered by the mean Y of what connects to them, which removes
  most edge crossings without a full layout solver.
- Cards are keyboard reachable (`Tab`, then `Enter`/`Space`) and report
  `aria-expanded`.

Honesty is unchanged: the banner still says the topology is logical only, and
an interface with no CIDR renders as `—` rather than a guess.

### Fixed

- The port-count pill clipped the trailing "s" of "ports" at some zoom levels;
  it is now sized for the widest label with the chevron parked clear.
- `topoExpandAll()` rebuilt the entire topology model once *per device*.
- `@app.on_event("shutdown")` is deprecated in FastAPI; the Management API
  logout now runs from a `lifespan` context manager.

### Tests

`tests/test_v414_topology.py` (26 tests) pins the contract of the redesign —
interfaces never emitted as nodes, expand/focus/search reachable, drag is not
a click, every emitted CSS class actually has a rule. Three test files pinned
the version as a literal string, so every release edited unrelated files; they
now assert what they meant (`version.py` defines it exactly once, the UI
reports the same version the app declares, the version never goes backwards).

Verified in headless Chromium against a fixture reproducing the lab exactly:
11 nodes / 9 links collapsed, 9 interface rows when fully expanded, 6 nodes
dimmed on network focus, 9 on a filter, no page errors.

---

## v4.13.0 — project structure, and UI fixes from the lab

### Changed — main.py was 2,473 lines, 83% of it an embedded frontend

`app/main.py` held the routes, the policy orchestration, the cache, the
progress registry **and** 100KB of HTML + CSS + JavaScript as a single Python
string. That meant no syntax highlighting or linting for the frontend, no
browser caching of assets, and one file that every change had to touch.

```
app/
  main.py            42 lines  — app factory and router include, nothing else
  version.py                   — single source of truth for APP_VERSION
  runtime.py                   — Management client, cache, HTTP error mapping
  progress.py                  — live phase registry for long requests
  policy.py                    — fetch -> hydrate -> analyse orchestration
  api/  meta access nat traffic topology export ui
  templates/index.html
  static/css/app.css
  static/js/app.js
  (analysis modules unchanged: checkpoint, resolver, analyzer,
   nat_analyzer, inline_layers, policy_browser, traffic)
```

**Deliberately not done:** the analysis modules were not moved into a
`services/` package. They are already single-responsibility and 90–650 lines
each; renaming them would have churned twelve test files for no structural
gain. `traffic.py` (651 lines) does deserve a split — matching, tracing, NAT
correlation and the topology graph are four concerns — but that is a behaviour
change worth landing separately and re-validating against the lab.

`tests/conftest.py` now exposes `app_source()`, which concatenates every file
the application is built from. Twenty test files asserted "this string exists
in app/main.py"; they now assert "this exists in the application", which is
what they always meant.

New `tests/test_v413_structure.py` keeps the structure from collapsing back:
main.py under 60 lines, no module over 700, no markup inside a `.py`, routers
that do not import each other, one home for the version — and, still
structural, **every route is a GET and no mutating Management command appears
anywhere in the source**.

### Fixed — five things the lab screenshots exposed

**Monospace applied to words.** `.metric` was styled with JetBrains Mono for
tabular figures, but metric *values* include `Access Control` and `Standard`,
which rendered as if broken. `metricCards()` and `setDashboardMetric()` now add
`.num` only for numeric values, and only `.metric.num` is monospaced.

**A bright bar under every wide table.** `::-webkit-scrollbar-thumb` was styled
but the *track* was not, so it fell back to light grey against a dark table.
Track and corner are now transparent and the thumb is inset.

**A bare strip below the sidebar.** The sidebar is `position:sticky` with
`height:100vh`, so on a page taller than the viewport its grid cell continued
below it and showed the page background. The column is now painted by a fixed
layer on `.app` that animates with the rail.

**A legacy media query fighting the new one.** The old `max-width:1100px` block
turned the sidebar into a horizontal strip, which collided with the collapsible
rail between 900px and 1100px. Reduced to the card reflow it was actually for.

**Four unlabelled inputs.** Traffic Path showed four bare boxes; you had to
click into each one to learn which was source, destination or service. They now
have visible labels, and the panel states up front that no packet is sent.

### Fixed — the collapsed rail, and two features that were built but unreachable

**The rail was still wrong after collapsing.** `.menu button` sets
`justify-content:flex-start` for the expanded layout and the rail rules never
overrode it, so every icon hugged the left edge of the 74px column. All six now
centre at offset 0.0px, verified in Chromium.

**Static assets had no cache-busting — a bug the refactor itself created.**
While the CSS and JS were inline in the HTML, every reload picked up the newest
version automatically. As separate files under `/static/` the browser caches
them, so upgrading left new markup running against stale styles: the theme
button rendered **both** the sun and the moon, and the collapse button still
said "Collapse". That looks like a broken UI, not a stale cache, which is the
worst kind of failure to hand a user. Asset URLs now carry
`?v={APP_VERSION}-{newest static mtime}` — the version makes an upgrade visible
to every existing user, the mtime makes an edit visible on the next reload
under `--reload`.

**The sidebar footer was louder than the navigation.** A full-width "Collapse"
pill and a "Light Mode" label with a toggle switch drew more attention than the
menu above them. Both are now quiet icon buttons: a sun/moon that shows the
theme you will switch *to*, and a collapse arrow that flips direction. `Ctrl+B`
collapses, `Ctrl+J` switches theme.

The icons are **inline SVG, not font glyphs**. `☀` and `☾` render differently in
every font stack and looked wrong in the fallback face; SVG is crisp at any size
and inherits `currentColor` like text does.

Two defects in that footer were caught by measuring it in Chromium rather than
looking at it:

- `.icon-btn .ico` is specificity (0,2,0) and silently beat a bare
  `.ico-moon{display:none}` at (0,1,0), so **both** icons rendered in dark mode.
  The show/hide pair now matches that weight.
- `flex:1 1 0` sizes the *main* axis, so stacking the row into a column in the
  rail made flex-basis apply to height and the buttons collapsed from 36px to
  19px. The rail gives them an explicit 44×38.

The rail also drops the 3px inset active bar: it is an edge marker for a
full-width row, and on a centred 44px square it read as a stray line. The brand
becomes a gradient badge rather than two letters floating in a gap.

**"Export Raw CSV" exported nothing.** It printed *"Package-level CSV export
will be added after package/inline validation"* — a stub left behind when the
UI became package-first in v4.2 while the CSV endpoint stayed layer-first. New
`GET /api/package-policy-browser.csv?package=` exports the whole package with
`Display Rule` and `Layer Path`, so an inline row reads `7.1` under
`Network → InternetLayer` rather than an ambiguous `1`. The package name is
sanitised before it reaches `Content-Disposition`.

**Zero-hit and disabled rules were computed and never shown.** `analyzer.py`
has produced `zero_hit_rules` and `disabled_rules` since v4.0 — with layer,
display rule and hit counts — and no view rendered them. The lab had **9 of
them invisible**. Analyze now has an **Unused Rules** tab merging both
(disabled wins the label, so a rule is never listed twice), with the Dashboard
linking to it.

It carries an explicit caveat rather than a recommendation: hit counters reset
on policy install and on gateway restart, and a rule can protect a path that is
simply idle. "Unused" is a review candidate, never a delete instruction — the
same reason Traffic Path says `UNVERIFIED` instead of guessing.

### Tests

191 → 223. New: `tests/test_v413_structure.py`, `tests/test_v413_ui_polish.py`.
Two assertions were rewritten
to test intent rather than an exact string, for the same reason as in v4.12:
`test_v44_source` pinned four placeholder strings that moved into labels.

Verified after the move: all 17 routes answer 200 against a fake Management
client, the page loads from a real uvicorn with both assets served, no console
errors, and the font stack still renders correctly **with fonts.googleapis.com
blocked** — the air-gapped case.

---

## v4.12.0 — real progress, collapsible rail, typography

### Fixed — the step indicator was decoration that lied

v4.11 showed Traffic Path a four-step list, but the browser makes **one**
request and cannot see server-side phases, so the list advanced on a
client-side guess. Observed behaviour: it sat on step 1 for 27 s and then
jumped straight to done.

The steps were not merely mistimed — they were the same class of dishonesty
this project keeps fixing elsewhere: a display that asserts more than the code
actually knows.

Now the backend records its phase against a client-supplied request id
(`?rid=`), and the UI polls `GET /api/progress?rid=`:

```
phase 0  Loading package / inline layer tree
phase 1  Resolving objects and service
phase 2  Walking the ordered rulebase
phase 3  Correlating NAT
```

Measuring it exposed the real cause of the "stuck" feeling: **phase 0 takes
tens of seconds while phases 1–3 finish in microseconds.** Since v4.9, first
load issues one `show-object` per thin object at 0.55 s pacing, and that is
virtually the whole runtime. Balanced-looking steps would have been a second
lie, so `hydrate_objects()` now takes an `on_progress` callback and the overlay
shows a moving counter:

```
Network: resolving object 34/49
```

A cached result reports `done` with label `Served from cache` immediately, so
the overlay can never hang on step 1 for a request that already finished.
Progress is best-effort throughout: a failure in the progress channel never
fails the real request, and a request without `rid` is unaffected.

### Changed — toasts moved to the top right

### Added — collapsible sidebar

`Ctrl/Cmd+B` or the Collapse button shrinks the sidebar to a 74px icon rail
with hover tooltips; the state persists in `localStorage`. The active marker
moved from `::before` to an inset shadow because a button has only two
pseudo-elements and the rail needs `::before` for the icon and `::after` for
the tooltip. Icons come from an explicit `data-icon` attribute — `::first-letter`
does not apply to buttons, so the first attempt rendered a blank rail. The
sidebar also gets `z-index` in rail mode, or the tooltip draws behind the
panels.

### Added — typography

`Nunito` for Latin (rounded, blunt terminals), `Anuphan` for Thai
(loopless — ไม่มีหัว — geometric, pairs with Nunito), `JetBrains Mono` with
tabular figures for rule numbers, IPs, ports, scores and elapsed time, so
columns of data line up. The stack falls back to `system-ui` and
`Noto Sans Thai`; **air-gapped installs should self-host the three families and
replace the `<link>` with local `@font-face`**, since a Management network
usually cannot reach fonts.googleapis.com. Noted inline in the CSS.

### Added — motion polish

Metric scale on card hover, alert badges pulse on drill hover, pill lift on row
hover, input focus rings, animated sidebar width. All still disabled under
`prefers-reduced-motion`.

### Changed — one test now asserts intent instead of a literal

`test_phase310` pinned the exact string
`data-page="browser" onclick="…">▤ Access Policy</button>`. Adding `data-label`
for the rail tooltip broke it, while the property it exists to protect —
Access Policy ordered before Analyze — still held. It now compares attribute
positions and checks the labels separately.

### Tests

165 → 190. New: `tests/test_v412_progress.py`, including a spy that asserts the
per-object counter strictly increases and that traffic phases are emitted in
order.

---

## v4.11.0 — feedback, status and responsive shell

Reported symptom: after clicking an action the app looked frozen, and telling
"working" from "finished" from "crashed" meant opening DevTools → Network.

That was accurate. The only feedback channel was one line of text
(`S.textContent = …`), and eight code paths ended in
`catch(e){S.textContent=e.message}` — a raw string with no cause, no remedy and
no way to report it. Since v4.9 a first package load also issues one
`show-object` per thin object at 0.55 s pacing, so 10–20 s of apparent silence
became normal.

### Added — activity is always visible

- **Top progress bar** driven by a global in-flight request counter, so *any*
  request shows activity without each call site opting in. `aria-busy` is set
  on `<body>` for assistive tech.
- **Blur overlay** for blocking work: translucent glass
  (`backdrop-filter: blur(9px)`, `rgba(…,.62)`, with a light-theme variant),
  a spinner, an **elapsed-time counter**, and named **step progress** so a long
  run shows which phase it is in rather than one opaque spinner.
- After 6 s the overlay explains *why* it is slow — per-object hydration paced
  under the API rate limit, cached for 5 minutes afterwards — so expected
  slowness stops reading as a hang.
- **Per-button busy state**: the clicked button shows its own spinner and is
  disabled, and `task()` refuses to start a job whose key is already running,
  so double-clicking can no longer fire two analyses.
- Requests now have an `AbortController` timeout instead of hanging forever.

### Added — failures reach the user, not the console

`describeError()` maps a failure to a cause and a remedy:

| Symptom | Reported as |
|---|---|
| `Failed to fetch` | Cannot reach Firewall Insight — uvicorn looks stopped |
| `HTTP 429` | Management API rate limit — raise `CHECKPOINT_MIN_REQUEST_INTERVAL` |
| `HTTP 502` | Management Server unreachable — check `CHECKPOINT_MGMT` |
| `AbortError` | Request timed out — raise `CHECKPOINT_TIMEOUT` |
| login/credential | Authentication failed — check `.env` |

Each failure now produces a colour-coded status bar, a toast with a **Copy
details** action, *and* an inline error panel with a **Retry** button in the
affected view. `window.onerror` and `unhandledrejection` handlers mean a script
bug surfaces instead of silently doing nothing — the exact class of problem that
sent the user to DevTools. Offline/online transitions are detected too.

### Added — toasts, skeletons, empty states

Four toast kinds (success / info / warn / error) with a life-bar countdown;
**error toasts are sticky** and announce as `role="alert"`. Tables render a
shimmer skeleton while loading instead of collapsing to blank space. Each page
opens with an empty state saying what to do next; the Traffic Path one notes
that the simulation never sends a packet, so the hosts need not exist.

### Added — incomplete results are labelled incomplete

New backend `data_quality()` reports `failed_inline_layers`,
`object_hydration_truncated` and human-readable warnings on
`/api/package-analyze`, `/api/package-policy-browser` and `/api/traffic-path`.
The UI renders a banner plus a toast. Previously a partially-loaded policy was
presented identically to a complete one — the same failure mode as the v4.9
bug, one layer up.

Traffic Path feedback now follows confidence rather than flattening it:
`exact` → success, `inferred` → warning that the gateway log is authoritative,
`UNVERIFIED` → a sticky warning explaining that guessing here risks being
confidently wrong. NAT reports whether the build supports hit counts.

### Fixed — horizontal overflow on mobile

`1fr` is shorthand for `minmax(auto,1fr)`, and `auto` will not shrink below its
content's min-width. One table with `min-width:650px` stretched its grid column
to 688px and forced the whole document to scroll sideways at 390px.
`minmax(0,1fr)` plus `min-width:0` down the chain lets `.table-wrap` scroll
instead of the page, so wide tables stay readable and the layout fits.

### Fixed — status bar nested inside itself

`#status` keeps its legacy `.status` class so every existing `S.textContent`
assignment still works, but that class carried its own background and border,
which rendered as a box inside the new status bar. Neutralised in context.

### Added — responsive and motion

Sidebar becomes an off-canvas drawer under 900px with a scrim and a Menu
button; controls, cards and grids reflow; sticky table headers; touch
scrolling. Page changes, hovers and cards animate on a shared easing scale,
all of it disabled under `prefers-reduced-motion`. `:focus-visible` rings for
keyboard users, `Escape` dismisses toasts and closes the drawer.

### Tests

119 → 165. New: `tests/test_v411_ux.py`. Behaviour was additionally verified in
headless Chromium: blur applied, overlay reference-counted and dismissed,
failure reaching the UI, `scrollWidth == 390` at 390px, double-submit blocked,
no page errors, dark and light themes.

---

## v4.10.0

Follow-up to v4.9. With hydration fixed, `tools/diag_resolver.py` narrowed the
live lab's remaining unresolvable objects from 10 to 2 — and both turned out to
be wrong for reasons that had nothing to do with missing data.

```
AD-Services [service-group]    member count: 10
    ldap [service-tcp]  ldap-ssl [service-tcp]  microsoft-ds [service-tcp]
    Kerberos_v5_UDP [service-udp]  ...  ALL_DCE_RPC [service-dce-rpc]

icmp-requests [service-group]  member count: 4
    echo-request / info-req / timestamp / mask-request  [service-icmp]
```

### Fixed — one unmodellable member discarded the whole group

`service_atoms()` and `address_atoms()` bailed out on the first member they
could not model:

```python
part = self.service_atoms(cu, seen.copy())
if part is None: return None
```

`ALL_DCE_RPC` has no fixed port, so `AD-Services` answered `unknown` even to a
TCP/389 query that plainly matches its `ldap` member.

The two callers were asking different questions with the same strictness:

| Question | Caller | Needs |
|---|---|---|
| "is this port in the set?" | traffic matching | **one** hit — positive evidence |
| "does set A cover set B?" | shadow analysis | **every** atom |

Added `address_atoms_partial()` / `service_atoms_partial()`, returning
`(atoms, complete)`. The matchers use them: a hit on a modelled member is a
definite `match`; failing to hit while something is unmodelled stays `unknown`.
`address_atoms()` / `service_atoms()` remain strict wrappers returning `None`
unless complete, so containment analysis is unchanged and still conservative.

### Fixed — ICMP-only services answered `unknown` to TCP queries

`service_atoms()` understood only TCP and UDP, so an ICMP service was
unmodellable rather than simply non-matching. This was a live hazard, not a
cosmetic one: an `unknown` earlier rule blocks every later definitive verdict,
so rule 6 (`Lab-Troubleshoot-ICMP`, service `icmp-requests`) would have turned
otherwise-exact traces into `UNVERIFIED` for any query whose source and
destination matched it. The lab avoided this only because the tested
destination fell outside rule 6.

`_leaf_service_atoms()` now models:

- `service-icmp` / `service-icmp6` → atom on `icmp-type` (0–255 if absent)
- `service-sctp` → port range, proto `sctp`
- `service-other` → proto `ip-<ip-protocol>`

so a TCP/443 query against an ICMP or GRE service is now a confident
`no-match`. `service-dce-rpc` and `service-rpc` stay unmodelled deliberately —
they negotiate ports at runtime, so `no-match` would be a lie.

### Changed — unknown reasons name the blocking leaf

"Static match unavailable for AD-Services [service-group]" did not say what to
look at. `resolver.unmodelled_names()` walks to the leaves, so the message is
now:

```
Static service match unavailable for AD-Services → ALL_DCE_RPC [service-dce-rpc]
Static match unavailable for Mixed-Nets → DynamicObj [dynamic-object]
```

`tools/diag_resolver.py` reports partially-modelled objects separately from
unusable ones, and no longer claims a service group failed because of
`address_atoms()`.

### Tests

100 → 119. New: `tests/test_v410_partial_resolution.py`.

---

## v4.9.0

### Fixed — objects-dictionary presence mistaken for completeness

`tools/diag_resolver.py` (added this release) reported **10 objects** in a live
lab's root Access layer that the resolver could not turn into comparable
ranges, every one of them marked `in dictionary: True` with `member count: 0`:

```
LAB-Internal-Nets [group]        Admin-Networks [group]
AD-Services [service-group]      dns / ntp / icmp-requests [service-group]
External-Cluster [simple-cluster]
External-GW01 / External-GW02 [cluster-member]
Internal-GW01 [simple-gateway]
```

`show-access-rulebase` is called with `details-level: standard`, so its
`objects-dictionary` entries carry only `uid`, `name` and `type` — no group
members, no gateway or cluster address. `hydrate_objects()` decided whether to
fetch full detail with a single test:

```python
for uid in [x for x in uids if x and x not in existing]:
```

Present was treated as complete, so all ten were skipped and stayed as stubs.

Consequences, both observed:

- **Traffic Path** returned `UNVERIFIED` for a flow whose real configured path
  is `Rule 7 → InternetLayer → Rule 7.1 → Accept`, because
  `address_atoms()` returned `None` for `LAB-Internal-Nets` and the tri-state
  matcher — correctly — refused to guess.
- **Shadow analysis** silently under-reported: `_dimension_cover()` answers
  `"Unsupported object type"` for an unresolvable object, so any rule using a
  group was skipped instead of compared.

`resolver.needs_detail()` now decides completeness from the fields the resolver
actually consumes — an address, a port, or members — rather than from presence.
`hydrate_objects()` re-fetches thin entries, and the hydration loop in
`hydrate_rulebase()` re-checks nested members for completeness too (a group
member can itself be a stub), over at most `MAX_HYDRATION_ROUNDS = 6` passes.

Action and track objects (`Accept`, `Drop`, `Log`) reach hydration because
`action` is in `RULE_FIELDS`; `needs_detail()` excludes them so they do not
each cost a paced, rate-limited round trip.

**Cost:** first load of a package now issues one `show-object` per thin object.
At the default 0.55 s pacing that is roughly 10–20 s extra on a small policy,
then served from the 300 s cache. Requesting `details-level: full` on
`show-access-rulebase` would trade those N calls for one larger response and is
worth measuring, but was not changed here.

### Fixed — rate-limited hydration failed silently

`hydrate_objects()` caught `CheckPointRateLimitError` and `break`, leaving a
partly-resolved dictionary indistinguishable from a complete one. It now sets
`CheckPointClient.hydration_truncated` so reduced confidence can be reported.

### Changed

- `disabled_rules` and `zero_hit_rules` findings now carry `display_rule`, so
  an inline finding reads `7.1` instead of the ambiguous `1`.
- Added `tools/diag_resolver.py`: read-only, prints every referenced object the
  resolver cannot evaluate and distinguishes "no members returned" from
  "members not hydrated".

### Tests

78 → 100. New: `tests/test_v49_hydration.py`.

---

## v4.8.0

Two fixes driven by validation against a live lab Management Server running
Management API **2.0.1** (the earlier baseline was validated against 1.9).

### Fixed — cleanup rule reported as an Any/Any/Any finding

Every Check Point policy ends with an implicit-deny cleanup rule, which is
Any/Any/Any/Drop by design. The analyzer counted it as an optimization finding,
so a healthy policy scored 92 instead of 100 and the dashboard showed a yellow
alert badge for a rule that was correct.

`analyzer.is_cleanup_rule()` now identifies the layer's cleanup rule
**positionally** — the last ordered rule in the layer with a `Drop` or `Reject`
action — and reports it under `cleanup_rules` instead of `any_any_any_rules`.
Detection deliberately ignores the rule name, because names vary by
administrator and language.

Still reported as genuine findings:

- a trailing Any/Any/Any **Accept** rule
- an Any/Any/Any Drop rule that is **not** last in its layer

The Analyze → Any Rules view now states which cleanup rules were excluded and
why, so the exclusion is visible rather than silent.

### Fixed — NAT hit counts permanently disabled

v4.0 hardcoded "no NAT hits" after one lab on Management API 1.9 answered
`HTTP 400: Unrecognized parameter [show-hits]` to `show-nat-rulebase`. Newer
Management builds accept the parameter, so the workaround was suppressing real
data everywhere.

`CheckPointClient` now **probes** the capability once per session:
`show-nat-rulebase` is called with `show-hits`, and only if the server rejects
it with an unrecognised-parameter error does the client fall back and remember
not to ask again. Rate-limit errors and unrelated API errors propagate normally
instead of being mistaken for an unsupported parameter.

`analyze_nat_rulebase()` reads the returned hit values instead of returning
`None`, and reports `summary.nat_hits_available`.

### Changed

- Version is now a single `APP_VERSION` constant, surfaced in `GET /health`.
- Application title is `Firewall Insight - Check Point Firewall Analysis Platform`.
- Added `pytest.ini` (`pythonpath = .`) so a bare `pytest` works. Previously only
  `python -m pytest` collected, because the plain `pytest` entry point does not
  put the working directory on `sys.path`.
- README rewritten as project documentation; release history moved here.

### Tests

63 → 78. New: `tests/test_v48_cleanup_rule.py`, `tests/test_v48_nat_hits.py`.

---

## v4.7 — Tri-state traffic matching

- Access matching distinguishes Match / No Match / Unknown.
- Security Zone, dynamic-style, negated and otherwise unsupported static
  conditions are no longer incorrectly treated as No Match.
- An uncertain parent rule can still be followed into its Inline Layer; when the
  child rule matches exactly the result is returned with `confidence = inferred`.
- A later cleanup rule is no longer reported as definitive when an earlier rule
  cannot be statically evaluated; the result becomes `UNVERIFIED`.
- Parent rows are neutral/green-accented, Inline rows blue-accented.

Driven by a real mismatch: expected `Rule 60 → InternetLayer → Rule 60.35 →
Accept`, incorrectly reported as `Cleanup Rule 132`.

## v4.6 — Tri-state groundwork

- `MATCH` / `NO MATCH` / `UNKNOWN` states introduced in the traffic matcher.
- Protection against returning Cleanup when an earlier rule is unevaluable.

## v4.5 — Inline-aware Traffic Path

- Traffic Path reads rules inside Access Sections recursively.
- When a matching parent rule references an Inline Layer, the trace follows the
  child layer until a terminal Accept/Drop/Reject rule is found.
- Result includes the complete matched path, e.g.
  `Rule 60 → InternetLayer → Rule 60.35 → Accept`.
- Inline rows use a neutral dark background with blue accents.

## v4.4 — Hierarchical rule numbering + flexible traffic inputs

- Inline rule numbers follow the parent path: `30 → 30.1, 30.2, 30.3`, nested `30.2.1`.
- Traffic Path accepts source and destination as IP address or domain/FQDN.
- Domain input is matched against Check Point domain objects and locally resolved
  DNS A/AAAA addresses.
- Service input accepts a numeric port, a standard service name, or an exact
  Check Point service object name including custom TCP/UDP services.

## v4.3.1 — Drill-down fixes

- Dashboard alert counts became clickable and route to the related analysis view.

## v4.3 — Inline hierarchy and dashboard findings

- Inline Layer rules render immediately below their parent rule.
- Parent rows show how many inline rules are attached.
- Dedicated Inline Layer Analysis panel on the dashboard.
- Shadow, duplicate and Any findings broken down into top-level vs inline counts.

## v4.2 — Package-first / SmartConsole count compatibility

- Policy Package became the primary selector; the ordered Access Control layer is
  resolved from the package.
- **Pagination fixed** for Access and NAT rulebases using the API collection `to`
  boundary instead of the number of returned top-level section wrappers.
- Section wrappers repeated across pages are de-duplicated.
- `Access Rules` is the SmartConsole-style top-level count; inline rules are
  loaded and analysed but displayed separately.
- Added `Total Rules Inspected`.

This is where inflated counts (1440 Access / 440 NAT against a real 132 / 116)
were traced to pagination plus section handling and corrected.

## v4.1 — Inline Layer compatibility

- Recursive discovery and loading of Inline Layers referenced by Access rules.
- Layer column, layer path and parent-rule context in the raw Access Policy.
- Analyzer runs independently inside each Access Layer to avoid false cross-layer
  shadow and duplicate findings.
- Access tree responses cached to reduce repeated Management API calls.
- Inline-layer fetch failures are tracked rather than silently treated as complete.

## v4.0 Final.1

- Dashboard `Analyze Selected Policies` also loads the raw Access Policy rulebase,
  so Access Policy, Analyze and NAT Policy are all populated after one action.

## v4.0 Final

- NAT `show-hits` disabled for Management API v1.9 compatibility
  (`HTTP 400: Unrecognized parameter [show-hits]`). *Revisited in v4.8.*
- Dashboard became a useful overview with Access/NAT metrics, finding summary,
  quick actions and selected context; cards support drill-down.
- Access workflow split into **Access Policy** (raw configured rulebase) and
  **Analyze** (optimizer findings and score).
- NAT parser supports scalar UID/string/object fields as well as lists, fixing
  blank Original/Translated NAT columns.
- NAT drill-down tabs for Disabled NAT and Possible No-Translation.
- Firewall and Management Server topology icons.
- Settings menu removed; Network Mapping no longer shows policy selectors.
- Non-zero finding counts highlighted with a yellow circular badge.
- API request pacing, cache, retry/backoff and persistent read-only session.
- CSV export for both raw policy and analysis.
